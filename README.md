# redact-gateway

> A single-binary reverse proxy that masks sensitive regions in **image uploads in-flight** — so raw sensitive pixels never reach your storage, with zero app code changes.

![status](https://img.shields.io/badge/status-early%20development-orange) ![language](https://img.shields.io/badge/language-Go-blue) ![license](https://img.shields.io/badge/license-MIT-green)

`redact-gateway` sits in front of your upload endpoint (or acts as an S3 presigned-PUT/POST sidecar). It intercepts inbound `multipart/form-data` and raw single-object bodies, classifies each item by its **magic bytes**, masks the detected sensitive regions in the image, strips privacy metadata, and forwards the **sanitized** payload to the origin. The object that lands in your storage is already redacted, and an audit entry records *what* was masked (bounding boxes + categories) **without ever storing the original pixels**.

The default build is **dependency-free (Go standard library only)**. It ships a genuinely useful pipeline today; heavyweight ML detectors are optional and clearly scoped (see [Scope](#scope-honest-by-design)).

## Why

Most redaction happens inside your application code, or at retrieval time, after the raw file has already been written to disk or object storage. `redact-gateway` moves redaction to the network edge on the **inbound** path, so the unredacted bytes never touch your storage in the first place — and you don't have to change the uploading app.

## The cardinal safety property: fail-closed

The whole point of a redaction proxy is that **it must never forward bytes it could not sanitize when policy required sanitization.** `redact-gateway` is **fail-closed by default**: on a `redact`/`blur` route the upload is **blocked** (the origin receives *nothing*) on any of:

- a detector error,
- an undecodable image,
- an image in an **unsupported format** (e.g. GIF/WebP, which v1 can't mask) — classified by magic bytes, not by a (spoofable) `Content-Type` header,
- a **re-encode failure**,
- a mask failure,
- an oversize part,
- a **decompression bomb** (declared dimensions over the pixel cap, caught *before* full decode),
- a truncated/partial image,
- on a `pass` route, a metadata-strip error.

`fail_open` is a per-route, **off-by-default**, explicitly-documented-as-unsafe opt-in. The gateway's own error responses (413/502/503/4xx) contain **only a short status string** — never request bytes, image data, or upstream content.

## What it does (default stdlib build)

- **Inbound-upload reverse proxy / S3 sidecar.** Handles `multipart/form-data` (each file part sanitized independently) and raw `PUT`/non-multipart `POST` bodies that sniff as a supported image.
- **Classification by magic bytes**, never by headers — a JPEG mislabeled `application/octet-stream` is still caught; a GIF that lies about being a PNG is still blocked on a redact route.
- **Image rewrite** (JPEG/PNG): decode → run detectors → apply the route action to the **union** of all detected regions → re-encode. Re-encoding inherently drops EXIF, IPTC, COM, and any embedded thumbnail, so a masked image can't leak originals via metadata.
- **Real metadata stripping on raw bytes** for the forward-original (`pass`) path: removes APP1 (EXIF/GPS), APP13 (IPTC), and COM segments — including the embedded thumbnail — without decoding.
- **Per-route policy:** `redact` (solid box), `blur` (bounded box blur), `drop` (reject the upload), `pass` (no mask, but still strip metadata + audit). Longest-prefix route match.
- **Detectors (pluggable `Detector` interface):**
  - `region-marker` — finds rectangular zones painted in a configured marker color (deterministic; great for explicit "redact this area" workflows and tests),
  - `regex-pii` — runs email/card/SSN-style regexes over a pluggable `OCR` interface (the default OCR is a no-op, so it finds nothing until a real OCR adapter is supplied — see Scope),
  - plus deterministic fakes for testing.
- **Order-stable multipart re-serialization:** images are sanitized concurrently but re-emitted **by original part index**; original part headers are preserved; per-part and outer `Content-Length` are recomputed; the forwarded `Content-Type` **reuses the original `boundary=` verbatim**; text/non-image parts are copied byte-for-byte.
- **Audit log (JSON lines)** `{ts_label, route, action, categories, bboxes, sanitized_sha256}`. The hash is of the **sanitized** output only. `ts_label` is **gateway-generated** (a monotonic counter + an injected clock), never request-derived, and every string is JSON-escaped — so a hostile filename can't inject or split a log line. **No original pixels are ever written.**
- **Bounded worker pool with backpressure:** the bound is **per-image-redaction job** (a global semaphore of size `N`), so total in-flight jobs ≤ `N` and peak image-buffer memory ≤ `N × max_bytes`. Saturation returns `503`; a client disconnect cancels that request's in-flight jobs. On shutdown the pool is **drained before** `http.Server.Shutdown`, and a job that has begun forwarding sends the **complete sanitized body or nothing**.
- **Config validation** bounds the `N × max_bytes` memory product against a ceiling, and rejects a missing origin, an invalid action, or an unknown detector.

## How it works

```
client ──upload──▶  redact-gateway  ──sanitized──▶  origin / object storage
                         │
                         ├─ classify each item by magic bytes
                         ├─ decode (pixel-cap guard) → detect → mask → re-encode
                         │   (or, on a pass route, strip EXIF/IPTC/COM from raw bytes)
                         ├─ fail-closed on any sanitize failure (origin gets nothing)
                         └─ append a no-pixel audit entry
```

## Quick start

```bash
go build ./cmd/redact-gateway
REDACT_ORIGIN="http://localhost:9000" ./redact-gateway -config config.example.json
```

A minimal config (`config.example.json`):

```json
{
  "listen": ":8080",
  "origin": "http://localhost:9000",
  "audit_path": "",
  "worker_pool_size": 8,
  "max_bytes": 10485760,
  "max_pixels": 40000000,
  "strip_metadata": true,
  "routes": [
    { "path_prefix": "/upload/avatars", "action": "redact", "detectors": ["region-marker"] },
    { "path_prefix": "/upload",         "action": "blur",   "detectors": ["region-marker", "regex-pii"] },
    { "path_prefix": "/",               "action": "pass" }
  ]
}
```

Config may be supplied by file and/or these environment overrides: `REDACT_LISTEN`, `REDACT_ORIGIN`, `REDACT_AUDIT_PATH`, `REDACT_WORKER_POOL_SIZE`, `REDACT_MAX_BYTES`, `REDACT_MAX_PIXELS`. An empty `audit_path` logs audit lines to stdout.

## Scope (honest by design)

- **Default build is standard-library only.** `go.mod` has no `require` block; the binary needs no network and pulls no dependencies. It ships the proxy + metadata stripping + the region/regex detectors — all fully tested.
- **ML detectors are optional adapters behind Go build tags**, under `internal/detect/ml/` (face via OpenCV/gocv, QR/barcode, OCR via tesseract, and a cloud VLM). They implement the same `Detector`/`OCR` interfaces and are **never compiled into the default build or CI**, so the default binary stays dependency-free. The VLM adapter — the only path that could send pixels off the box — is gated behind **both** a build tag **and** an explicit runtime kill switch, and is documented as breaking the local-by-default guarantee. See `internal/detect/ml/doc.go`.
- **Documented futures (not in v1):** PDF page redaction, video frame redaction, and an nginx `auth_request` integration.

## Testing

The entire default pipeline is **offline and deterministic** — fakes/region-marker detectors, generated test images, and an injected clock; no network, no ML, no wall-clock in pure logic. The suite runs under the race detector and includes an adversarial proxy set asserting the fail-closed/no-leak guarantees (origin receives nothing, and no original bytes appear in the audit log, error responses, or anywhere — checked in raw, hex, and base64 form).

```bash
go build ./...
gofmt -l .                       # must print nothing
go vet ./...
go test -race -count=1 ./...
go test -cover ./...
```

CI (`.github/workflows/ci.yml`) runs `gofmt -l`, `go vet`, `go test -race`, and golangci-lint across Go 1.23 and 1.24, building **only** the default stdlib build.

## License

[MIT](LICENSE) © 2026 Mykola Podpriatov
