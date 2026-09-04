# Security policy

`redact-gateway` is a security control. Its whole reason to exist is the fail-closed contract in the README: an upload that could not be sanitized when policy required sanitization must never reach the origin. A way around that contract is a vulnerability, not a bug report.

## Reporting

Use GitHub's private vulnerability reporting on this repository: **Security → Report a vulnerability**. That opens a private advisory only the maintainer can see.

Do not open a public issue for a bypass. A public issue is a working exploit against every deployment running that version, published before anyone can upgrade.

Useful reports include the route configuration, the input that got through (a description or a synthetic reproduction, never real personal data), and what the origin received. A failing test against `internal/proxy` is the fastest possible report.

## What counts

The fail-closed and no-leak guarantees are the security surface:

- Any input that gets unsanitized bytes past a `redact` or `blur` route, including a format confusion that makes the magic-byte classifier disagree with the decoder.
- Any path that leaks original bytes into the audit log, an error response, or `/metrics`. The audit log records only a hash of the sanitized output; error responses carry only a short status string.
- A decompression bomb, an oversize part, or a truncated image that gets past the guards instead of being blocked.
- A crash or a hang reachable from an upload, since a proxy that is down is a proxy someone will route around.
- Anything that lets one request's data appear in another request's response.

## What does not

- `fail_open`. It is off by default, per-route, and documented as unsafe. A route that opts into forwarding unsanitized bytes is doing exactly what it asked for.
- The ML adapters under `internal/detect/ml/`. They live behind build tags, are excluded from the default build and from CI, and the cloud VLM adapter additionally requires a runtime kill switch to be flipped. A finding there is a normal issue.
- Missing detection. The default build ships the region-marker, full-image and regex-PII detectors, and the default OCR is a no-op, so `regex-pii` finds nothing until a real OCR adapter is supplied. Content the configured detectors were never able to find is a feature request, not a bypass. Content they did find and the gateway then failed to mask is a vulnerability.
- Anything requiring control of the config file or the process environment. Whoever can rewrite the route table has already won.

## Supported versions

The default branch is the only supported version. Fixes land there; there are no backports.

## Response

Expect an acknowledgement within a few days and an assessment within two weeks. A confirmed bypass of the fail-closed contract is treated as the highest priority. Credit in the advisory unless you would rather not be named.
