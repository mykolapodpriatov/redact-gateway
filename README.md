# redact-gateway

> A single-binary reverse proxy that redacts faces, PII text, barcodes and signatures from images in-flight — uploads hit your storage already sanitized, with zero app code changes.

![status](https://img.shields.io/badge/status-early%20development-orange) ![language](https://img.shields.io/badge/language-Go-blue) ![license](https://img.shields.io/badge/license-MIT-green)

A drop-in HTTP reverse proxy / S3-upload sidecar that intercepts inbound image and PDF-page payloads (multipart and presigned POST/PUT) and rewrites the bytes with sensitive regions masked before they reach the origin.

## Why

Most redaction tools run per-file in your app code or at retrieval time. This sanitizes uploads transparently at the network edge, so raw sensitive pixels never reach your storage.

## Features

- Transparent inbound-upload proxy / S3 sidecar rewriting image & PDF bytes in transit
- Pluggable detectors: OCR+regex PII, face/QR/barcode, optional VLM for free-form content
- Concurrent worker pool with backpressure; per-route redact/blur/drop/pass YAML policy
- bbox+category audit log that never persists original sensitive pixels
- Local-default (no data leaves the box); optional cloud VLM behind a hard kill-switch

## How it works

Put redact-gateway in front of your upload endpoint or S3. It detects sensitive regions with local models, masks them per your YAML policy, forwards the sanitized bytes, and records a bbox/category audit entry — without storing the originals.

## Tech stack

- Go
- net/http reverse proxy
- Tesseract / PaddleOCR
- ONNX face/QR detectors
- optional Claude / Gemini VLM
- YAML policy

## Status & roadmap

🚧 **Early development.** This repository is being built in the open; the scaffold and design are in place and the implementation is landing incrementally.

- [ ] Reverse proxy that rewrites multipart image uploads
- [ ] Local detectors (OCR+regex PII, face/QR/barcode) + worker pool
- [ ] Per-route YAML policy + bbox/category audit log
- [ ] S3 presigned-upload sidecar; PDF pages; optional VLM pass

## Installation

> Coming soon.

## License

[MIT](LICENSE) © 2026 Mykola Podpriatov
