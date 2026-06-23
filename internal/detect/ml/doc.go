// Package ml documents and scaffolds the OPTIONAL machine-learning detector
// adapters (face, QR/barcode, OCR, VLM). None of these are compiled into the
// default stdlib-only build or CI: each real adapter lives in a file guarded
// by a Go build tag (for example //go:build opencv) and requires native
// libraries the default binary deliberately avoids.
//
// # Why build tags
//
// The default build must stay dependency-free, offline-testable, and free of
// cgo/native libraries. ML detectors need heavyweight runtimes (OpenCV/gocv
// for face detection, gozxing for QR, tesseract for OCR, a cloud client for a
// VLM). Gating them behind build tags means `go build ./...` and the CI matrix
// never pull those dependencies, while an operator who needs them can opt in
// with `go build -tags opencv` (and accept the native toolchain requirement).
//
// # Implementing an adapter
//
// Each adapter implements the same interfaces as the default detectors so it
// drops into the pipeline unchanged:
//
//	detect.Detector — face/QR/VLM region detectors
//	detect.OCR      — a real OCR engine that makes RegexPIIDetector active
//
// A file should start with a build tag and a matching package clause, e.g.:
//
//	//go:build opencv
//
//	package ml
//
//	// FaceDetector uses gocv (OpenCV) Haar cascades to find faces.
//	type FaceDetector struct{ /* cascade handle */ }
//	func (d *FaceDetector) Name() string { return "face" }
//	func (d *FaceDetector) Detect(ctx context.Context, img image.Image) ([]detect.Region, error) { /* ... */ }
//
// The operator then registers the adapter by name in the detector registry
// (see cmd/redact-gateway) under the build tag, and references it in a route's
// detectors list in the config.
//
// # Kill switch for the VLM adapter
//
// The optional VLM (vision-language-model) adapter sends image content to a
// cloud API and is therefore the only detector that can transmit pixels off
// the box. It MUST be gated behind BOTH a build tag and an explicit runtime
// kill switch (a config flag that defaults to disabled), and is documented as
// breaking the local-by-default guarantee. It is intentionally not provided in
// this scaffold.
package ml
