// Package detect defines the detector and OCR interfaces used by the
// redaction pipeline, together with the real stdlib-only detectors that ship
// in the default build (an explicit-region marker detector and a regex-PII
// detector over a pluggable OCR interface) and a deterministic fake used by
// tests.
//
// Heavyweight ML detectors (face/OCR/QR/VLM) implement these same interfaces
// but live under internal/detect/ml behind Go build tags, so the default
// build and CI stay dependency-free. See internal/detect/ml for wiring docs.
package detect

import (
	"context"
	"image"
)

// Region is a single sensitive rectangle reported by a Detector. Rect is in
// image-pixel coordinates; Category is a short machine label (for example
// "face", "email", "marker") recorded in the audit log; Confidence is an
// optional detector score in [0,1].
type Region struct {
	Rect       image.Rectangle
	Category   string
	Confidence float64
}

// Detector inspects a decoded image and reports the sensitive regions it
// found. Implementations MUST be safe for concurrent use: the worker pool may
// invoke Detect from many goroutines at once.
//
// A non-nil error is treated as fail-closed by the pipeline: on a redact/blur
// route the whole upload is blocked rather than forwarded, so a detector must
// only return nil error when it genuinely completed. Returning an empty slice
// with a nil error means "scanned, found nothing".
type Detector interface {
	// Name is a short stable identifier used in config route detector lists
	// and in error messages.
	Name() string
	// Detect reports sensitive regions in img. It must honor ctx cancellation.
	Detect(ctx context.Context, img image.Image) ([]Region, error)
}

// TextBox is a single piece of text recognized by an OCR engine together with
// the image rectangle it occupies.
type TextBox struct {
	Text string
	Rect image.Rectangle
}

// OCR extracts text-with-bounding-boxes from an image. The default build wires
// a no-op OCR (NopOCR) that returns nothing, so RegexPIIDetector finds nothing
// until a real OCR adapter (for example tesseract, behind a build tag) is
// plugged in. Implementations MUST be safe for concurrent use.
type OCR interface {
	// Extract returns the recognized text boxes in img, honoring ctx.
	Extract(ctx context.Context, img image.Image) ([]TextBox, error)
}

// NopOCR is the default OCR: it recognizes no text. It exists so the regex-PII
// detector compiles and runs deterministically in the stdlib-only build
// (finding nothing) and lights up only when a real OCR adapter is supplied.
type NopOCR struct{}

// Extract always returns an empty slice and a nil error.
func (NopOCR) Extract(context.Context, image.Image) ([]TextBox, error) { return nil, nil }
