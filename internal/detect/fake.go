package detect

import (
	"context"
	"image"
)

// FakeDetector returns scripted regions (or a scripted error) regardless of
// the image, for deterministic tests of the policy/proxy/pipeline layers. It
// is safe for concurrent use.
type FakeDetector struct {
	// DetectorName is returned by Name. Defaults to "fake" when empty.
	DetectorName string
	// Regions is returned verbatim by Detect (clamped/clipped by the caller).
	Regions []Region
	// Err, when non-nil, is returned by Detect to exercise fail-closed paths.
	Err error
}

// Name implements Detector.
func (f *FakeDetector) Name() string {
	if f.DetectorName == "" {
		return "fake"
	}
	return f.DetectorName
}

// Detect implements Detector. It honors ctx cancellation, then returns the
// scripted error (if any) or a copy of the scripted regions.
func (f *FakeDetector) Detect(ctx context.Context, _ image.Image) ([]Region, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.Err != nil {
		return nil, f.Err
	}
	if len(f.Regions) == 0 {
		return nil, nil
	}
	out := make([]Region, len(f.Regions))
	copy(out, f.Regions)
	return out, nil
}

// FakeOCR returns scripted text boxes (or an error), for testing
// RegexPIIDetector without a real OCR engine.
type FakeOCR struct {
	Boxes []TextBox
	Err   error
}

// Extract implements OCR.
func (f *FakeOCR) Extract(ctx context.Context, _ image.Image) ([]TextBox, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.Err != nil {
		return nil, f.Err
	}
	out := make([]TextBox, len(f.Boxes))
	copy(out, f.Boxes)
	return out, nil
}
