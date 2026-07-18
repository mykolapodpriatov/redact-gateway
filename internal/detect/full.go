package detect

import (
	"context"
	"image"
)

// FullImageDetector reports a single Region covering the entire image bounds.
// It is deterministic and stdlib-only, for locked-down upload routes that must
// redact or blur every pixel regardless of content (a "mask everything"
// policy), where any content-based detector would be too permissive.
type FullImageDetector struct {
	// Category labels the produced region in the audit log. Defaults to
	// "full-image" when empty.
	Category string
}

// Name implements Detector.
func (d *FullImageDetector) Name() string { return "full-image" }

// Detect implements Detector. It honors ctx cancellation and returns exactly
// one Region equal to the image's bounds. A degenerate (empty) image yields no
// region, matching the other detectors' "found nothing" convention.
func (d *FullImageDetector) Detect(ctx context.Context, img image.Image) ([]Region, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b := img.Bounds()
	if b.Empty() {
		return nil, nil
	}
	category := d.Category
	if category == "" {
		category = "full-image"
	}
	return []Region{{Rect: b, Category: category, Confidence: 1}}, nil
}
