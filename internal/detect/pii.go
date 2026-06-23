package detect

import (
	"context"
	"image"
	"regexp"
	"sort"
)

// RegexPIIDetector finds personally-identifiable text by running configured
// regexes over the output of an OCR engine and reporting the bounding box of
// every matching text box. With the default NopOCR it finds nothing
// (documented); supplying a real OCR adapter makes it active without any
// change to the rest of the pipeline.
type RegexPIIDetector struct {
	// OCR extracts text boxes from the image. Required.
	OCR OCR
	// Patterns maps a category label (recorded in the audit log, for example
	// "email" or "card") to a compiled regexp. A text box whose text matches
	// any pattern becomes a Region with that pattern's category.
	Patterns []PIIPattern
}

// PIIPattern pairs a category label with the regexp that detects it.
type PIIPattern struct {
	Category string
	Regexp   *regexp.Regexp
}

// DefaultPIIPatterns returns a small, conservative set of PII regexes
// (email-like, payment-card-like, US-SSN-like). They are intentionally simple
// and meant to run over OCR text, not raw bytes.
func DefaultPIIPatterns() []PIIPattern {
	return []PIIPattern{
		{Category: "email", Regexp: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)},
		{Category: "card", Regexp: regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)},
		{Category: "ssn", Regexp: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	}
}

// Name implements Detector.
func (d *RegexPIIDetector) Name() string { return "regex-pii" }

// Detect implements Detector. It runs OCR, matches each recognized text box
// against the configured patterns, and reports a Region for every match
// (first matching pattern wins per box). An OCR error is propagated so the
// pipeline can fail closed.
func (d *RegexPIIDetector) Detect(ctx context.Context, img image.Image) ([]Region, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.OCR == nil {
		// Treat a missing OCR as "no text source": deterministic, finds
		// nothing. This mirrors the default NopOCR behavior.
		return nil, nil
	}
	boxes, err := d.OCR.Extract(ctx, img)
	if err != nil {
		return nil, err
	}
	patterns := d.Patterns
	if patterns == nil {
		patterns = DefaultPIIPatterns()
	}

	var regions []Region
	for _, tb := range boxes {
		for _, p := range patterns {
			if p.Regexp != nil && p.Regexp.MatchString(tb.Text) {
				regions = append(regions, Region{
					Rect:       tb.Rect,
					Category:   p.Category,
					Confidence: 1,
				})
				break
			}
		}
	}
	sortRegions(regions)
	return regions, nil
}

// sortRegions orders regions deterministically by (MinY, MinX, MaxY, MaxX,
// Category) so detector output is stable regardless of map iteration order.
func sortRegions(regions []Region) {
	sort.Slice(regions, func(i, j int) bool {
		a, b := regions[i].Rect, regions[j].Rect
		switch {
		case a.Min.Y != b.Min.Y:
			return a.Min.Y < b.Min.Y
		case a.Min.X != b.Min.X:
			return a.Min.X < b.Min.X
		case a.Max.Y != b.Max.Y:
			return a.Max.Y < b.Max.Y
		case a.Max.X != b.Max.X:
			return a.Max.X < b.Max.X
		default:
			return regions[i].Category < regions[j].Category
		}
	})
}
