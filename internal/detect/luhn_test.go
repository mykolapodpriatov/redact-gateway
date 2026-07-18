package detect_test

import (
	"context"
	"image"
	"image/color"
	"testing"

	"redact-gateway/internal/detect"
	"redact-gateway/internal/testutil"
)

func TestLuhnValid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// Known-valid test PANs.
		{"visa16", "4111111111111111", true},
		{"mastercard16", "5555555555554444", true},
		{"amex15", "378282246310005", true},
		// Length boundaries (13 and 19 digits) both valid.
		{"visa13boundary", "4222222222222", true},
		{"len19boundary", "4000000000000000006", true},
		// A checksum-failing 16-digit string.
		{"checksumFail16", "4111111111111112", false},
		// Separator tolerance: spaces and hyphens are stripped.
		{"spaces", "4111 1111 1111 1111", true},
		{"hyphens", "4111-1111-1111-1111", true},
		// A non-card long digit run must fail (the false positive is gone).
		{"nonCardRun16", "1234567890123456", false},
		// Out-of-range lengths and non-digit runes are rejected.
		{"tooShort12", "411111111111", false},
		{"tooLong20", "41111111111111111110", false},
		{"empty", "", false},
		{"letters", "4111abcd11111111", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detect.LuhnValid(tc.in); got != tc.want {
				t.Fatalf("LuhnValid(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCardPatternLuhnGating drives the gating through the detector: a valid PAN
// is masked as "card" while a bare 16-digit non-card run is not masked at all,
// proving the over-broad false positive is gone. Output stays sorted.
func TestCardPatternLuhnGating(t *testing.T) {
	ocr := &detect.FakeOCR{Boxes: []detect.TextBox{
		{Text: "pay to 4111 1111 1111 1111 today", Rect: image.Rect(0, 0, 100, 10)},
		{Text: "order id 1234567890123456", Rect: image.Rect(0, 20, 100, 30)},
	}}
	d := &detect.RegexPIIDetector{OCR: ocr, Patterns: detect.DefaultPIIPatterns()}
	regions, err := d.Detect(context.Background(), testutil.SolidRGBA(100, 40, color.White))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("want exactly 1 region (the valid card), got %d: %+v", len(regions), regions)
	}
	if regions[0].Category != "card" {
		t.Fatalf("category = %q, want card", regions[0].Category)
	}
	if regions[0].Rect != image.Rect(0, 0, 100, 10) {
		t.Fatalf("card bbox = %v, want the first box", regions[0].Rect)
	}
}
