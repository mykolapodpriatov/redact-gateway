package detect_test

import (
	"context"
	"image"
	"image/color"
	"testing"

	"redact-gateway/internal/detect"
	"redact-gateway/internal/testutil"
)

func TestFullImageDetectorCoversBounds(t *testing.T) {
	sizes := []struct{ w, h int }{
		{1, 1},
		{16, 9},
		{100, 50},
		{640, 480},
	}
	d := &detect.FullImageDetector{}
	if d.Name() != "full-image" {
		t.Fatalf("name = %q, want full-image", d.Name())
	}
	for _, s := range sizes {
		src := testutil.SolidRGBA(s.w, s.h, color.White)
		regions, err := d.Detect(context.Background(), src)
		if err != nil {
			t.Fatalf("%dx%d detect: %v", s.w, s.h, err)
		}
		if len(regions) != 1 {
			t.Fatalf("%dx%d: want 1 region, got %d", s.w, s.h, len(regions))
		}
		if regions[0].Rect != src.Bounds() {
			t.Fatalf("%dx%d: region rect = %v, want image bounds %v", s.w, s.h, regions[0].Rect, src.Bounds())
		}
		if regions[0].Category != "full-image" {
			t.Fatalf("%dx%d: category = %q, want full-image", s.w, s.h, regions[0].Category)
		}
	}
}

// TestFullImageDetectorNonZeroOrigin covers an image whose bounds do not start
// at (0,0): the region must equal those exact bounds.
func TestFullImageDetectorNonZeroOrigin(t *testing.T) {
	bounds := image.Rect(5, 7, 25, 20)
	src := image.NewRGBA(bounds)
	regions, err := (&detect.FullImageDetector{}).Detect(context.Background(), src)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 1 || regions[0].Rect != bounds {
		t.Fatalf("region = %+v, want single region equal to %v", regions, bounds)
	}
}

// TestFullImageDetectorCustomCategory verifies the Category field overrides the
// default label.
func TestFullImageDetectorCustomCategory(t *testing.T) {
	d := &detect.FullImageDetector{Category: "all-pixels"}
	regions, err := d.Detect(context.Background(), testutil.SolidRGBA(8, 8, color.White))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 1 || regions[0].Category != "all-pixels" {
		t.Fatalf("regions = %+v, want one region with category all-pixels", regions)
	}
}

// TestFullImageDetectorEmptyImage confirms a degenerate image yields no region.
func TestFullImageDetectorEmptyImage(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 0, 0))
	regions, err := (&detect.FullImageDetector{}).Detect(context.Background(), src)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 0 {
		t.Fatalf("empty image should yield no region, got %d", len(regions))
	}
}

// TestFullImageDetectorCanceled confirms ctx cancellation is honored.
func TestFullImageDetectorCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&detect.FullImageDetector{}).Detect(ctx, testutil.SolidRGBA(4, 4, color.White)); err == nil {
		t.Fatal("expected context error")
	}
}
