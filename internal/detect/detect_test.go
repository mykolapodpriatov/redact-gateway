package detect_test

import (
	"context"
	"errors"
	"image"
	"image/color"
	"testing"

	"redact-gateway/internal/detect"
	"redact-gateway/internal/testutil"
)

func TestRegionMarkerDetectorFindsRect(t *testing.T) {
	bg := color.RGBA{R: 250, G: 250, B: 250, A: 255}
	marker := color.RGBA{R: 255, G: 0, B: 255, A: 255}
	rect := image.Rect(8, 6, 20, 16)
	src := testutil.WithRect(testutil.SolidRGBA(40, 30, bg), rect, marker)

	d := &detect.RegionMarkerDetector{Marker: marker, Tolerance: 8}
	regions, err := d.Detect(context.Background(), src)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("want 1 region, got %d: %+v", len(regions), regions)
	}
	if regions[0].Rect != rect {
		t.Fatalf("region rect = %v, want %v", regions[0].Rect, rect)
	}
	if regions[0].Category != "marker" {
		t.Fatalf("category = %q", regions[0].Category)
	}
}

func TestRegionMarkerDetectorTwoBlocksOrdered(t *testing.T) {
	bg := color.RGBA{R: 0, G: 0, B: 0, A: 255}
	marker := color.RGBA{R: 255, G: 255, B: 0, A: 255}
	r1 := image.Rect(2, 2, 6, 6)
	r2 := image.Rect(20, 18, 28, 24)
	img := testutil.WithRect(testutil.SolidRGBA(40, 40, bg), r1, marker)
	img = testutil.WithRect(img, r2, marker)

	d := &detect.RegionMarkerDetector{Marker: marker, Tolerance: 4}
	regions, err := d.Detect(context.Background(), img)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 2 {
		t.Fatalf("want 2 regions, got %d", len(regions))
	}
	// Deterministic order by (MinY, MinX): r1 before r2.
	if regions[0].Rect != r1 || regions[1].Rect != r2 {
		t.Fatalf("regions out of order: %v", regions)
	}
}

func TestRegionMarkerDetectorNoMarker(t *testing.T) {
	src := testutil.SolidRGBA(20, 20, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	d := &detect.RegionMarkerDetector{Marker: color.RGBA{R: 255, G: 0, B: 255, A: 255}}
	regions, err := d.Detect(context.Background(), src)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 0 {
		t.Fatalf("expected no regions, got %d", len(regions))
	}
}

func TestRegionMarkerDetectorMinArea(t *testing.T) {
	bg := color.RGBA{A: 255}
	marker := color.RGBA{R: 255, G: 0, B: 255, A: 255}
	small := image.Rect(1, 1, 3, 3) // area 4
	img := testutil.WithRect(testutil.SolidRGBA(20, 20, bg), small, marker)
	d := &detect.RegionMarkerDetector{Marker: marker, MinArea: 100}
	regions, err := d.Detect(context.Background(), img)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 0 {
		t.Fatalf("MinArea should have filtered the small blob, got %d", len(regions))
	}
}

func TestRegionMarkerDetectorCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &detect.RegionMarkerDetector{Marker: color.RGBA{A: 255}}
	if _, err := d.Detect(ctx, testutil.SolidRGBA(4, 4, color.White)); err == nil {
		t.Fatal("expected context error")
	}
}

func TestRegexPIIOverFakeOCR(t *testing.T) {
	ocr := &detect.FakeOCR{Boxes: []detect.TextBox{
		{Text: "contact me at jane.doe@example.com please", Rect: image.Rect(0, 0, 100, 10)},
		{Text: "card 4111 1111 1111 1111", Rect: image.Rect(0, 20, 100, 30)},
		{Text: "ssn 123-45-6789", Rect: image.Rect(0, 40, 100, 50)},
		{Text: "nothing sensitive here", Rect: image.Rect(0, 60, 100, 70)},
	}}
	d := &detect.RegexPIIDetector{OCR: ocr, Patterns: detect.DefaultPIIPatterns()}
	regions, err := d.Detect(context.Background(), testutil.SolidRGBA(100, 80, color.White))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 3 {
		t.Fatalf("want 3 PII regions, got %d: %+v", len(regions), regions)
	}
	gotCats := map[string]image.Rectangle{}
	for _, r := range regions {
		gotCats[r.Category] = r.Rect
	}
	if gotCats["email"] != image.Rect(0, 0, 100, 10) {
		t.Errorf("email bbox wrong: %v", gotCats["email"])
	}
	if gotCats["card"] != image.Rect(0, 20, 100, 30) {
		t.Errorf("card bbox wrong: %v", gotCats["card"])
	}
	if gotCats["ssn"] != image.Rect(0, 40, 100, 50) {
		t.Errorf("ssn bbox wrong: %v", gotCats["ssn"])
	}
}

func TestRegexPIINopOCRFindsNothing(t *testing.T) {
	d := &detect.RegexPIIDetector{OCR: detect.NopOCR{}, Patterns: detect.DefaultPIIPatterns()}
	regions, err := d.Detect(context.Background(), testutil.SolidRGBA(10, 10, color.White))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(regions) != 0 {
		t.Fatalf("NopOCR must find nothing, got %d", len(regions))
	}
}

func TestRegexPIIPropagatesOCRError(t *testing.T) {
	wantErr := errors.New("ocr boom")
	d := &detect.RegexPIIDetector{OCR: &detect.FakeOCR{Err: wantErr}}
	_, err := d.Detect(context.Background(), testutil.SolidRGBA(4, 4, color.White))
	if !errors.Is(err, wantErr) {
		t.Fatalf("want wrapped ocr error, got %v", err)
	}
}

func TestFakeDetector(t *testing.T) {
	want := []detect.Region{{Rect: image.Rect(1, 1, 2, 2), Category: "x"}}
	f := &detect.FakeDetector{Regions: want}
	got, err := f.Detect(context.Background(), testutil.SolidRGBA(4, 4, color.White))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 1 || got[0].Rect != want[0].Rect {
		t.Fatalf("fake regions mismatch: %v", got)
	}
	if f.Name() != "fake" {
		t.Fatalf("name = %q", f.Name())
	}

	boom := errors.New("scripted")
	fe := &detect.FakeDetector{Err: boom}
	if _, err := fe.Detect(context.Background(), testutil.SolidRGBA(4, 4, color.White)); !errors.Is(err, boom) {
		t.Fatalf("want scripted error, got %v", err)
	}
}
