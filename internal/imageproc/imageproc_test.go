package imageproc_test

import (
	"bytes"
	"image"
	"image/color"
	"testing"

	"redact-gateway/internal/imageproc"
	"redact-gateway/internal/testutil"
)

const maxPixels = 40_000_000

func TestDetectFormat(t *testing.T) {
	jpg := testutil.EncodeJPEG(testutil.SolidRGBA(4, 4, color.White), 90)
	png := testutil.EncodePNG(testutil.SolidRGBA(4, 4, color.White))
	if f, err := imageproc.DetectFormat(jpg); err != nil || f != imageproc.FormatJPEG {
		t.Fatalf("jpeg detect: %v %v", f, err)
	}
	if f, err := imageproc.DetectFormat(png); err != nil || f != imageproc.FormatPNG {
		t.Fatalf("png detect: %v %v", f, err)
	}
	if _, err := imageproc.DetectFormat([]byte("not an image")); err == nil {
		t.Fatal("expected error for non-image")
	}
}

func TestSniffIsImage(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"jpeg", testutil.EncodeJPEG(testutil.SolidRGBA(2, 2, color.White), 90), true},
		{"png", testutil.EncodePNG(testutil.SolidRGBA(2, 2, color.White)), true},
		{"gif", []byte("GIF89a\x00\x00"), true},
		{"webp", append([]byte("RIFF\x00\x00\x00\x00WEBP"), 0, 0), true},
		{"text", []byte("hello world this is text"), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := imageproc.SniffIsImage(c.data); got != c.want {
				t.Fatalf("SniffIsImage(%s)=%v want %v", c.name, got, c.want)
			}
		})
	}
}

func TestDecodeRoundtripPNG(t *testing.T) {
	src := testutil.SolidRGBA(16, 12, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	data := testutil.EncodePNG(src)
	dec, err := imageproc.Decode(data, maxPixels)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Format != imageproc.FormatPNG {
		t.Fatalf("format: %v", dec.Format)
	}
	if dec.Image.Bounds() != src.Bounds() {
		t.Fatalf("bounds: %v want %v", dec.Image.Bounds(), src.Bounds())
	}
}

func TestDecodeRoundtripJPEG(t *testing.T) {
	src := testutil.SolidRGBA(20, 10, color.RGBA{R: 100, G: 110, B: 120, A: 255})
	data := testutil.EncodeJPEG(src, 95)
	dec, err := imageproc.Decode(data, maxPixels)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Format != imageproc.FormatJPEG {
		t.Fatalf("format: %v", dec.Format)
	}
	if dec.Image.Bounds().Dx() != 20 || dec.Image.Bounds().Dy() != 10 {
		t.Fatalf("bounds: %v", dec.Image.Bounds())
	}
}

func TestDecodeDecompressionBomb(t *testing.T) {
	bomb := testutil.JPEGBomb(60000, 60000) // 3.6 gigapixels declared
	_, err := imageproc.Decode(bomb, maxPixels)
	if err == nil {
		t.Fatal("expected bomb to be rejected")
	}
	if err != imageproc.ErrTooManyPixels {
		t.Fatalf("want ErrTooManyPixels, got %v", err)
	}
}

func TestDecodeTruncated(t *testing.T) {
	trunc := testutil.TruncatedJPEG()
	_, err := imageproc.Decode(trunc, maxPixels)
	if err == nil {
		t.Fatal("expected truncated JPEG to be rejected (never partial)")
	}
}

func TestDecodeUnsupportedFormat(t *testing.T) {
	gif := []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00")
	_, err := imageproc.Decode(gif, maxPixels)
	if err != imageproc.ErrUnsupportedFormat {
		t.Fatalf("want ErrUnsupportedFormat, got %v", err)
	}
}

func TestMaskSolidChangesRegionOnly(t *testing.T) {
	bg := color.RGBA{R: 200, G: 200, B: 200, A: 255}
	src := testutil.SolidRGBA(40, 40, bg)
	region := image.Rect(10, 10, 20, 20)
	out := imageproc.Mask(src, []image.Rectangle{region}, imageproc.MaskOptions{Mode: imageproc.MaskSolid})

	// Inside the region: must be opaque black (the default fill).
	for y := region.Min.Y; y < region.Max.Y; y++ {
		for x := region.Min.X; x < region.Max.X; x++ {
			if got := out.RGBAAt(x, y); got != (color.RGBA{A: 255}) {
				t.Fatalf("region pixel (%d,%d) = %v, want black", x, y, got)
			}
		}
	}
	// Outside the region: unchanged background.
	corners := []image.Point{{X: 0, Y: 0}, {X: 39, Y: 0}, {X: 0, Y: 39}, {X: 39, Y: 39}, {X: 25, Y: 25}}
	for _, p := range corners {
		if got := out.RGBAAt(p.X, p.Y); got != bg {
			t.Fatalf("non-region pixel %v changed: %v", p, got)
		}
	}
}

func TestMaskClampsOutOfBounds(t *testing.T) {
	src := testutil.SolidRGBA(10, 10, color.White)
	// Region partly and fully out of bounds, plus a degenerate zero-area rect.
	regions := []image.Rectangle{
		image.Rect(5, 5, 100, 100), // overflow
		image.Rect(-50, -50, 3, 3), // negative origin
		image.Rect(2, 2, 2, 2),     // zero area
		image.Rect(50, 50, 60, 60), // fully outside
	}
	out := imageproc.Mask(src, regions, imageproc.MaskOptions{Mode: imageproc.MaskSolid})
	if out.Bounds() != src.Bounds() {
		t.Fatalf("bounds changed: %v", out.Bounds())
	}
	// Pixel (8,0) is outside all clamped fill areas → unchanged. (The
	// negative-origin rect clamps to (0,0)-(3,3); the overflow rect clamps to
	// (5,5)-(10,10); neither covers (8,0).)
	if out.RGBAAt(8, 0) != (color.RGBA{R: 255, G: 255, B: 255, A: 255}) {
		t.Fatalf("(8,0) unexpectedly changed: %v", out.RGBAAt(8, 0))
	}
	// Pixel (5,5) is inside the first region → black.
	if out.RGBAAt(5, 5) != (color.RGBA{A: 255}) {
		t.Fatalf("(5,5) should be masked: %v", out.RGBAAt(5, 5))
	}
}

func TestMaskBlurBounded(t *testing.T) {
	// A sharp checkerboard region; after blur, interior pixels should differ
	// from the original sharp values but bounds stay intact and outside is
	// unchanged.
	src := image.NewRGBA(image.Rect(0, 0, 20, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 20; x++ {
			if (x+y)%2 == 0 {
				src.SetRGBA(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
			} else {
				src.SetRGBA(x, y, color.RGBA{A: 255})
			}
		}
	}
	region := image.Rect(4, 4, 16, 16)
	out := imageproc.Mask(src, []image.Rectangle{region}, imageproc.MaskOptions{Mode: imageproc.MaskBlur, BlurRadius: 3})
	if out.Bounds() != src.Bounds() {
		t.Fatalf("bounds changed: %v", out.Bounds())
	}
	// Outside the region unchanged.
	if out.RGBAAt(0, 0) != src.RGBAAt(0, 0) {
		t.Fatalf("outside region changed")
	}
	// Inside, at least one pixel should have become a mid-gray (averaged).
	changed := false
	for y := region.Min.Y; y < region.Max.Y; y++ {
		for x := region.Min.X; x < region.Max.X; x++ {
			c := out.RGBAAt(x, y)
			if c.R != 0 && c.R != 255 {
				changed = true
			}
		}
	}
	if !changed {
		t.Fatal("blur did not average any region pixel")
	}
}

func TestEncodeRoundtrip(t *testing.T) {
	src := testutil.SolidRGBA(8, 8, color.RGBA{R: 9, G: 9, B: 9, A: 255})
	for _, f := range []imageproc.Format{imageproc.FormatPNG, imageproc.FormatJPEG} {
		out, err := imageproc.Encode(src, f, imageproc.EncodeOptions{JPEGQuality: 90})
		if err != nil {
			t.Fatalf("encode %s: %v", f, err)
		}
		dec, err := imageproc.Decode(out, maxPixels)
		if err != nil {
			t.Fatalf("re-decode %s: %v", f, err)
		}
		if dec.Format != f {
			t.Fatalf("format mismatch: %v != %v", dec.Format, f)
		}
	}
}

func TestEncodeEmptyFails(t *testing.T) {
	empty := image.NewRGBA(image.Rect(0, 0, 0, 0))
	if _, err := imageproc.Encode(empty, imageproc.FormatPNG, imageproc.EncodeOptions{}); err == nil {
		t.Fatal("expected error encoding empty image")
	}
	if _, err := imageproc.Encode(nil, imageproc.FormatPNG, imageproc.EncodeOptions{}); err == nil {
		t.Fatal("expected error encoding nil image")
	}
}

func TestEncodeDropsMetadata(t *testing.T) {
	// Decoding a metadata-laden JPEG then re-encoding must yield bytes with no
	// APP1/APP13/COM segments (re-encode inherently drops them).
	withMeta := testutil.JPEGWithMetadata(testutil.MetaOptions{EXIF: true, IPTC: true, COM: true})
	dec, err := imageproc.Decode(withMeta, maxPixels)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out, err := imageproc.Encode(dec.Image, imageproc.FormatJPEG, imageproc.EncodeOptions{JPEGQuality: 90})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if testutil.HasSegment(out, 0xE1) || testutil.HasSegment(out, 0xED) || testutil.HasSegment(out, 0xFE) {
		t.Fatal("re-encoded image still contains metadata segments")
	}
	if bytes.Contains(out, []byte("FAKEEXIFGPS")) {
		t.Fatal("re-encoded image leaked EXIF payload")
	}
}
