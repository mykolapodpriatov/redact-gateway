package imageproc_test

import (
	"image"
	"image/color"
	"testing"

	"redact-gateway/internal/imageproc"
	"redact-gateway/internal/testutil"
)

func TestSniffBMPandTIFF(t *testing.T) {
	bmp := []byte{0x42, 0x4D, 0, 0, 0, 0}
	tiffLE := []byte("II*\x00....")
	tiffBE := []byte("MM\x00*....")
	if !imageproc.SniffIsImage(bmp) {
		t.Error("BMP not sniffed as image")
	}
	if !imageproc.SniffIsImage(tiffLE) || !imageproc.SniffIsImage(tiffBE) {
		t.Error("TIFF not sniffed as image")
	}
}

func TestMaskTransparentFillBecomesBlack(t *testing.T) {
	// A fully transparent fill must be replaced with opaque black so a redact
	// never leaves the region see-through.
	src := testutil.SolidRGBA(10, 10, color.RGBA{R: 200, G: 200, B: 200, A: 255})
	out := imageproc.Mask(src, []image.Rectangle{image.Rect(2, 2, 8, 8)}, imageproc.MaskOptions{
		Mode: imageproc.MaskSolid,
		Fill: color.RGBA{0, 0, 0, 0}, // transparent
	})
	if got := out.RGBAAt(5, 5); got != (color.RGBA{A: 255}) {
		t.Fatalf("transparent fill not coerced to opaque black: %v", got)
	}
}

func TestMaskCustomOpaqueFill(t *testing.T) {
	src := testutil.SolidRGBA(10, 10, color.White)
	red := color.RGBA{R: 255, G: 0, B: 0, A: 255}
	out := imageproc.Mask(src, []image.Rectangle{image.Rect(0, 0, 5, 5)}, imageproc.MaskOptions{
		Mode: imageproc.MaskSolid,
		Fill: red,
	})
	if got := out.RGBAAt(2, 2); got != red {
		t.Fatalf("custom fill not applied: %v", got)
	}
}

func TestEncodeUnsupportedFormat(t *testing.T) {
	src := testutil.SolidRGBA(4, 4, color.White)
	if _, err := imageproc.Encode(src, imageproc.Format("gif"), imageproc.EncodeOptions{}); err == nil {
		t.Fatal("expected error for unsupported encode format")
	}
}

func TestEncodeDefaultsBadQuality(t *testing.T) {
	src := testutil.SolidRGBA(8, 8, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	// Out-of-range quality must fall back to a default, not error.
	out, err := imageproc.Encode(src, imageproc.FormatJPEG, imageproc.EncodeOptions{JPEGQuality: 9999})
	if err != nil {
		t.Fatalf("encode with bad quality should default, got: %v", err)
	}
	if _, err := imageproc.Decode(out, 40_000_000); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
}

func TestDecodeConfigCorruptHeader(t *testing.T) {
	// Sniffs as PNG but the header is garbage → DecodeConfig fails.
	bad := append([]byte("\x89PNG\r\n\x1a\n"), []byte("garbage-not-ihdr")...)
	if _, err := imageproc.Decode(bad, 40_000_000); err == nil {
		t.Fatal("expected decode-config error for corrupt PNG header")
	}
}

func TestDecodeMaxPixelsDisabled(t *testing.T) {
	// maxPixels <= 0 disables the cap; a normal image still decodes.
	data := testutil.EncodePNG(testutil.SolidRGBA(16, 16, color.White))
	if _, err := imageproc.Decode(data, 0); err != nil {
		t.Fatalf("decode with disabled cap: %v", err)
	}
}
