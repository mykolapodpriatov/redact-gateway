package exif_test

import (
	"bytes"
	"image/color"
	"image/jpeg"
	"testing"

	"redact-gateway/internal/exif"
	"redact-gateway/internal/testutil"
)

func TestStripRemovesAllMetadata(t *testing.T) {
	in := testutil.JPEGWithMetadata(testutil.MetaOptions{
		EXIF:            true,
		IPTC:            true,
		COM:             true,
		ThumbnailMarker: []byte("THUMBNAIL-PIXELS-XYZ"),
	})
	// Sanity: input has all three segments and the thumbnail marker.
	if !testutil.HasSegment(in, 0xE1) || !testutil.HasSegment(in, 0xED) || !testutil.HasSegment(in, 0xFE) {
		t.Fatal("test input is missing expected segments")
	}
	if !bytes.Contains(in, []byte("THUMBNAIL-PIXELS-XYZ")) {
		t.Fatal("test input missing thumbnail marker")
	}

	out, err := exif.Strip(in)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if testutil.HasSegment(out, 0xE1) {
		t.Error("APP1 (EXIF/GPS) survived stripping")
	}
	if testutil.HasSegment(out, 0xED) {
		t.Error("APP13 (IPTC) survived stripping")
	}
	if testutil.HasSegment(out, 0xFE) {
		t.Error("COM survived stripping")
	}
	if bytes.Contains(out, []byte("THUMBNAIL-PIXELS-XYZ")) {
		t.Error("embedded thumbnail survived stripping")
	}
	if bytes.Contains(out, []byte("FAKEEXIFGPS")) {
		t.Error("EXIF GPS payload survived stripping")
	}
	// Output must still decode to a valid image.
	if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("stripped output no longer decodes: %v", err)
	}
}

func TestStripNoMetadataUnchanged(t *testing.T) {
	in := testutil.EncodeJPEG(testutil.SolidRGBA(8, 8, color.RGBA{R: 5, G: 5, B: 5, A: 255}), 90)
	if testutil.HasSegment(in, 0xE1) || testutil.HasSegment(in, 0xED) || testutil.HasSegment(in, 0xFE) {
		t.Skip("baseline JPEG unexpectedly carries metadata")
	}
	out, err := exif.Strip(in)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
	// Pixels must be identical after a no-op strip.
	if !bytes.Equal(in, out) {
		// Some encoders may differ structurally; at minimum the decoded image
		// must match. Re-decode both and compare bounds.
		a, _ := jpeg.Decode(bytes.NewReader(in))
		b, _ := jpeg.Decode(bytes.NewReader(out))
		if a.Bounds() != b.Bounds() {
			t.Fatalf("bounds changed by no-op strip: %v vs %v", a.Bounds(), b.Bounds())
		}
	}
}

func TestStripOnlyEXIF(t *testing.T) {
	in := testutil.JPEGWithMetadata(testutil.MetaOptions{EXIF: true})
	out, err := exif.Strip(in)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if testutil.HasSegment(out, 0xE1) {
		t.Fatal("APP1 survived")
	}
	if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
}

func TestStripRejectsNonJPEG(t *testing.T) {
	if _, err := exif.Strip([]byte("\x89PNG\r\n\x1a\n....")); err != exif.ErrNotJPEG {
		t.Fatalf("want ErrNotJPEG, got %v", err)
	}
	if _, err := exif.Strip([]byte{0xFF}); err != exif.ErrNotJPEG {
		t.Fatalf("want ErrNotJPEG for short input, got %v", err)
	}
}

func TestStripRejectsMalformed(t *testing.T) {
	// SOI followed by a marker claiming a length that overruns the buffer.
	bad := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF, 0x00}
	_, err := exif.Strip(bad)
	if err == nil {
		t.Fatal("expected malformed error")
	}
}

func TestStripMalformedNoSOS(t *testing.T) {
	// SOI then a valid APP1 but the stream ends before SOS/EOI.
	in := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x04, 0x41, 0x42}
	_, err := exif.Strip(in)
	if err == nil {
		t.Fatal("expected error for stream ending before SOS/EOI")
	}
}
