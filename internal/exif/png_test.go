package exif_test

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image/png"
	"testing"

	"redact-gateway/internal/exif"
	"redact-gateway/internal/testutil"
)

func TestStripPNGRemovesMetadataChunks(t *testing.T) {
	in := testutil.PNGWithMetadata()
	// Sanity: input carries the eXIf and tEXt chunks and their secrets.
	if !testutil.HasPNGChunk(in, "eXIf") || !testutil.HasPNGChunk(in, "tEXt") {
		t.Fatal("test input is missing the expected metadata chunks")
	}
	if !bytes.Contains(in, []byte("FAKE-PNG-GPS")) || !bytes.Contains(in, []byte("PNG-TEXT-SECRET")) {
		t.Fatal("test input is missing the expected metadata payloads")
	}

	out, err := exif.StripPNG(in)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if testutil.HasPNGChunk(out, "eXIf") {
		t.Error("eXIf (GPS) chunk survived stripping")
	}
	if testutil.HasPNGChunk(out, "tEXt") {
		t.Error("tEXt chunk survived stripping")
	}
	if bytes.Contains(out, []byte("FAKE-PNG-GPS")) {
		t.Error("eXIf GPS payload survived stripping")
	}
	if bytes.Contains(out, []byte("PNG-TEXT-SECRET")) {
		t.Error("tEXt payload survived stripping")
	}
	// Critical chunks must remain and the output must still decode to the same
	// pixels.
	if !testutil.HasPNGChunk(out, "IHDR") || !testutil.HasPNGChunk(out, "IDAT") || !testutil.HasPNGChunk(out, "IEND") {
		t.Fatal("a critical chunk was dropped")
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("stripped output no longer decodes: %v", err)
	}
	if img.Bounds().Dx() != 8 || img.Bounds().Dy() != 8 {
		t.Fatalf("decoded bounds changed: %v", img.Bounds())
	}
}

func TestStripPNGNoMetadataDecodes(t *testing.T) {
	// A vanilla PNG with no metadata chunks must round-trip to a decodable PNG.
	in := testutil.EncodePNG(testutil.SolidRGBA(8, 8, nil))
	out, err := exif.StripPNG(in)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
}

func TestStripPNGRejectsNonPNG(t *testing.T) {
	if _, err := exif.StripPNG([]byte{0xFF, 0xD8, 0xFF, 0xE0}); err != exif.ErrNotPNG {
		t.Fatalf("want ErrNotPNG for JPEG bytes, got %v", err)
	}
	if _, err := exif.StripPNG([]byte("short")); err != exif.ErrNotPNG {
		t.Fatalf("want ErrNotPNG for short input, got %v", err)
	}
}

func TestStripPNGRejectsMalformed(t *testing.T) {
	// Valid signature + IHDR, then a chunk whose declared length overruns the
	// buffer.
	base := testutil.EncodePNG(testutil.SolidRGBA(4, 4, nil))
	// Truncate to signature + IHDR, then append a bogus chunk header with a huge
	// length and no body.
	const sig = 8
	const ihdr = 4 + 4 + 13 + 4
	bad := append([]byte(nil), base[:sig+ihdr]...)
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 0xFFFFFF) // absurd length
	copy(hdr[4:8], "tEXt")
	bad = append(bad, hdr[:]...)
	if _, err := exif.StripPNG(bad); err == nil {
		t.Fatal("expected malformed error for overrunning chunk")
	}
}

func TestStripPNGRejectsMissingIEND(t *testing.T) {
	// Signature + a well-formed eXIf chunk but no IEND terminator.
	out := append([]byte(nil), []byte("\x89PNG\r\n\x1a\n")...)
	payload := []byte("Exif\x00\x00data")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	out = append(out, lenBuf[:]...)
	out = append(out, "eXIf"...)
	out = append(out, payload...)
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte("eXIf"))
	_, _ = crc.Write(payload)
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc.Sum32())
	out = append(out, crcBuf[:]...)
	if _, err := exif.StripPNG(out); err == nil {
		t.Fatal("expected error for PNG stream missing IEND")
	}
}
