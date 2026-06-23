package exif_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"redact-gateway/internal/exif"
	"redact-gateway/internal/testutil"
)

// seg builds an FF<marker><len><payload> segment.
func seg(marker byte, payload []byte) []byte {
	out := []byte{0xFF, marker}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)+2))
	out = append(out, l[:]...)
	return append(out, payload...)
}

// minimalScan returns a tiny but valid SOS + scan + EOI tail extracted from a
// real encoded JPEG, so handcrafted streams terminate correctly.
func minimalScanTail(t *testing.T) []byte {
	t.Helper()
	data := testutil.EncodeJPEG(testutil.SolidRGBA(8, 8, nil), 80)
	// Find SOS marker and return from its 0xFF to the end.
	for i := 2; i+1 < len(data); {
		if data[i] != 0xFF {
			i++
			continue
		}
		m := data[i+1]
		if m == 0xDA { // SOS
			return data[i:]
		}
		i++
	}
	t.Fatal("no SOS found in encoded jpeg")
	return nil
}

// TestStripKeepsAPP0Verbatim ensures a non-stripped APPn (APP0/JFIF) is copied
// through unchanged while APP1 is removed.
func TestStripKeepsAPP0Verbatim(t *testing.T) {
	tail := minimalScanTail(t)
	app0 := seg(0xE0, []byte("JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")) // JFIF
	app1 := seg(0xE1, []byte("Exif\x00\x00GPSDATA"))

	stream := []byte{0xFF, 0xD8} // SOI
	stream = append(stream, app0...)
	stream = append(stream, app1...)
	stream = append(stream, tail...)

	out, err := exif.Strip(stream)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if !testutil.HasSegment(out, 0xE0) {
		t.Error("APP0/JFIF was dropped but should be kept verbatim")
	}
	if testutil.HasSegment(out, 0xE1) {
		t.Error("APP1 survived")
	}
	if !bytes.Contains(out, []byte("JFIF")) {
		t.Error("JFIF payload missing from output")
	}
	if bytes.Contains(out, []byte("GPSDATA")) {
		t.Error("EXIF GPS payload leaked")
	}
}

// TestStripStandaloneMarker exercises the no-length (standalone) marker path:
// a TEM (0x01) marker before SOS must be copied verbatim.
func TestStripStandaloneMarker(t *testing.T) {
	tail := minimalScanTail(t)
	stream := []byte{0xFF, 0xD8}                             // SOI
	stream = append(stream, 0xFF, 0x01)                      // TEM standalone marker
	stream = append(stream, seg(0xFE, []byte("comment"))...) // COM to strip
	stream = append(stream, tail...)

	out, err := exif.Strip(stream)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if testutil.HasSegment(out, 0xFE) {
		t.Error("COM survived")
	}
	// The TEM marker (FF01) should remain in the output before the scan.
	if !bytes.Contains(out, []byte{0xFF, 0x01}) {
		t.Error("standalone TEM marker was dropped")
	}
}

// TestStripSecondSOIRejected ensures a malformed stream with a second SOI is
// rejected (fail-closed).
func TestStripSecondSOIRejected(t *testing.T) {
	stream := []byte{0xFF, 0xD8, 0xFF, 0xD8} // SOI, then a stray second SOI
	if _, err := exif.Strip(stream); err == nil {
		t.Fatal("expected error for second SOI")
	}
}

// TestStripBadSegmentLength rejects a segment whose declared length is < 2.
func TestStripBadSegmentLength(t *testing.T) {
	stream := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x01} // APP1 length=1 (<2)
	if _, err := exif.Strip(stream); err == nil {
		t.Fatal("expected error for too-small segment length")
	}
}

// TestStripNonFFAfterSOI rejects a stream where a marker prefix is not 0xFF.
func TestStripNonFFAfterSOI(t *testing.T) {
	stream := []byte{0xFF, 0xD8, 0x12, 0x34}
	if _, err := exif.Strip(stream); err == nil {
		t.Fatal("expected error for missing 0xFF marker prefix")
	}
}
