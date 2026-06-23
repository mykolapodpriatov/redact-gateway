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

// pngChunk builds a [length(4)][type(4)][data][crc(4)] chunk with a correct
// CRC-32 over the type and data bytes (mirrors the chunk framing the gateway
// parses).
func pngChunk(ctype string, data []byte) []byte {
	out := make([]byte, 0, 12+len(data))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	out = append(out, lenBuf[:]...)
	out = append(out, ctype...)
	out = append(out, data...)
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte(ctype))
	_, _ = crc.Write(data)
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc.Sum32())
	out = append(out, crcBuf[:]...)
	return out
}

// apngWithMetadata builds a structurally valid animated PNG (APNG) that carries
// the animation chunks acTL/fcTL/fdAT plus the metadata chunks tEXt and eXIf.
// The base PNG supplies the signature, IHDR, IDAT, and IEND; the animation and
// metadata chunks are spliced between IHDR and IEND. Go's image/png decoder
// ignores the (ancillary) APNG chunks, so the result still decodes as a static
// PNG — which is exactly the fidelity the gateway must not silently impose.
func apngWithMetadata(t *testing.T) []byte {
	t.Helper()

	base := testutil.EncodePNG(testutil.SolidRGBA(8, 8, nil))
	const sigLen = 8
	const ihdrChunkLen = 4 + 4 + 13 + 4 // len + type + 13 data + crc
	splitAfterIHDR := sigLen + ihdrChunkLen

	// Split the base into [signature+IHDR] and [IDAT..+IEND].
	head := base[:splitAfterIHDR]
	tail := base[splitAfterIHDR:]

	// acTL: num_frames(4) + num_plays(4).
	acTL := make([]byte, 8)
	binary.BigEndian.PutUint32(acTL[0:4], 2) // 2 frames
	binary.BigEndian.PutUint32(acTL[4:8], 0) // loop forever

	// fcTL frame-control payload (26 bytes): sequence_number(4), width(4),
	// height(4), x_offset(4), y_offset(4), delay_num(2), delay_den(2),
	// dispose_op(1), blend_op(1).
	mkFcTL := func(seq uint32) []byte {
		b := make([]byte, 26)
		binary.BigEndian.PutUint32(b[0:4], seq)
		binary.BigEndian.PutUint32(b[4:8], 8)   // width
		binary.BigEndian.PutUint32(b[8:12], 8)  // height
		binary.BigEndian.PutUint32(b[12:16], 0) // x_offset
		binary.BigEndian.PutUint32(b[16:20], 0) // y_offset
		binary.BigEndian.PutUint16(b[20:22], 1) // delay_num
		binary.BigEndian.PutUint16(b[22:24], 1) // delay_den
		b[24] = 0                               // dispose_op
		b[25] = 0                               // blend_op
		return b
	}

	// fdAT: sequence_number(4) + frame data (reuses an arbitrary deflate-ish
	// blob; the stdlib decoder never parses fdAT, so its exact bytes are
	// irrelevant to decodability).
	fdAT := append([]byte{0, 0, 0, 3}, []byte("\x00\x01\x02")...)

	textPayload := append([]byte("Comment\x00"), []byte("APNG-TEXT-SECRET")...)
	exifPayload := append([]byte("Exif\x00\x00"), []byte("APNG-FAKE-GPS:51.5,-0.12")...)

	out := make([]byte, 0, len(base)+256)
	out = append(out, head...)
	out = append(out, pngChunk("acTL", acTL)...)
	out = append(out, pngChunk("fcTL", mkFcTL(0))...)
	out = append(out, pngChunk("tEXt", textPayload)...) // metadata, must be dropped
	out = append(out, pngChunk("fcTL", mkFcTL(1))...)
	out = append(out, pngChunk("fdAT", fdAT)...)
	out = append(out, pngChunk("eXIf", exifPayload)...) // metadata, must be dropped
	out = append(out, tail...)
	return out
}

// TestStripPNGPreservesAPNGAnimationChunks is a regression test for an APNG
// fidelity bug: the rendering-chunk allowlist must preserve the animation
// chunks acTL/fcTL/fdAT (so an animated PNG forwarded on a pass +
// strip_metadata route stays animated rather than collapsing to its static
// first frame) while still dropping the metadata chunks tEXt and eXIf.
func TestStripPNGPreservesAPNGAnimationChunks(t *testing.T) {
	in := apngWithMetadata(t)

	// Sanity: the input actually carries the animation and metadata chunks and
	// their recognizable payloads.
	for _, c := range []string{"acTL", "fcTL", "fdAT", "tEXt", "eXIf"} {
		if !testutil.HasPNGChunk(in, c) {
			t.Fatalf("test input is missing the %q chunk", c)
		}
	}
	if !bytes.Contains(in, []byte("APNG-TEXT-SECRET")) || !bytes.Contains(in, []byte("APNG-FAKE-GPS")) {
		t.Fatal("test input is missing the expected metadata payloads")
	}

	out, err := exif.StripPNG(in)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}

	// Animation chunks must survive: dropping them would silently de-animate the
	// image, altering it beyond metadata removal.
	for _, c := range []string{"acTL", "fcTL", "fdAT"} {
		if !testutil.HasPNGChunk(out, c) {
			t.Errorf("APNG animation chunk %q was dropped; animation is lost", c)
		}
	}

	// Metadata chunks (and their payloads) must still be removed.
	if testutil.HasPNGChunk(out, "tEXt") {
		t.Error("tEXt metadata chunk survived stripping")
	}
	if testutil.HasPNGChunk(out, "eXIf") {
		t.Error("eXIf metadata chunk survived stripping")
	}
	if bytes.Contains(out, []byte("APNG-TEXT-SECRET")) {
		t.Error("tEXt payload survived stripping")
	}
	if bytes.Contains(out, []byte("APNG-FAKE-GPS")) {
		t.Error("eXIf GPS payload survived stripping")
	}

	// Critical chunks must remain and the output must still decode as a valid
	// PNG.
	for _, c := range []string{"IHDR", "IDAT", "IEND"} {
		if !testutil.HasPNGChunk(out, c) {
			t.Fatalf("critical chunk %q was dropped", c)
		}
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("stripped APNG output no longer decodes: %v", err)
	}
	if img.Bounds().Dx() != 8 || img.Bounds().Dy() != 8 {
		t.Fatalf("decoded bounds changed: %v", img.Bounds())
	}
}
