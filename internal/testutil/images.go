// Package testutil builds deterministic in-memory images and JPEG byte
// streams for the offline test suite. Nothing here touches the network, a real
// clock, or any ML model. It is imported only by tests.
package testutil

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
)

// SolidRGBA returns a w x h RGBA image filled with c. A nil c defaults to
// opaque black so callers cannot accidentally panic on a nil uniform.
func SolidRGBA(w, h int, c color.Color) *image.RGBA {
	if c == nil {
		c = color.RGBA{A: 255}
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), image.NewUniform(c), image.Point{}, draw.Src)
	return img
}

// WithRect returns a copy of src with rect filled by c (used to paint a marker
// region for RegionMarkerDetector tests).
func WithRect(src image.Image, rect image.Rectangle, c color.Color) *image.RGBA {
	out := image.NewRGBA(src.Bounds())
	draw.Draw(out, src.Bounds(), src, src.Bounds().Min, draw.Src)
	draw.Draw(out, rect.Intersect(src.Bounds()), image.NewUniform(c), image.Point{}, draw.Src)
	return out
}

// EncodePNG encodes img to PNG bytes.
func EncodePNG(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// EncodeJPEG encodes img to JPEG bytes at the given quality.
func EncodeJPEG(img image.Image, quality int) []byte {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// MarkerImagePNG returns a PNG of a solid background with a single filled
// rectangle in markerColor at rect — the canonical RegionMarkerDetector input.
func MarkerImagePNG(w, h int, bg, markerColor color.Color, rect image.Rectangle) []byte {
	base := SolidRGBA(w, h, bg)
	withRect := WithRect(base, rect, markerColor)
	return EncodePNG(withRect)
}

// pngSignatureLen is the length of the 8-byte PNG magic signature.
const pngSignatureLen = 8

// makePNGChunk builds a [length(4)][type(4)][data][crc(4)] PNG chunk with a
// correct CRC-32 over the type and data bytes.
func makePNGChunk(ctype string, data []byte) []byte {
	chunk := make([]byte, 0, 12+len(data))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	chunk = append(chunk, lenBuf[:]...)
	chunk = append(chunk, ctype...)
	chunk = append(chunk, data...)
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte(ctype))
	_, _ = crc.Write(data)
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc.Sum32())
	chunk = append(chunk, crcBuf[:]...)
	return chunk
}

// PNGWithMetadata encodes a small PNG and splices an eXIf and a tEXt chunk
// immediately after the IHDR chunk (a valid place for ancillary chunks). The
// eXIf payload carries a recognizable GPS marker and the tEXt a keyword/value;
// both are present so a stripper test can assert they are removed while the
// image still decodes. The result is a structurally valid PNG.
func PNGWithMetadata() []byte {
	base := EncodePNG(SolidRGBA(8, 8, color.RGBA{R: 10, G: 20, B: 30, A: 255}))
	// base layout: 8-byte signature, then IHDR chunk (length 13 → 25 bytes:
	// 4 len + 4 type + 13 data + 4 crc), then the rest (IDAT.., IEND).
	const ihdrChunkLen = 4 + 4 + 13 + 4
	splitAt := pngSignatureLen + ihdrChunkLen

	exifPayload := append([]byte("Exif\x00\x00"), []byte("FAKE-PNG-GPS:51.5,-0.12")...)
	textPayload := append([]byte("Comment\x00"), []byte("PNG-TEXT-SECRET")...)

	out := make([]byte, 0, len(base)+64)
	out = append(out, base[:splitAt]...)
	out = append(out, makePNGChunk("eXIf", exifPayload)...)
	out = append(out, makePNGChunk("tEXt", textPayload)...)
	out = append(out, base[splitAt:]...)
	return out
}

// HasPNGChunk reports whether the PNG byte stream contains a chunk of the given
// type, walking the chunk list. It is the PNG analogue of HasSegment.
func HasPNGChunk(data []byte, ctype string) bool {
	if len(data) < pngSignatureLen {
		return false
	}
	i := pngSignatureLen
	for i+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[i : i+4]))
		t := string(data[i+4 : i+8])
		if t == ctype {
			return true
		}
		next := i + 8 + length + 4
		if next <= i || next > len(data) {
			return false
		}
		i = next
	}
	return false
}

// EncodeGIF encodes img to GIF bytes (an image format the gateway cannot strip
// metadata from), for fail-closed tests on a pass+strip_metadata route.
func EncodeGIF(img image.Image) []byte {
	var buf bytes.Buffer
	if err := gif.Encode(&buf, img, nil); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
