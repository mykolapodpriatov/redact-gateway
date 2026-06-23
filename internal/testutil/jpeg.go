package testutil

import (
	"encoding/binary"
	"image"
	"image/color"
)

// MetaOptions controls which metadata segments JPEGWithMetadata injects.
type MetaOptions struct {
	// EXIF injects an APP1 "Exif\x00\x00..." segment (optionally containing a
	// fake embedded thumbnail marker).
	EXIF bool
	// IPTC injects an APP13 "Photoshop 3.0\x00..." segment.
	IPTC bool
	// COM injects a comment segment.
	COM bool
	// ThumbnailMarker, when non-empty, is embedded inside the APP1 payload so a
	// test can assert it was removed along with the EXIF block.
	ThumbnailMarker []byte
}

// JPEGWithMetadata encodes a small image to JPEG and splices the requested
// metadata segments (APP1/APP13/COM) immediately after the SOI marker — the
// position real cameras place them. The result is a structurally valid JPEG.
func JPEGWithMetadata(opts MetaOptions) []byte {
	base := EncodeJPEG(SolidRGBA(8, 8, color.RGBA{R: 10, G: 20, B: 30, A: 255}), 90)
	// base starts with FFD8 (SOI). Insert segments right after it.
	var segs []byte
	if opts.EXIF {
		payload := append([]byte("Exif\x00\x00"), []byte("FAKEEXIFGPS:51.5,-0.12")...)
		if len(opts.ThumbnailMarker) > 0 {
			payload = append(payload, opts.ThumbnailMarker...)
		}
		segs = append(segs, makeSegment(0xE1, payload)...)
	}
	if opts.IPTC {
		payload := append([]byte("Photoshop 3.0\x00"), []byte("8BIM\x04\x04IPTCDATA")...)
		segs = append(segs, makeSegment(0xED, payload)...)
	}
	if opts.COM {
		segs = append(segs, makeSegment(0xFE, []byte("a secret comment"))...)
	}

	out := make([]byte, 0, len(base)+len(segs))
	out = append(out, base[:2]...) // SOI
	out = append(out, segs...)
	out = append(out, base[2:]...)
	return out
}

// makeSegment builds an FF<marker><len><payload> JPEG segment. len is
// big-endian and includes the two length bytes.
func makeSegment(marker byte, payload []byte) []byte {
	segLen := len(payload) + 2
	seg := make([]byte, 0, segLen+2)
	seg = append(seg, 0xFF, marker)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(segLen))
	seg = append(seg, l[:]...)
	seg = append(seg, payload...)
	return seg
}

// HasSegment reports whether the JPEG byte stream contains a segment with the
// given marker (the byte after 0xFF), scanning segment-by-segment up to SOS.
func HasSegment(data []byte, marker byte) bool {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return false
	}
	i := 2
	for i+1 < len(data) {
		if data[i] != 0xFF {
			return false
		}
		for i < len(data) && data[i] == 0xFF {
			i++
		}
		if i >= len(data) {
			return false
		}
		m := data[i]
		i++
		if m == marker {
			return true
		}
		if m == 0xD9 { // EOI
			return false
		}
		if m == 0xDA { // SOS: metadata segments do not appear past here
			return false
		}
		if m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
			continue // standalone, no length
		}
		if i+2 > len(data) {
			return false
		}
		segLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		if segLen < 2 {
			return false
		}
		i += segLen
	}
	return false
}

// JPEGBomb returns a JPEG whose SOF dimensions are patched to width x height
// (which may be enormous) without actually allocating that many pixels. Its
// DecodeConfig reports the patched dimensions, so the decompression-bomb guard
// can reject it before any full decode. The pixel data is the tiny original,
// so a full decode would fail — which is exactly why the guard must run first.
func JPEGBomb(width, height int) []byte {
	data := EncodeJPEG(SolidRGBA(8, 8, color.RGBA{A: 255}), 90)
	patchSOF(data, width, height)
	return data
}

// patchSOF rewrites the height and width fields of the first SOF0/SOF2 marker
// in a JPEG stream in place.
func patchSOF(data []byte, width, height int) {
	i := 2
	for i+1 < len(data) {
		if data[i] != 0xFF {
			return
		}
		for i < len(data) && data[i] == 0xFF {
			i++
		}
		if i >= len(data) {
			return
		}
		m := data[i]
		i++
		if m == 0xD9 || m == 0xDA {
			return
		}
		if m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
			continue
		}
		if i+2 > len(data) {
			return
		}
		segLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		// SOF0=C0, SOF1=C1, SOF2=C2: payload is [precision(1)][height(2)][width(2)]...
		if m == 0xC0 || m == 0xC1 || m == 0xC2 {
			off := i + 2 + 1 // skip length(2) + precision(1)
			if off+4 <= len(data) {
				binary.BigEndian.PutUint16(data[off:off+2], uint16(height))
				binary.BigEndian.PutUint16(data[off+2:off+4], uint16(width))
			}
			return
		}
		i += segLen
	}
}

// TruncatedJPEG returns a JPEG truncated partway through the entropy-coded
// scan data: the header (and thus DecodeConfig dimensions) are intact, but the
// pixel data is incomplete, exercising the post-decode bounds/truncation guard.
func TruncatedJPEG() []byte {
	data := EncodeJPEG(gradient(64, 64), 90)
	// Find SOS, then cut a few bytes into the scan data.
	i := 2
	for i+1 < len(data) {
		if data[i] != 0xFF {
			break
		}
		for i < len(data) && data[i] == 0xFF {
			i++
		}
		if i >= len(data) {
			break
		}
		m := data[i]
		i++
		if m == 0xDA { // SOS
			if i+2 > len(data) {
				break
			}
			segLen := int(binary.BigEndian.Uint16(data[i : i+2]))
			scanStart := i + segLen
			cut := scanStart + 8
			if cut < len(data) {
				return append([]byte(nil), data[:cut]...)
			}
			break
		}
		if m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
			continue
		}
		if i+2 > len(data) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		i += segLen
	}
	// Fallback: chop the last 16 bytes.
	if len(data) > 16 {
		return append([]byte(nil), data[:len(data)-16]...)
	}
	return data
}

// gradient builds a w x h image with a varying pattern so JPEG produces real
// entropy-coded data (a solid color compresses to almost nothing).
func gradient(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{
				R: uint8((x * 255) / w),
				G: uint8((y * 255) / h),
				B: uint8((x + y) % 256),
				A: 255,
			})
		}
	}
	return img
}
