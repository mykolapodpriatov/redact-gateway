package exif

import (
	"encoding/binary"
	"fmt"
)

// ErrNotPNG indicates the input did not begin with the 8-byte PNG signature,
// so it is not a PNG chunk stream this package can process.
var ErrNotPNG = fmt.Errorf("exif: not a PNG (missing signature)")

// ErrMalformedPNG indicates the PNG chunk stream is structurally invalid (a
// truncated chunk, a length that overruns the buffer, or a missing IEND).
// Callers treat a strip error as fail-closed: forwarding metadata-bearing
// bytes that could not be parsed would risk a privacy leak.
var ErrMalformedPNG = fmt.Errorf("exif: malformed PNG chunk stream")

// pngSignature is the 8-byte magic that begins every PNG file.
var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// keptPNGChunks is the allowlist of chunk types preserved by StripPNG. It
// covers the critical chunks (IHDR, PLTE, IDAT, IEND), the ancillary chunks
// that affect rendering (color space, transparency, gamma, physical
// dimensions, significant bits, palette histogram/suggestion), and the APNG
// animation chunks (acTL, fcTL, fdAT) that carry the animation control and
// per-frame pixel data. Every other chunk — notably the metadata carriers
// eXIf, tEXt, iTXt, zTXt, and tIME — is dropped. Using an allowlist (rather
// than a denylist) is deliberate: it fail-safes against unknown/future
// metadata chunk types, which are dropped rather than forwarded.
var keptPNGChunks = map[string]bool{
	// Critical chunks (decode would fail without them).
	"IHDR": true,
	"PLTE": true,
	"IDAT": true,
	"IEND": true,
	// Rendering-affecting ancillary chunks (color, transparency, gamma, etc.).
	"tRNS": true,
	"cHRM": true,
	"gAMA": true,
	"iCCP": true,
	"sBIT": true,
	"sRGB": true,
	"bKGD": true,
	"hIST": true,
	"pHYs": true,
	"sPLT": true,
	// APNG animation chunks. acTL is the animation control; fcTL is the
	// per-frame control; fdAT carries frame pixel data (analogous to IDAT, not
	// a metadata vector). Preserving these keeps an animated PNG animated
	// instead of silently collapsing it to its static first frame, without
	// weakening the metadata-stripping guarantee.
	"acTL": true,
	"fcTL": true,
	"fdAT": true,
}

// StripPNG parses the PNG chunk stream in data and returns a copy that retains
// only the rendering-relevant chunks (see keptPNGChunks), dropping every
// metadata chunk — eXIf (which can carry GPS), tEXt/iTXt/zTXt (textual and XMP
// metadata), tIME, and any other unrecognized chunk. The 8-byte signature and
// the kept chunks (including their CRCs) are copied verbatim, so the output is
// a valid, decodable PNG with the same pixels. A structurally invalid input
// returns ErrMalformedPNG (fail-closed); a non-PNG input returns ErrNotPNG.
func StripPNG(data []byte) ([]byte, error) {
	if len(data) < len(pngSignature) || string(data[:len(pngSignature)]) != string(pngSignature) {
		return nil, ErrNotPNG
	}

	out := make([]byte, 0, len(data))
	out = append(out, data[:len(pngSignature)]...)
	i := len(pngSignature)

	sawIEND := false
	for i < len(data) {
		// Each chunk is [length(4)][type(4)][data(length)][CRC(4)].
		if i+8 > len(data) {
			return nil, fmt.Errorf("%w: truncated chunk header at offset %d", ErrMalformedPNG, i)
		}
		length := binary.BigEndian.Uint32(data[i : i+4])
		ctype := string(data[i+4 : i+8])
		// chunkEnd is the exclusive end of the full chunk (header+data+CRC).
		// Guard the addition against uint32/int overflow on 32-bit platforms by
		// computing in int64.
		chunkEnd64 := int64(i) + 8 + int64(length) + 4
		if chunkEnd64 > int64(len(data)) {
			return nil, fmt.Errorf("%w: chunk %q overruns buffer", ErrMalformedPNG, ctype)
		}
		chunkEnd := int(chunkEnd64)

		if keptPNGChunks[ctype] {
			out = append(out, data[i:chunkEnd]...)
		}
		if ctype == "IEND" {
			sawIEND = true
			i = chunkEnd
			break
		}
		i = chunkEnd
	}
	if !sawIEND {
		return nil, fmt.Errorf("%w: missing IEND chunk", ErrMalformedPNG)
	}
	return out, nil
}
