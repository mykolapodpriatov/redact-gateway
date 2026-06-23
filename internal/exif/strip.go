// Package exif strips privacy-sensitive metadata segments from raw JPEG bytes
// without decoding the image. It removes APP1 (EXIF/GPS), APP13 (IPTC), and
// COM (comment) segments, including any thumbnail embedded inside an APP1 EXIF
// block, then re-serializes the remaining segments verbatim.
//
// This operates on RAW BYTES on purpose: Go's image decoders discard EXIF on
// decode, so metadata stripping for a forwarded (pass-route) image must happen
// before any decode. Redact/blur routes re-encode the image, which already
// drops all of this metadata; this package is for the forward-original path.
package exif

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNotJPEG indicates the input did not begin with a JPEG SOI marker, so it
// is not a JPEG segment stream this package can process.
var ErrNotJPEG = errors.New("exif: not a JPEG (missing SOI marker)")

// ErrMalformed indicates the JPEG segment stream is structurally invalid (a
// truncated segment, a bad length, or a missing terminator). Callers treat a
// strip error as fail-closed: forwarding metadata-bearing bytes that could not
// be parsed would risk a privacy leak.
var ErrMalformed = errors.New("exif: malformed JPEG segment stream")

const (
	markerSOI   = 0xD8 // Start of image (no length).
	markerEOI   = 0xD9 // End of image (no length).
	markerSOS   = 0xDA // Start of scan; entropy data follows to EOI.
	markerAPP1  = 0xE1 // EXIF / GPS.
	markerAPP13 = 0xED // IPTC / Photoshop.
	markerCOM   = 0xFE // Comment.
)

// isStripped reports whether a marker byte (the byte after 0xFF) names a
// segment this package removes.
func isStripped(marker byte) bool {
	return marker == markerAPP1 || marker == markerAPP13 || marker == markerCOM
}

// hasLength reports whether a marker carries a 2-byte length field. SOI, EOI,
// the restart markers RST0-7 (0xD0-0xD7), and TEM (0x01) are standalone.
func hasLength(marker byte) bool {
	switch {
	case marker == markerSOI, marker == markerEOI, marker == 0x01:
		return false
	case marker >= 0xD0 && marker <= 0xD7: // RSTn
		return false
	default:
		return true
	}
}

// Strip parses the JPEG segment stream in data and returns a copy with all
// APP1 (EXIF/GPS), APP13 (IPTC), and COM segments removed (the embedded EXIF
// thumbnail lives inside APP1 and is removed with it). All other segments —
// including the SOF, DQT, DHT, the SOS header, and the entropy-coded scan data
// through EOI — are copied verbatim, so the output still decodes to the same
// pixels. A structurally invalid input returns ErrMalformed (fail-closed).
func Strip(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0xFF || data[1] != markerSOI {
		return nil, ErrNotJPEG
	}

	out := make([]byte, 0, len(data))
	// Emit SOI.
	out = append(out, 0xFF, markerSOI)
	i := 2

	for {
		if i >= len(data) {
			return nil, fmt.Errorf("%w: unexpected end before SOS/EOI", ErrMalformed)
		}
		// Every marker begins with 0xFF. There may be fill 0xFF bytes between
		// segments; skip them.
		if data[i] != 0xFF {
			return nil, fmt.Errorf("%w: expected marker prefix 0xFF at offset %d", ErrMalformed, i)
		}
		for i < len(data) && data[i] == 0xFF {
			i++
		}
		if i >= len(data) {
			return nil, fmt.Errorf("%w: truncated marker", ErrMalformed)
		}
		marker := data[i]
		markerStart := i - 1 // position of the 0xFF immediately before marker
		i++

		if marker == markerSOI {
			return nil, fmt.Errorf("%w: unexpected second SOI", ErrMalformed)
		}
		if marker == markerEOI {
			out = append(out, 0xFF, markerEOI)
			return out, nil
		}

		if !hasLength(marker) {
			// Standalone marker before scan data: copy it verbatim.
			out = append(out, 0xFF, marker)
			continue
		}

		// Read the 2-byte big-endian segment length (includes the length
		// bytes themselves).
		if i+2 > len(data) {
			return nil, fmt.Errorf("%w: truncated length field", ErrMalformed)
		}
		segLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		if segLen < 2 {
			return nil, fmt.Errorf("%w: segment length %d too small", ErrMalformed, segLen)
		}
		segDataEnd := i + segLen // end of the segment payload (exclusive)
		if segDataEnd > len(data) {
			return nil, fmt.Errorf("%w: segment overruns buffer", ErrMalformed)
		}

		if marker == markerSOS {
			// Start of scan: copy the SOS header verbatim, then everything
			// from the end of the SOS header to the end of the input (the
			// entropy-coded data and the trailing EOI) verbatim. Scanning
			// entropy data marker-by-marker is unnecessary and error-prone.
			out = append(out, data[markerStart:segDataEnd]...)
			out = append(out, data[segDataEnd:]...)
			if !endsWithEOI(out) {
				return nil, fmt.Errorf("%w: scan data not terminated by EOI", ErrMalformed)
			}
			return out, nil
		}

		if isStripped(marker) {
			// Drop the entire segment (marker + length + payload).
			i = segDataEnd
			continue
		}

		// Keep this segment verbatim.
		out = append(out, data[markerStart:segDataEnd]...)
		i = segDataEnd
	}
}

func endsWithEOI(b []byte) bool {
	return len(b) >= 2 && b[len(b)-2] == 0xFF && b[len(b)-1] == markerEOI
}
