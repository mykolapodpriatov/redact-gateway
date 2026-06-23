// Package imageproc decodes, masks, and re-encodes raster images (JPEG/PNG)
// for the redaction pipeline. Every operation is pure and deterministic so
// the security-critical core is reproducibly testable. The package enforces a
// decoded-pixel cap before allocating any pixel buffer (a decompression-bomb
// guard) and validates post-decode bounds to catch truncated inputs.
package imageproc

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/gif" // register GIF so DetectFormat can name it for clear blocking
	"image/jpeg"
	"image/png"
)

// Format identifies a supported raster encoding.
type Format string

const (
	// FormatJPEG is the JPEG encoding.
	FormatJPEG Format = "jpeg"
	// FormatPNG is the PNG encoding.
	FormatPNG Format = "png"
)

// Errors returned by the decode path. Callers (the pipeline) translate these
// into fail-closed blocks.
var (
	// ErrUnsupportedFormat means the bytes sniff as an image but in a format
	// this build cannot mask (for example GIF or WebP). On a redact route the
	// pipeline MUST block rather than forward such input.
	ErrUnsupportedFormat = errors.New("imageproc: unsupported image format")
	// ErrTooManyPixels means the declared width*height exceeds the configured
	// MaxPixels cap (decompression-bomb guard) and decoding was refused before
	// allocating the pixel buffer.
	ErrTooManyPixels = errors.New("imageproc: image exceeds max pixels")
	// ErrInvalidBounds means the decoded image had zero or mismatched bounds,
	// which can indicate a truncated/partial decode.
	ErrInvalidBounds = errors.New("imageproc: invalid or truncated image bounds")
)

// DecodedImage is a decoded image together with the format it came in, so the
// pipeline can re-encode in the original format.
type DecodedImage struct {
	Image  image.Image
	Format Format
}

// DetectFormat sniffs the leading bytes and returns the raster Format. For an
// image in a format this build cannot mask it returns ErrUnsupportedFormat; for
// non-image bytes it returns ("", ErrUnsupportedFormat) as well — callers
// decide whether non-image data is allowed (text parts pass through; redact
// routes block). It never consumes more than a short prefix.
func DetectFormat(data []byte) (Format, error) {
	switch {
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		return FormatJPEG, nil
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		return FormatPNG, nil
	default:
		return "", ErrUnsupportedFormat
	}
}

// SniffIsImage reports whether the leading bytes look like ANY image format
// (including ones this build cannot mask, such as GIF/WebP). It is used for
// classification: an item that is an image but in an unsupported format must
// be blocked on a redact route, whereas a genuinely non-image item passes
// through. Classification is by magic bytes, never by Content-Type.
func SniffIsImage(data []byte) bool {
	switch {
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF: // JPEG
		return true
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n": // PNG
		return true
	case len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a"): // GIF
		return true
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP": // WebP
		return true
	case len(data) >= 2 && data[0] == 0x42 && data[1] == 0x4D: // BMP
		return true
	case len(data) >= 4 && (string(data[:4]) == "II*\x00" || string(data[:4]) == "MM\x00*"): // TIFF
		return true
	default:
		return false
	}
}

// Decode reads dimensions via DecodeConfig FIRST and refuses width*height >
// maxPixels (decompression-bomb guard) before allocating the pixel buffer,
// then fully decodes JPEG/PNG and validates the resulting bounds against the
// config to catch truncated/partial decodes (Go's image/jpeg can return a
// non-nil image with a nil error on a partial input).
//
// maxPixels <= 0 disables the cap (NOT recommended outside tests).
func Decode(data []byte, maxPixels int64) (*DecodedImage, error) {
	format, err := DetectFormat(data)
	if err != nil {
		return nil, err
	}

	cfg, cfgFormat, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		// Sniffed as supported but header won't parse: treat as undecodable.
		return nil, fmt.Errorf("imageproc: decode config: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, ErrInvalidBounds
	}
	if maxPixels > 0 {
		// Compute width*height with overflow protection.
		px := int64(cfg.Width) * int64(cfg.Height)
		if cfg.Width != 0 && px/int64(cfg.Width) != int64(cfg.Height) {
			// Multiplication overflowed int64: definitely over the cap.
			return nil, ErrTooManyPixels
		}
		if px > maxPixels {
			return nil, ErrTooManyPixels
		}
	}

	var img image.Image
	switch format {
	case FormatJPEG:
		img, err = jpeg.Decode(bytes.NewReader(data))
	case FormatPNG:
		img, err = png.Decode(bytes.NewReader(data))
	default:
		return nil, ErrUnsupportedFormat
	}
	if err != nil {
		return nil, fmt.Errorf("imageproc: decode: %w", err)
	}
	if img == nil {
		return nil, ErrInvalidBounds
	}

	// Post-decode bounds validation: catch truncated decodes that returned a
	// non-nil image whose dimensions disagree with the declared header.
	b := img.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 {
		return nil, ErrInvalidBounds
	}
	if cfgFormat == string(FormatJPEG) || cfgFormat == string(FormatPNG) {
		if b.Dx() != cfg.Width || b.Dy() != cfg.Height {
			return nil, ErrInvalidBounds
		}
	}

	return &DecodedImage{Image: img, Format: format}, nil
}
