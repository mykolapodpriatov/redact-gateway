package imageproc

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
)

// EncodeOptions configures Encode.
type EncodeOptions struct {
	// JPEGQuality is the quality (1-100) used when re-encoding JPEG. Values
	// outside that range fall back to a sensible default (90).
	JPEGQuality int
}

// Encode re-encodes img in the given format. Re-encoding produces a fresh
// image stream with NO EXIF, IPTC, COM segments, or embedded thumbnail, so a
// masked image cannot leak original pixels via metadata. A non-nil error here
// is fail-closed by the pipeline (the upload is blocked rather than forwarded).
func Encode(img image.Image, format Format, opts EncodeOptions) ([]byte, error) {
	if img == nil {
		return nil, fmt.Errorf("imageproc: encode: nil image")
	}
	b := img.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 {
		return nil, fmt.Errorf("imageproc: encode: empty image bounds")
	}

	var buf bytes.Buffer
	switch format {
	case FormatJPEG:
		q := opts.JPEGQuality
		if q < 1 || q > 100 {
			q = 90
		}
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
			return nil, fmt.Errorf("imageproc: encode jpeg: %w", err)
		}
	case FormatPNG:
		enc := png.Encoder{CompressionLevel: png.DefaultCompression}
		if err := enc.Encode(&buf, img); err != nil {
			return nil, fmt.Errorf("imageproc: encode png: %w", err)
		}
	default:
		return nil, fmt.Errorf("imageproc: encode: %w", ErrUnsupportedFormat)
	}
	return buf.Bytes(), nil
}
