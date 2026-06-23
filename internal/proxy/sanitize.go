package proxy

import (
	"context"
	"errors"
	"fmt"
	"image"
	"sort"

	"redact-gateway/internal/audit"
	"redact-gateway/internal/detect"
	"redact-gateway/internal/exif"
	"redact-gateway/internal/imageproc"
	"redact-gateway/internal/policy"
)

// EncodeFunc re-encodes a decoded image. It defaults to imageproc.Encode but
// is injectable so tests can force a re-encode failure (a fail-closed path).
type EncodeFunc func(img image.Image, format imageproc.Format, opts imageproc.EncodeOptions) ([]byte, error)

// blockError marks a fail-closed decision: the upload must be blocked and the
// origin must receive nothing. Its message is a short status string that is
// safe to return to the client (it never contains request or image bytes).
type blockError struct {
	status string
}

func (e *blockError) Error() string { return e.status }

// newBlock builds a blockError with a short, byte-free status string.
func newBlock(status string) *blockError { return &blockError{status: status} }

// IsBlock reports whether err is a fail-closed block decision.
func IsBlock(err error) bool {
	var b *blockError
	return errors.As(err, &b)
}

// dropError marks a policy "drop": the whole upload is rejected. Like
// blockError its message is byte-free.
type dropError struct{ status string }

func (e *dropError) Error() string { return e.status }

// IsDrop reports whether err is a policy drop decision.
func IsDrop(err error) bool {
	var d *dropError
	return errors.As(err, &d)
}

// Sanitizer turns one input item (image bytes) into sanitized output bytes per
// a route's policy, applying the fail-closed rules and writing an audit entry.
// It is safe for concurrent use (its dependencies are).
type Sanitizer struct {
	// Registry resolves detector names (from a route) to Detector instances.
	Registry map[string]detect.Detector
	// Audit logs bbox/category/sanitized-hash entries (never pixels).
	Audit *audit.Logger
	// Encode re-encodes masked images; defaults to imageproc.Encode.
	Encode EncodeFunc
	// MaxPixels caps decoded dimensions (decompression-bomb guard).
	MaxPixels int64
	// JPEGQuality and BlurRadius configure masking output.
	JPEGQuality int
	BlurRadius  int
}

// ItemResult is the outcome of sanitizing one item.
type ItemResult struct {
	// Output is the bytes to forward (sanitized image, metadata-stripped
	// original, or the verbatim original for a non-image pass-through).
	Output []byte
	// Audited indicates an audit entry was written for this item.
	Audited bool
}

// SanitizeImage processes one item's bytes under route. data has already been
// read under the per-part size cap. The boolean isImage is the magic-byte
// classification result for this item (an image in an UNSUPPORTED format still
// counts as isImage=true so it is blocked on a redact route, never passed).
//
// Fail-closed contract: on a masking route, ANY failure to fully sanitize
// (undecodable, unsupported format, decompression bomb, truncated, mask, or
// re-encode failure, or a detector error) returns a blockError unless the
// route opts into fail-open. On a pass route a strip_metadata error is also a
// blockError unless fail-open.
func (s *Sanitizer) SanitizeImage(ctx context.Context, route policy.Route, data []byte, isImage bool) (*ItemResult, error) {
	switch route.Action {
	case policy.ActionDrop:
		return nil, &dropError{status: "upload rejected by policy"}
	case policy.ActionPass:
		return s.handlePass(route, data, isImage)
	case policy.ActionRedact, policy.ActionBlur:
		return s.handleMask(ctx, route, data, isImage)
	default:
		// Unknown action: fail closed.
		return s.failClosed(route, data, "unsupported policy action")
	}
}

// handlePass forwards the item unmasked. If it is an image and metadata
// stripping is enabled, the raw bytes are stripped of metadata first: a JPEG
// has its APP1/APP13/COM segments removed; a PNG has its eXIf/tEXt/iTXt/zTXt/
// tIME (and other ancillary metadata) chunks removed. A strip error is
// fail-closed (forwarding metadata-bearing bytes is a leak). An image in a
// format the gateway cannot strip (GIF/WebP/BMP/TIFF) is ALSO fail-closed when
// strip_metadata is requested: the operator demanded metadata removal and we
// cannot guarantee it, so we block unless the route opts into fail-open. A
// genuinely non-image item passes verbatim. Every image is audited as
// action=pass.
func (s *Sanitizer) handlePass(route policy.Route, data []byte, isImage bool) (*ItemResult, error) {
	out := data
	if isImage && route.StripMetadata {
		switch {
		case isJPEG(data):
			stripped, err := exif.Strip(data)
			if err != nil {
				return s.failClosed(route, data, "metadata strip failed")
			}
			out = stripped
		case isPNG(data):
			stripped, err := exif.StripPNG(data)
			if err != nil {
				return s.failClosed(route, data, "metadata strip failed")
			}
			out = stripped
		default:
			// Sniffed as an image but in a format we cannot strip metadata from
			// (GIF/WebP/BMP/TIFF). The operator asked for metadata removal and
			// we cannot honor it, so fail closed (block) unless fail-open.
			return s.failClosed(route, data, "metadata strip unsupported for format")
		}
	}
	if isImage {
		if err := s.audited(route, nil, out); err != nil {
			return s.failClosed(route, data, "audit write failed")
		}
		return &ItemResult{Output: out, Audited: true}, nil
	}
	// Non-image part: pass verbatim, no audit entry (nothing was inspected).
	return &ItemResult{Output: out, Audited: false}, nil
}

// handleMask decodes, detects, masks the union of regions, and re-encodes. Any
// failure is fail-closed (block) unless the route opts into fail-open.
func (s *Sanitizer) handleMask(ctx context.Context, route policy.Route, data []byte, isImage bool) (*ItemResult, error) {
	if !isImage {
		// A non-image part on a masking route is forwarded verbatim only if it
		// is genuinely non-image; masking does not apply to it. This is safe:
		// there are no sensitive pixels to mask in non-image bytes.
		return &ItemResult{Output: data, Audited: false}, nil
	}

	dec, err := imageproc.Decode(data, s.MaxPixels)
	if err != nil {
		switch {
		case errors.Is(err, imageproc.ErrUnsupportedFormat):
			return s.failClosed(route, data, "unsupported image format")
		case errors.Is(err, imageproc.ErrTooManyPixels):
			return s.failClosed(route, data, "image too large")
		case errors.Is(err, imageproc.ErrInvalidBounds):
			return s.failClosed(route, data, "image decode failed")
		default:
			return s.failClosed(route, data, "image decode failed")
		}
	}

	regions, cats, err := s.runDetectors(ctx, route, dec.Image)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// Client disconnect / shutdown: never forward, never fail-open.
			return nil, newBlock("request canceled")
		}
		return s.failClosed(route, data, "detector error")
	}

	mode := imageproc.MaskSolid
	if route.Action == policy.ActionBlur {
		mode = imageproc.MaskBlur
	}
	rects := make([]image.Rectangle, 0, len(regions))
	for _, r := range regions {
		rects = append(rects, r.Rect)
	}
	masked := imageproc.Mask(dec.Image, rects, imageproc.MaskOptions{
		Mode:       mode,
		BlurRadius: s.BlurRadius,
	})

	encode := s.Encode
	if encode == nil {
		encode = imageproc.Encode
	}
	out, err := encode(masked, dec.Format, imageproc.EncodeOptions{JPEGQuality: s.JPEGQuality})
	if err != nil {
		return s.failClosed(route, data, "re-encode failed")
	}

	if err := s.audited(route, regions, out); err != nil {
		return s.failClosed(route, data, "audit write failed")
	}
	_ = cats
	return &ItemResult{Output: out, Audited: true}, nil
}

// runDetectors runs every configured detector and returns the union of regions
// (clamped to image bounds) plus the distinct categories. A detector error is
// propagated for fail-closed handling. An empty/absent detector list yields no
// regions (the route still re-encodes, which strips metadata).
func (s *Sanitizer) runDetectors(ctx context.Context, route policy.Route, img image.Image) ([]detect.Region, []string, error) {
	bounds := img.Bounds()
	var all []detect.Region
	catset := make(map[string]struct{})
	for _, name := range route.Detectors {
		d, ok := s.Registry[name]
		if !ok {
			return nil, nil, fmt.Errorf("sanitize: unknown detector %q", name)
		}
		regions, err := d.Detect(ctx, img)
		if err != nil {
			return nil, nil, fmt.Errorf("sanitize: detector %q: %w", name, err)
		}
		for _, r := range regions {
			clip := r.Rect.Intersect(bounds)
			if clip.Empty() {
				continue
			}
			r.Rect = clip
			all = append(all, r)
			if r.Category != "" {
				catset[r.Category] = struct{}{}
			}
		}
	}
	cats := make([]string, 0, len(catset))
	for c := range catset {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return all, cats, nil
}

// audited writes the audit entry (categories + bboxes + sanitized hash).
func (s *Sanitizer) audited(route policy.Route, regions []detect.Region, sanitized []byte) error {
	if s.Audit == nil {
		return nil
	}
	cats := make([]string, 0, len(regions))
	boxes := make([]image.Rectangle, 0, len(regions))
	for _, r := range regions {
		if r.Category != "" {
			cats = append(cats, r.Category)
		}
		boxes = append(boxes, r.Rect)
	}
	return s.Audit.Record(route.PathPrefix, string(route.Action), cats, boxes, sanitized)
}

// failClosed implements the fail-closed contract for a sanitize failure. By
// default it returns a blockError (the upload is blocked, origin receives
// nothing). When the route opts into fail-open (the documented UNSAFE escape
// hatch, per-route, default off) it instead forwards the ORIGINAL bytes
// unmodified. status is a short, byte-free string safe to return to the client.
func (s *Sanitizer) failClosed(route policy.Route, data []byte, status string) (*ItemResult, error) {
	if route.FailOpen {
		return &ItemResult{Output: data, Audited: false}, nil
	}
	return nil, newBlock(status)
}

func isJPEG(data []byte) bool {
	return len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF
}

func isPNG(data []byte) bool {
	return len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n"
}
