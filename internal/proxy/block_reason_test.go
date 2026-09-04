package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"strings"
	"testing"

	"redact-gateway/internal/audit"
	"redact-gateway/internal/detect"
	"redact-gateway/internal/imageproc"
	"redact-gateway/internal/metrics"
	"redact-gateway/internal/policy"
	"redact-gateway/internal/proxy"
)

// errWriter fails every write, so the audit append inside the sanitizer fails
// and the item is blocked on the audit path.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// gifBytes is a header that classifies as a GIF by magic bytes. The gateway
// cannot mask or strip GIF, so it is the input for both the unsupported-format
// and the metadata-strip paths.
var gifBytes = []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00,")

// sanitizerOpt tweaks the sanitizer a case needs.
type sanitizerOpt func(*proxy.Sanitizer)

func newSanitizer(opts ...sanitizerOpt) *proxy.Sanitizer {
	s := &proxy.Sanitizer{
		Registry: map[string]detect.Detector{
			"region-marker": &detect.RegionMarkerDetector{Marker: markerColor, Tolerance: 16},
		},
		Audit:       audit.NewLogger(&bytes.Buffer{}, audit.SystemClock{}),
		MaxPixels:   40_000_000,
		JPEGQuality: 90,
		BlurRadius:  4,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

var blockReasonRoute = policy.Route{
	PathPrefix: "/u",
	Action:     policy.ActionRedact,
	Detectors:  []string{"region-marker"},
	MaxBytes:   2 << 20,
}

// Every fail-closed path lands in exactly one reason counter, and the
// breakdown sums to redact_uploads_blocked_total.
func TestBlockReasonsAreAttributed(t *testing.T) {
	goodPNG := markerPNG(40, 40, image.Rect(5, 5, 15, 15))

	cases := []struct {
		name   string
		metric string
		build  func() (*proxy.Sanitizer, policy.Route, []byte, context.Context)
	}{
		{
			name:   "undecodable image",
			metric: "redact_uploads_blocked_decode_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				bad := append([]byte("\x89PNG\r\n\x1a\n"), []byte("not-a-png")...)
				return newSanitizer(), blockReasonRoute, bad, context.Background()
			},
		},
		{
			name:   "format the gateway cannot mask",
			metric: "redact_uploads_blocked_unsupported_format_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				return newSanitizer(), blockReasonRoute, gifBytes, context.Background()
			},
		},
		{
			name:   "over the pixel cap",
			metric: "redact_uploads_blocked_too_large_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				s := newSanitizer(func(s *proxy.Sanitizer) { s.MaxPixels = 4 })
				return s, blockReasonRoute, goodPNG, context.Background()
			},
		},
		{
			name:   "detector error",
			metric: "redact_uploads_blocked_detector_error_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				s := newSanitizer(func(s *proxy.Sanitizer) {
					s.Registry = map[string]detect.Detector{
						"boom": &detect.FakeDetector{DetectorName: "boom", Err: errors.New("detector exploded")},
					}
				})
				route := blockReasonRoute
				route.Detectors = []string{"boom"}
				return s, route, goodPNG, context.Background()
			},
		},
		{
			name:   "metadata strip unsupported on a pass route",
			metric: "redact_uploads_blocked_strip_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				route := policy.Route{PathPrefix: "/u", Action: policy.ActionPass, StripMetadata: true, MaxBytes: 2 << 20}
				return newSanitizer(), route, gifBytes, context.Background()
			},
		},
		{
			name:   "re-encode failure",
			metric: "redact_uploads_blocked_encode_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				s := newSanitizer(func(s *proxy.Sanitizer) {
					s.Encode = func(image.Image, imageproc.Format, imageproc.EncodeOptions) ([]byte, error) {
						return nil, errors.New("encoder exploded")
					}
				})
				return s, blockReasonRoute, goodPNG, context.Background()
			},
		},
		{
			name:   "audit write failure",
			metric: "redact_uploads_blocked_audit_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				s := newSanitizer(func(s *proxy.Sanitizer) {
					s.Audit = audit.NewLogger(errWriter{}, audit.SystemClock{})
				})
				return s, blockReasonRoute, goodPNG, context.Background()
			},
		},
		{
			name:   "policy drop",
			metric: "redact_uploads_blocked_policy_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				route := policy.Route{PathPrefix: "/u", Action: policy.ActionDrop, MaxBytes: 2 << 20}
				return newSanitizer(), route, goodPNG, context.Background()
			},
		},
		{
			name:   "request canceled mid-detect",
			metric: "redact_uploads_blocked_canceled_total",
			build: func() (*proxy.Sanitizer, policy.Route, []byte, context.Context) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return newSanitizer(), blockReasonRoute, goodPNG, ctx
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			met := metrics.New()
			san, route, data, ctx := tc.build()
			san.Metrics = met

			if _, err := san.SanitizeImage(ctx, route, data, true); err == nil {
				t.Fatal("expected a fail-closed block")
			}

			got := met.BlockedByReason()
			if got[tc.metric] != 1 {
				t.Errorf("%s = %d, want 1; full breakdown %v", tc.metric, got[tc.metric], got)
			}
			var sum uint64
			for _, v := range got {
				sum += v
			}
			if sum != 1 {
				t.Errorf("per-reason sum = %d, want exactly 1", sum)
			}

			var buf bytes.Buffer
			if err := met.WriteProm(&buf); err != nil {
				t.Fatalf("WriteProm: %v", err)
			}
			if !strings.Contains(buf.String(), "redact_uploads_blocked_total 1\n") {
				t.Error("the total did not move with the reason counter")
			}
		})
	}
}

// A fail-open route forwards instead of blocking, so nothing is counted at all.
func TestFailOpenCountsNeitherTotalNorReason(t *testing.T) {
	met := metrics.New()
	san := newSanitizer()
	san.Metrics = met
	route := blockReasonRoute
	route.FailOpen = true

	if _, err := san.SanitizeImage(context.Background(), route, gifBytes, true); err != nil {
		t.Fatalf("fail-open route returned an error: %v", err)
	}

	for name, v := range met.BlockedByReason() {
		if v != 0 {
			t.Errorf("%s = %d, want 0 on a fail-open forward", name, v)
		}
	}
	var buf bytes.Buffer
	if err := met.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	if !strings.Contains(buf.String(), "redact_uploads_blocked_total 0\n") {
		t.Error("a fail-open forward moved redact_uploads_blocked_total")
	}
}
