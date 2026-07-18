package proxy_test

import (
	"bytes"
	"context"
	"image"
	"strings"
	"testing"

	"redact-gateway/internal/audit"
	"redact-gateway/internal/detect"
	"redact-gateway/internal/metrics"
	"redact-gateway/internal/policy"
	"redact-gateway/internal/proxy"
)

// TestSanitizerMetricsWiring exercises the counters wired into sanitize.go: a
// successful redact bumps processed + images-sanitized + regions-masked, and a
// fail-closed block bumps processed + blocked.
func TestSanitizerMetricsWiring(t *testing.T) {
	met := metrics.New()
	san := &proxy.Sanitizer{
		Registry:    map[string]detect.Detector{"region-marker": &detect.RegionMarkerDetector{Marker: markerColor, Tolerance: 16}},
		Audit:       audit.NewLogger(&bytes.Buffer{}, audit.SystemClock{}),
		MaxPixels:   40_000_000,
		JPEGQuality: 90,
		BlurRadius:  4,
		Metrics:     met,
	}
	route := policy.Route{PathPrefix: "/u", Action: policy.ActionRedact, Detectors: []string{"region-marker"}, MaxBytes: 2 << 20}

	// One valid image with a single marker region → sanitized.
	img := markerPNG(40, 40, image.Rect(5, 5, 15, 15))
	if _, err := san.SanitizeImage(context.Background(), route, img, true); err != nil {
		t.Fatalf("sanitize valid image: %v", err)
	}

	// One undecodable image (sniffs as PNG) → fail-closed block.
	bad := append([]byte("\x89PNG\r\n\x1a\n"), []byte("not-a-png")...)
	if _, err := san.SanitizeImage(context.Background(), route, bad, true); err == nil {
		t.Fatal("expected a block for the undecodable image")
	}

	var buf bytes.Buffer
	if err := met.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"redact_uploads_processed_total 2",
		"redact_uploads_blocked_total 1",
		"redact_images_sanitized_total 1",
		"redact_regions_masked_total 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q; got:\n%s", want, out)
		}
	}
}
