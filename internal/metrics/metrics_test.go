package metrics_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"redact-gateway/internal/metrics"
)

func TestCountersAndExposition(t *testing.T) {
	m := metrics.New()
	m.IncUploadsProcessed()
	m.IncUploadsProcessed()
	m.IncUploadsProcessed()
	m.IncUploadsBlocked()
	m.IncImagesSanitized()
	m.IncImagesSanitized()
	m.AddRegionsMasked(5)
	m.AddRegionsMasked(0)  // ignored
	m.AddRegionsMasked(-3) // ignored

	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	out := buf.String()

	wantLines := []string{
		"redact_uploads_processed_total 3",
		"redact_uploads_blocked_total 1",
		"redact_images_sanitized_total 2",
		"redact_regions_masked_total 5",
	}
	for _, want := range wantLines {
		if !strings.Contains(out, want) {
			t.Fatalf("exposition missing %q; got:\n%s", want, out)
		}
	}

	// Every metric must carry HELP and TYPE metadata.
	for _, name := range []string{
		"redact_uploads_processed_total",
		"redact_uploads_blocked_total",
		"redact_images_sanitized_total",
		"redact_regions_masked_total",
	} {
		if !strings.Contains(out, "# TYPE "+name+" counter") {
			t.Fatalf("missing TYPE line for %q", name)
		}
	}
}

// TestNoLabelsNoLeak asserts the metrics surface can never carry a
// request-derived label: the exposition uses bare metric names with no '{...}'
// label set at all. This is the fail-closed no-leak invariant applied to
// observability — no image bytes or filenames can ride out on a metric label.
func TestNoLabelsNoLeak(t *testing.T) {
	m := metrics.New()
	m.IncUploadsProcessed()
	m.AddRegionsMasked(42)

	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	if bytes.ContainsRune(buf.Bytes(), '{') {
		t.Fatalf("exposition contains a label set (leak channel):\n%s", buf.String())
	}
}

func TestHandlerHealthzAndMetrics(t *testing.T) {
	m := metrics.New()
	m.IncUploadsProcessed()
	h := m.Handler()

	// /healthz
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("/healthz body = %q, want ok", rec.Body.String())
	}

	// /metrics
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "redact_uploads_processed_total 1") {
		t.Fatalf("/metrics body missing counter: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("/metrics content-type = %q", ct)
	}

	// Unknown path → 404.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", rec.Code)
	}
}

// TestNilMetricsIsNoOp confirms the nil-safe contract: a nil *Metrics accepts
// increments and writes nothing without panicking.
func TestNilMetricsIsNoOp(t *testing.T) {
	var m *metrics.Metrics
	m.IncUploadsProcessed()
	m.IncUploadsBlocked()
	m.IncImagesSanitized()
	m.AddRegionsMasked(7)
	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("nil WriteProm: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("nil metrics wrote %d bytes, want 0", buf.Len())
	}
}
