package metrics_test

import (
	"bytes"
	"fmt"
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
	m.IncUploadsBlocked(metrics.ReasonDecode)
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
	m.IncUploadsBlocked(metrics.ReasonDecode)
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

// ---- per-reason block breakdown --------------------------------------------

// allReasons is every real BlockReason paired with the metric it must land in.
var allReasons = []struct {
	reason metrics.BlockReason
	metric string
}{
	{metrics.ReasonDecode, "redact_uploads_blocked_decode_total"},
	{metrics.ReasonUnsupportedFormat, "redact_uploads_blocked_unsupported_format_total"},
	{metrics.ReasonTooLarge, "redact_uploads_blocked_too_large_total"},
	{metrics.ReasonDetectorError, "redact_uploads_blocked_detector_error_total"},
	{metrics.ReasonStrip, "redact_uploads_blocked_strip_total"},
	{metrics.ReasonEncode, "redact_uploads_blocked_encode_total"},
	{metrics.ReasonAudit, "redact_uploads_blocked_audit_total"},
	{metrics.ReasonPolicy, "redact_uploads_blocked_policy_total"},
	{metrics.ReasonCanceled, "redact_uploads_blocked_canceled_total"},
}

// Each reason lands in its own counter, and every counter is exported even at
// zero so an operator can alert on it before it has ever fired.
func TestBlockedByReasonRoutesEachReason(t *testing.T) {
	for _, tc := range allReasons {
		t.Run(tc.metric, func(t *testing.T) {
			m := metrics.New()
			m.IncUploadsBlocked(tc.reason)
			got := m.BlockedByReason()
			if got[tc.metric] != 1 {
				t.Errorf("%s = %d, want 1", tc.metric, got[tc.metric])
			}
			for _, other := range allReasons {
				if other.metric != tc.metric && got[other.metric] != 0 {
					t.Errorf("%s = %d, want 0", other.metric, got[other.metric])
				}
			}
		})
	}
}

// The breakdown always sums to the total after a mixed run.
func TestBlockedByReasonSumsToTotal(t *testing.T) {
	m := metrics.New()
	counts := map[metrics.BlockReason]int{
		metrics.ReasonDecode:        3,
		metrics.ReasonPolicy:        2,
		metrics.ReasonCanceled:      1,
		metrics.ReasonDetectorError: 4,
	}
	total := 0
	for reason, n := range counts {
		for i := 0; i < n; i++ {
			m.IncUploadsBlocked(reason)
			total++
		}
	}

	var sum uint64
	for _, v := range m.BlockedByReason() {
		sum += v
	}
	if sum != uint64(total) {
		t.Errorf("per-reason sum = %d, want %d", sum, total)
	}

	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	if want := fmt.Sprintf("redact_uploads_blocked_total %d\n", total); !strings.Contains(buf.String(), want) {
		t.Errorf("exposition missing %q", want)
	}
}

// An unattributed block still moves the total, so a future block path that
// forgets to name a reason under-reports the breakdown instead of vanishing.
func TestUnsetReasonStillCountsTotal(t *testing.T) {
	m := metrics.New()
	m.IncUploadsBlocked(metrics.ReasonUnset)

	var sum uint64
	for _, v := range m.BlockedByReason() {
		sum += v
	}
	if sum != 0 {
		t.Errorf("per-reason sum = %d, want 0 for an unset reason", sum)
	}

	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	if !strings.Contains(buf.String(), "redact_uploads_blocked_total 1\n") {
		t.Error("unattributed block did not move redact_uploads_blocked_total")
	}
}

// The no-leak invariant: redact_build_info is the ONLY labeled series, and its
// labels are build-time constants. Every counter stays bare, so no
// request-derived string can ride out on a metric.
func TestBuildInfoIsTheOnlyLabeledSeries(t *testing.T) {
	m := metrics.New()
	m.SetBuildInfo("v1.2.3", "go1.24.0")
	for _, tc := range allReasons {
		m.IncUploadsBlocked(tc.reason)
	}
	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !strings.ContainsAny(line, "{}") {
			continue
		}
		if !strings.HasPrefix(line, "redact_build_info{") {
			t.Errorf("sample line carries a label: %q", line)
		}
	}
}

// The build-info series carries the version and the Go version, is typed as a
// gauge, and always has the value 1.
func TestBuildInfoExposition(t *testing.T) {
	m := metrics.New()
	m.SetBuildInfo("v1.2.3", "go1.24.0")
	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# TYPE redact_build_info gauge\n",
		`redact_build_info{version="v1.2.3",go_version="go1.24.0"} 1` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q; got:\n%s", want, out)
		}
	}
}

// Without SetBuildInfo the series is absent rather than exported empty.
func TestBuildInfoAbsentWhenUnset(t *testing.T) {
	var buf bytes.Buffer
	if err := metrics.New().WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	if strings.Contains(buf.String(), "redact_build_info") {
		t.Error("redact_build_info exported without SetBuildInfo")
	}
}

// A version string with a quote or a backslash in it must not be able to break
// out of its label and corrupt the exposition for every other series.
func TestBuildInfoEscapesLabelValues(t *testing.T) {
	m := metrics.New()
	m.SetBuildInfo(`v1"2\3`+"\n", "go1.24.0")
	var buf bytes.Buffer
	if err := m.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	want := `redact_build_info{version="v1\"2\\3\n",go_version="go1.24.0"} 1`
	if !strings.Contains(buf.String(), want) {
		t.Errorf("exposition missing %q; got:\n%s", want, buf.String())
	}
	// One line, still: an unescaped newline would have split the series.
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "redact_build_info") && !strings.HasSuffix(line, " 1") {
			t.Errorf("build info line is malformed: %q", line)
		}
	}
}

// A nil *Metrics accepts SetBuildInfo without panicking.
func TestSetBuildInfoNilSafe(t *testing.T) {
	var m *metrics.Metrics
	m.SetBuildInfo("v1", "go1")
}

// Every reason's counter appears in the exposition even before it fires.
func TestExpositionListsEveryReasonAtZero(t *testing.T) {
	var buf bytes.Buffer
	if err := metrics.New().WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	for _, tc := range allReasons {
		if !strings.Contains(buf.String(), tc.metric+" 0\n") {
			t.Errorf("exposition missing %q at zero", tc.metric)
		}
	}
}
