// Package metrics provides hand-rolled, dependency-free counters and a
// Prometheus text-exposition HTTP handler for the gateway's observability
// surface (/healthz + /metrics). It is stdlib-only (like the sibling repos):
// no client library, no labels.
//
// The counters are process-wide monotonic totals and safe for concurrent use.
// By design NOTHING request-derived is ever recorded — no image bytes, no
// filenames, no categories, no per-request labels of any kind. Every sample is
// emitted with a bare metric name and an integer value, so the metrics surface
// cannot become a leak channel for the content the gateway is meant to redact.
// This preserves the repo's fail-closed no-leak invariant.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

// Metrics holds the gateway's counters. The zero value is not usable; call New.
// All increment methods are nil-safe so a Sanitizer may hold an optional
// (possibly nil) *Metrics without guarding every call site.
type Metrics struct {
	uploadsProcessed atomic.Uint64
	uploadsBlocked   atomic.Uint64
	imagesSanitized  atomic.Uint64
	regionsMasked    atomic.Uint64
}

// New returns a ready-to-use Metrics with all counters at zero.
func New() *Metrics { return &Metrics{} }

// IncUploadsProcessed counts one upload item (a multipart part or a raw body)
// entering sanitization.
func (m *Metrics) IncUploadsProcessed() {
	if m != nil {
		m.uploadsProcessed.Add(1)
	}
}

// IncUploadsBlocked counts one upload item blocked fail-closed (a block or drop
// decision), i.e. the origin received nothing for it.
func (m *Metrics) IncUploadsBlocked() {
	if m != nil {
		m.uploadsBlocked.Add(1)
	}
}

// IncImagesSanitized counts one image successfully decoded, masked, and
// re-encoded on a redact/blur route.
func (m *Metrics) IncImagesSanitized() {
	if m != nil {
		m.imagesSanitized.Add(1)
	}
}

// AddRegionsMasked adds n to the total sensitive regions masked. A non-positive
// n is ignored.
func (m *Metrics) AddRegionsMasked(n int) {
	if m != nil && n > 0 {
		m.regionsMasked.Add(uint64(n))
	}
}

// sample is one exported counter: a bare name, a help string, and its value.
type sample struct {
	name, help string
	value      uint64
}

func (m *Metrics) samples() []sample {
	return []sample{
		{"redact_uploads_processed_total", "Total upload items processed by the gateway.", m.uploadsProcessed.Load()},
		{"redact_uploads_blocked_total", "Total upload items blocked fail-closed (origin received nothing).", m.uploadsBlocked.Load()},
		{"redact_images_sanitized_total", "Total images decoded, masked, and re-encoded.", m.imagesSanitized.Load()},
		{"redact_regions_masked_total", "Total sensitive regions masked across all images.", m.regionsMasked.Load()},
	}
}

// WriteProm writes the counters in Prometheus text exposition format (v0.0.4):
// a "# HELP" and "# TYPE" line plus a single UNLABELED sample per metric. No
// label is ever emitted, so no request-derived string can ride out on the
// metrics surface.
func (m *Metrics) WriteProm(w io.Writer) error {
	if m == nil {
		return nil
	}
	for _, s := range m.samples() {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", s.name, s.help, s.name, s.name, s.value); err != nil {
			return err
		}
	}
	return nil
}

// Handler returns an http.Handler serving GET /healthz (200 "ok") and GET
// /metrics (Prometheus exposition). It is intended for a SEPARATE admin
// listener, never the proxy listener, so liveness/metrics can never be
// interceptable as an upload. Any other path returns 404.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = m.WriteProm(w)
	})
	return mux
}
