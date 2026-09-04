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

// BlockReason names why an upload item was blocked fail-closed. Every value is
// a compile-time constant chosen by the gateway from a closed set; none of them
// is derived from the request, so counting them cannot leak upload content.
//
// ReasonUnset is the zero value and is deliberately NOT a reason: a block
// raised outside the sanitize path (a malformed multipart body, say) carries it
// and is not counted, which keeps redact_uploads_blocked_total measuring
// exactly what it has always measured.
type BlockReason int

const (
	ReasonUnset BlockReason = iota
	ReasonDecode
	ReasonUnsupportedFormat
	ReasonTooLarge
	ReasonDetectorError
	ReasonStrip
	ReasonEncode
	ReasonAudit
	ReasonPolicy
	ReasonCanceled
	numBlockReasons
)

// Valid reports whether r is a real reason (not the unset zero value).
func (r BlockReason) Valid() bool { return r > ReasonUnset && r < numBlockReasons }

// blockReasonMetric maps each reason to its exported metric name and help text.
// Indexed by BlockReason; the ReasonUnset slot is never exported.
var blockReasonMetric = [numBlockReasons]struct{ name, help string }{
	ReasonDecode:            {"redact_uploads_blocked_decode_total", "Upload items blocked because the image could not be decoded (corrupt or truncated)."},
	ReasonUnsupportedFormat: {"redact_uploads_blocked_unsupported_format_total", "Upload items blocked because the image format cannot be masked (classified by magic bytes)."},
	ReasonTooLarge:          {"redact_uploads_blocked_too_large_total", "Upload items blocked by the pixel cap (decompression-bomb guard)."},
	ReasonDetectorError:     {"redact_uploads_blocked_detector_error_total", "Upload items blocked because a detector returned an error."},
	ReasonStrip:             {"redact_uploads_blocked_strip_total", "Upload items blocked because metadata could not be stripped on a pass route."},
	ReasonEncode:            {"redact_uploads_blocked_encode_total", "Upload items blocked because the masked image could not be re-encoded."},
	ReasonAudit:             {"redact_uploads_blocked_audit_total", "Upload items blocked because the audit entry could not be written."},
	ReasonPolicy:            {"redact_uploads_blocked_policy_total", "Upload items blocked by policy (a drop route, or an unknown action)."},
	ReasonCanceled:          {"redact_uploads_blocked_canceled_total", "Upload items blocked because the request was canceled mid-sanitize."},
}

// Metrics holds the gateway's counters. The zero value is not usable; call New.
// All increment methods are nil-safe so a Sanitizer may hold an optional
// (possibly nil) *Metrics without guarding every call site.
type Metrics struct {
	uploadsProcessed atomic.Uint64
	uploadsBlocked   atomic.Uint64
	imagesSanitized  atomic.Uint64
	regionsMasked    atomic.Uint64

	// blockedByReason breaks uploadsBlocked down by cause. Every increment
	// bumps both, so the per-reason counters always sum to uploadsBlocked.
	blockedByReason [numBlockReasons]atomic.Uint64
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
// decision), i.e. the origin received nothing for it, and attributes it to a
// reason. The total and the reason counter move together, so the per-reason
// counters always sum to the total. An invalid reason still counts toward the
// total, so a future block path that forgets to name itself under-reports the
// breakdown rather than losing the block entirely.
func (m *Metrics) IncUploadsBlocked(reason BlockReason) {
	if m == nil {
		return
	}
	m.uploadsBlocked.Add(1)
	if reason.Valid() {
		m.blockedByReason[reason].Add(1)
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
	out := []sample{
		{"redact_uploads_processed_total", "Total upload items processed by the gateway.", m.uploadsProcessed.Load()},
		{"redact_uploads_blocked_total", "Total upload items blocked fail-closed (origin received nothing).", m.uploadsBlocked.Load()},
		{"redact_images_sanitized_total", "Total images decoded, masked, and re-encoded.", m.imagesSanitized.Load()},
		{"redact_regions_masked_total", "Total sensitive regions masked across all images.", m.regionsMasked.Load()},
	}
	// The breakdown is emitted in reason order, always, including at zero: a
	// counter that only appears once it fires is a counter nobody can alert on.
	for r := ReasonUnset + 1; r < numBlockReasons; r++ {
		out = append(out, sample{blockReasonMetric[r].name, blockReasonMetric[r].help, m.blockedByReason[r].Load()})
	}
	return out
}

// BlockedByReason returns the current per-reason block counts, keyed by the
// exported metric name. It exists so tests can assert the sum invariant
// without parsing the exposition text.
func (m *Metrics) BlockedByReason() map[string]uint64 {
	if m == nil {
		return nil
	}
	out := make(map[string]uint64, numBlockReasons-1)
	for r := ReasonUnset + 1; r < numBlockReasons; r++ {
		out[blockReasonMetric[r].name] = m.blockedByReason[r].Load()
	}
	return out
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
