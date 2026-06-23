// Package audit writes an append-only JSON-lines record of what the gateway
// redacted, WITHOUT ever persisting original pixels. Each entry stores the
// route, action, the detected categories and bounding boxes, and a SHA-256 of
// the SANITIZED output only.
//
// The ts_label field is gateway-generated (a monotonic counter plus an
// injected clock) and is NEVER derived from request data, so there is no
// log-injection vector via timestamps. Every string field is written through
// encoding/json, which escapes control and JSON-special characters, so a
// hostile filename or form field cannot split or corrupt a line.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Clock supplies the wall-clock time used to build ts_label. It is injected so
// tests are deterministic. The standard implementation is SystemClock.
type Clock interface {
	Now() time.Time
}

// SystemClock returns the real wall-clock time.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// BBox is a serialized bounding box (pixel coordinates) for the audit entry.
type BBox struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

// bboxFromRect converts an image.Rectangle to a BBox.
func bboxFromRect(r image.Rectangle) BBox {
	return BBox{X: r.Min.X, Y: r.Min.Y, W: r.Dx(), H: r.Dy()}
}

// Entry is one audit record. It deliberately has no field that could carry
// original image bytes.
type Entry struct {
	// TSLabel is gateway-generated ("<seq>@<rfc3339nano>"), never
	// request-derived.
	TSLabel string `json:"ts_label"`
	// Route is the matched route's path prefix.
	Route string `json:"route"`
	// Action is the policy action applied (redact/blur/drop/pass).
	Action string `json:"action"`
	// Categories lists the distinct detector categories that contributed
	// regions.
	Categories []string `json:"categories"`
	// BBoxes lists the masked bounding boxes.
	BBoxes []BBox `json:"bboxes"`
	// SanitizedSHA256 is the hex SHA-256 of the SANITIZED output bytes. For a
	// dropped or non-re-encoded item it may be empty.
	SanitizedSHA256 string `json:"sanitized_sha256,omitempty"`
}

// Logger writes audit entries as JSON lines to an io.Writer. It is safe for
// concurrent use. The sequence counter and injected clock together produce a
// strictly increasing, non-request-derived ts_label.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	clock Clock
	seq   atomic.Uint64
}

// NewLogger returns a Logger writing to w. If clock is nil, SystemClock is
// used.
func NewLogger(w io.Writer, clock Clock) *Logger {
	if clock == nil {
		clock = SystemClock{}
	}
	return &Logger{w: w, clock: clock}
}

// Record builds an entry from the route/action/regions/sanitized bytes and
// appends it as a single JSON line. The ts_label is generated here. The
// sanitized hash is computed from sanitized (pass nil for a dropped upload).
// Original pixels are never touched.
func (l *Logger) Record(route, action string, categories []string, boxes []image.Rectangle, sanitized []byte) error {
	e := Entry{
		TSLabel:    l.nextLabel(),
		Route:      route,
		Action:     action,
		Categories: dedupe(categories),
		BBoxes:     toBBoxes(boxes),
	}
	if sanitized != nil {
		sum := sha256.Sum256(sanitized)
		e.SanitizedSHA256 = hex.EncodeToString(sum[:])
	}
	return l.write(e)
}

// nextLabel returns "<seq>@<rfc3339nano>" using the monotonic counter and the
// injected clock. The sequence guarantees uniqueness and ordering even if the
// clock has coarse resolution.
func (l *Logger) nextLabel() string {
	n := l.seq.Add(1)
	return fmt.Sprintf("%d@%s", n, l.clock.Now().UTC().Format(time.RFC3339Nano))
}

func (l *Logger) write(e Entry) error {
	// Marshal first (escapes all strings), then write the line under the lock
	// so concurrent records never interleave bytes.
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(b); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

func toBBoxes(boxes []image.Rectangle) []BBox {
	out := make([]BBox, 0, len(boxes))
	for _, r := range boxes {
		out = append(out, bboxFromRect(r))
	}
	return out
}

// dedupe returns the distinct, order-preserving categories (nil-safe). An
// empty input yields an empty (non-nil) slice so the JSON is [] not null.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
