package audit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"strings"
	"sync"
	"testing"
	"time"

	"redact-gateway/internal/audit"
)

// fixedClock returns a constant time, so ts_label depends only on the
// gateway-generated sequence (never request data).
type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

func TestRecordHasBBoxesCategoriesHash(t *testing.T) {
	var buf bytes.Buffer
	clk := fixedClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	l := audit.NewLogger(&buf, clk)

	sanitized := []byte("sanitized-output-bytes")
	boxes := []image.Rectangle{image.Rect(1, 2, 11, 22), image.Rect(5, 5, 6, 6)}
	if err := l.Record("/upload", "redact", []string{"face", "face", "email"}, boxes, sanitized); err != nil {
		t.Fatalf("record: %v", err)
	}

	var e audit.Entry
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Route != "/upload" || e.Action != "redact" {
		t.Fatalf("route/action wrong: %+v", e)
	}
	if len(e.BBoxes) != 2 || e.BBoxes[0] != (audit.BBox{X: 1, Y: 2, W: 10, H: 20}) {
		t.Fatalf("bboxes wrong: %+v", e.BBoxes)
	}
	// Categories de-duplicated.
	if len(e.Categories) != 2 {
		t.Fatalf("categories not deduped: %+v", e.Categories)
	}
	sum := sha256.Sum256(sanitized)
	if e.SanitizedSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sanitized hash wrong")
	}
	// ts_label starts with the sequence number and is not request-derived.
	if !strings.HasPrefix(e.TSLabel, "1@") {
		t.Fatalf("ts_label = %q, want gateway-generated 1@...", e.TSLabel)
	}
}

func TestNoOriginalPixelLeak(t *testing.T) {
	// A distinctive original pixel payload that must NEVER appear in the audit
	// line in raw, hex, or base64 form.
	original := []byte("ORIGINAL-SECRET-PIXEL-DATA-DEADBEEF-1234567890")
	sanitized := []byte("totally-different-sanitized")

	var buf bytes.Buffer
	l := audit.NewLogger(&buf, fixedClock{t: time.Unix(0, 0).UTC()})
	if err := l.Record("/r", "blur", []string{"x"}, []image.Rectangle{image.Rect(0, 0, 1, 1)}, sanitized); err != nil {
		t.Fatalf("record: %v", err)
	}
	line := buf.Bytes()

	checks := map[string][]byte{
		"raw":    original,
		"hex":    []byte(hex.EncodeToString(original)),
		"base64": []byte(base64.StdEncoding.EncodeToString(original)),
	}
	for form, needle := range checks {
		if bytes.Contains(line, needle) {
			t.Fatalf("audit line leaked original pixels in %s form", form)
		}
	}

	// And the sanitized hash must differ from the original's hash.
	origSum := sha256.Sum256(original)
	if strings.Contains(string(line), hex.EncodeToString(origSum[:])) {
		t.Fatal("audit line contains sha256(original)")
	}
}

func TestNoLogInjection(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLogger(&buf, fixedClock{t: time.Unix(0, 0).UTC()})
	// A hostile category containing a newline and JSON-special characters that
	// would split or corrupt a naive line-based log.
	hostile := "evil\",\"action\":\"pass\"}\n{\"injected\":\"line"
	if err := l.Record("/r", "redact", []string{hostile}, nil, []byte("out")); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Exactly one newline (the line terminator) — no injected second line.
	if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 1 {
		t.Fatalf("expected exactly 1 newline, got %d (log injection!)", n)
	}
	// The line must still parse as a single JSON object with the hostile string
	// preserved verbatim inside the category field.
	var e audit.Entry
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &e); err != nil {
		t.Fatalf("line is not valid single JSON: %v", err)
	}
	if len(e.Categories) != 1 || e.Categories[0] != hostile {
		t.Fatalf("hostile category not preserved/escaped: %+v", e.Categories)
	}
}

func TestAppendOnlyMonotonicLabels(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLogger(&buf, fixedClock{t: time.Unix(0, 0).UTC()})
	for i := 0; i < 3; i++ {
		if err := l.Record("/r", "pass", nil, nil, nil); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}
	for i, ln := range lines {
		var e audit.Entry
		if err := json.Unmarshal(ln, &e); err != nil {
			t.Fatalf("line %d invalid: %v", i, err)
		}
		wantPrefix := []byte{byte('1' + i)}
		if !strings.HasPrefix(e.TSLabel, string(wantPrefix)+"@") {
			t.Fatalf("line %d ts_label=%q, want seq %d", i, e.TSLabel, i+1)
		}
	}
}

func TestConcurrentRecordsNoInterleave(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLogger(&buf, fixedClock{t: time.Unix(0, 0).UTC()})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Record("/r", "redact", []string{"c"}, []image.Rectangle{image.Rect(0, 0, 1, 1)}, []byte("x"))
		}()
	}
	wg.Wait()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 50 {
		t.Fatalf("want 50 lines, got %d", len(lines))
	}
	for i, ln := range lines {
		var e audit.Entry
		if err := json.Unmarshal(ln, &e); err != nil {
			t.Fatalf("line %d not valid JSON (interleaved write): %v", i, err)
		}
	}
}
