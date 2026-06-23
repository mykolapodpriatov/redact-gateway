package intercept_test

import (
	"bytes"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"strings"
	"testing"

	"redact-gateway/internal/intercept"
)

func buildBody(t *testing.T, parts []struct {
	name, filename string
	body           []byte
}) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		hdr := textproto.MIMEHeader{}
		if p.filename != "" {
			hdr.Set("Content-Disposition", `form-data; name="`+p.name+`"; filename="`+p.filename+`"`)
		} else {
			hdr.Set("Content-Disposition", `form-data; name="`+p.name+`"`)
		}
		pw, _ := w.CreatePart(hdr)
		_, _ = pw.Write(p.body)
	}
	_ = w.Close()
	return buf.Bytes(), w.Boundary()
}

func TestParseBoundary(t *testing.T) {
	b, ok := intercept.ParseBoundary("multipart/form-data; boundary=abc123")
	if !ok || b != "abc123" {
		t.Fatalf("boundary parse: %q ok=%v", b, ok)
	}
	if _, ok := intercept.ParseBoundary("application/json"); ok {
		t.Fatal("non-multipart should not yield a boundary")
	}
	if _, ok := intercept.ParseBoundary("multipart/form-data"); ok {
		t.Fatal("missing boundary should not be ok")
	}
}

func TestParseMultipartPerPartLimit(t *testing.T) {
	body, boundary := buildBody(t, []struct {
		name, filename string
		body           []byte
	}{
		{"small", "", []byte("tiny")},
		{"big", "big.bin", bytes.Repeat([]byte("Z"), 5000)},
	})
	// Cap below the big part but the total body is modest: per-part enforcement
	// must still reject.
	_, err := intercept.ParseMultipart(bytes.NewReader(body), boundary, 1000)
	if err != intercept.ErrTooLarge {
		t.Fatalf("want ErrTooLarge for oversize part, got %v", err)
	}
}

func TestParseMultipartOK(t *testing.T) {
	body, boundary := buildBody(t, []struct {
		name, filename string
		body           []byte
	}{
		{"a", "", []byte("alpha")},
		{"b", "b.png", []byte("\x89PNGdata")},
	})
	pl, err := intercept.ParseMultipart(bytes.NewReader(body), boundary, 1<<20)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pl.Parts) != 2 {
		t.Fatalf("want 2 parts, got %d", len(pl.Parts))
	}
	if pl.Parts[0].Index != 0 || pl.Parts[1].Index != 1 {
		t.Fatalf("indices wrong: %d %d", pl.Parts[0].Index, pl.Parts[1].Index)
	}
	if pl.Parts[1].FileName != "b.png" {
		t.Fatalf("filename not parsed: %q", pl.Parts[1].FileName)
	}
	if pl.Boundary != boundary {
		t.Fatalf("boundary not captured: %q != %q", pl.Boundary, boundary)
	}
}

func TestSerializePreservesBoundaryAndOrder(t *testing.T) {
	body, boundary := buildBody(t, []struct {
		name, filename string
		body           []byte
	}{
		{"first", "", []byte("one")},
		{"second", "s.bin", []byte("two")},
		{"third", "", []byte("three")},
	})
	pl, err := intercept.ParseMultipart(bytes.NewReader(body), boundary, 1<<20)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Rewrite the middle part's body (simulating a sanitized image).
	pl.Parts[1].Body = []byte("SANITIZED")

	out, err := pl.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// The same boundary token must be used.
	if !bytes.Contains(out, []byte("--"+boundary)) {
		t.Fatal("serialized body does not reuse the original boundary")
	}
	// Re-parse and confirm order + rewritten content.
	pl2, err := intercept.ParseMultipart(bytes.NewReader(out), boundary, 1<<20)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(pl2.Parts) != 3 {
		t.Fatalf("want 3 parts after round-trip, got %d", len(pl2.Parts))
	}
	if string(pl2.Parts[0].Body) != "one" || string(pl2.Parts[1].Body) != "SANITIZED" || string(pl2.Parts[2].Body) != "three" {
		t.Fatalf("order/content wrong: %q %q %q",
			pl2.Parts[0].Body, pl2.Parts[1].Body, pl2.Parts[2].Body)
	}
	if pl2.Parts[0].FormName != "first" || pl2.Parts[2].FormName != "third" {
		t.Fatalf("field names not preserved: %q %q", pl2.Parts[0].FormName, pl2.Parts[2].FormName)
	}
}

func TestSerializeRecomputesPerPartContentLength(t *testing.T) {
	// A part carrying an explicit Content-Length must have it recomputed to the
	// rewritten body length.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="f"; filename="f.bin"`)
	hdr.Set("Content-Length", "3")
	pw, _ := w.CreatePart(hdr)
	_, _ = pw.Write([]byte("abc"))
	_ = w.Close()
	boundary := w.Boundary()

	pl, err := intercept.ParseMultipart(bytes.NewReader(buf.Bytes()), boundary, 1<<20)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pl.Parts[0].Body = []byte("a-much-longer-sanitized-body")
	out, err := pl.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// The recomputed length must appear and equal the new body size.
	wantLen := strconv.Itoa(len("a-much-longer-sanitized-body"))
	if !strings.Contains(string(out), "Content-Length: "+wantLen) {
		t.Fatalf("per-part Content-Length not recomputed to %s:\n%s", wantLen, out)
	}
	if strings.Contains(string(out), "Content-Length: 3") {
		t.Fatal("stale per-part Content-Length survived")
	}
}

func TestReadRawBody(t *testing.T) {
	raw, err := intercept.ReadRawBody(bytes.NewReader([]byte("hello")), 1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(raw.Bytes) != "hello" {
		t.Fatalf("body mismatch: %q", raw.Bytes)
	}
}

func TestReadRawBodyTooLarge(t *testing.T) {
	_, err := intercept.ReadRawBody(bytes.NewReader(bytes.Repeat([]byte("x"), 100)), 10)
	if err != intercept.ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestReadRawBodyZeroCap(t *testing.T) {
	_, err := intercept.ReadRawBody(bytes.NewReader([]byte("x")), 0)
	if err != intercept.ErrTooLarge {
		t.Fatalf("want ErrTooLarge for zero cap, got %v", err)
	}
}
