package proxy_test

import (
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"testing"

	"redact-gateway/internal/detect"
	"redact-gateway/internal/policy"
	"redact-gateway/internal/testutil"
)

func cardPIIRegistry(boxes []detect.TextBox) map[string]detect.Detector {
	return map[string]detect.Detector{
		"regex-pii": &detect.RegexPIIDetector{
			OCR:      &detect.FakeOCR{Boxes: boxes},
			Patterns: detect.DefaultPIIPatterns(),
		},
	}
}

func assertRedactedHeaders(t *testing.T, rec *httptest.ResponseRecorder, wantCount, wantCats string) {
	t.Helper()
	if _, ok := rec.Result().Header["X-Redacted-Count"]; !ok {
		t.Fatal("missing X-Redacted-Count")
	}
	if _, ok := rec.Result().Header["X-Redacted-Categories"]; !ok {
		t.Fatal("missing X-Redacted-Categories")
	}
	if got := rec.Header().Get("X-Redacted-Count"); got != wantCount {
		t.Fatalf("X-Redacted-Count = %q, want %q", got, wantCount)
	}
	if got := rec.Header().Get("X-Redacted-Categories"); got != wantCats {
		t.Fatalf("X-Redacted-Categories = %q, want %q", got, wantCats)
	}
}

func assertRedactedHeadersAbsent(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if _, ok := rec.Result().Header["X-Redacted-Count"]; ok {
		t.Fatalf("X-Redacted-Count present before detection: %q", rec.Header().Get("X-Redacted-Count"))
	}
	if _, ok := rec.Result().Header["X-Redacted-Categories"]; ok {
		t.Fatalf("X-Redacted-Categories present before detection: %q", rec.Header().Get("X-Redacted-Categories"))
	}
}

func TestRedactedHeadersCardDetector(t *testing.T) {
	rig := newRig(t, rigOptions{
		routes: []policy.Route{{
			PathPrefix: "/u",
			Action:     policy.ActionRedact,
			Detectors:  []string{"regex-pii"},
			MaxBytes:   2 << 20,
		}},
		registry: cardPIIRegistry([]detect.TextBox{
			{Text: "4111111111111111", Rect: image.Rect(2, 2, 20, 12)},
		}),
	})
	img := testutil.EncodePNG(testutil.SolidRGBA(32, 32, color.White))
	rec := rig.doRaw(t, http.MethodPut, "/u/card.png", "image/png", img)
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v body=%q", rec.Code, rig.origin.Hit(), rec.Body.String())
	}
	assertRedactedHeaders(t, rec, "1", "card")
}

func TestRedactedHeadersCleanImage(t *testing.T) {
	rig := newRig(t, rigOptions{
		routes: []policy.Route{{
			PathPrefix: "/u",
			Action:     policy.ActionRedact,
			Detectors:  []string{"regex-pii"},
			MaxBytes:   2 << 20,
		}},
		registry: cardPIIRegistry(nil),
	})
	img := testutil.EncodePNG(testutil.SolidRGBA(32, 32, color.White))
	rec := rig.doRaw(t, http.MethodPut, "/u/clean.png", "image/png", img)
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v body=%q", rec.Code, rig.origin.Hit(), rec.Body.String())
	}
	assertRedactedHeaders(t, rec, "0", "")
}

func TestRedactedHeadersAbsentOn4xxBeforeDetection(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{{
		PathPrefix: "/u",
		Action:     policy.ActionRedact,
		Detectors:  []string{"regex-pii"},
		MaxBytes:   16,
	}},
		registry: cardPIIRegistry(nil),
	})
	big := testutil.EncodePNG(testutil.SolidRGBA(64, 64, color.White))
	rec := rig.doRaw(t, http.MethodPut, "/u/big.png", "image/png", big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", rec.Code)
	}
	if rig.origin.Hit() {
		t.Fatal("oversize body should not reach origin")
	}
	assertRedactedHeadersAbsent(t, rec)
}

func TestRedactedHeadersPassAndDrop(t *testing.T) {
	img := testutil.EncodePNG(testutil.SolidRGBA(16, 16, color.White))

	pass := newRig(t, rigOptions{routes: []policy.Route{{
		PathPrefix: "/p", Action: policy.ActionPass, MaxBytes: 2 << 20,
	}}})
	passRec := pass.doRaw(t, http.MethodPut, "/p/a.png", "image/png", img)
	if passRec.Code != http.StatusOK || !pass.origin.Hit() {
		t.Fatalf("pass status=%d hit=%v", passRec.Code, pass.origin.Hit())
	}
	assertRedactedHeaders(t, passRec, "0", "")

	drop := newRig(t, rigOptions{routes: []policy.Route{{
		PathPrefix: "/d", Action: policy.ActionDrop, MaxBytes: 2 << 20,
	}}})
	dropRec := drop.doRaw(t, http.MethodPut, "/d/a.png", "image/png", img)
	if drop.origin.Hit() {
		t.Fatal("drop reached origin")
	}
	if dropRec.Code == http.StatusOK {
		t.Fatalf("drop should not return 200, got %d", dropRec.Code)
	}
	assertRedactedHeaders(t, dropRec, "0", "")
}
