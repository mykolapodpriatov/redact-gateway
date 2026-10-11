package proxy_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"redact-gateway/internal/policy"
)

func TestDotSegmentDoesNotTakeThePassRoute(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/public", Action: policy.ActionPass, MaxBytes: 1 << 20},
		{PathPrefix: "/private", Action: policy.ActionDrop, MaxBytes: 1 << 20},
	}})
	req := httptest.NewRequest(http.MethodPost, "/ignored", bytes.NewReader([]byte("not-an-image")))
	req.URL.Path = "/public/../private/a.jpg"
	req.URL.RawPath = "/public/../private/a.jpg"
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	rig.handler.ServeHTTP(rec, req)
	if rig.origin.Hit() {
		t.Fatalf("origin received %s; dot-segments took the pass route", rig.origin.Path())
	}
}

func TestDotSegmentIsForwardedClean(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/public", Action: policy.ActionPass, MaxBytes: 1 << 20},
		{PathPrefix: "/private", Action: policy.ActionPass, MaxBytes: 1 << 20},
	}})
	req := httptest.NewRequest(http.MethodPost, "/ignored", bytes.NewReader([]byte("not-an-image")))
	req.URL.Path = "/public/../private/a.jpg"
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	rig.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v body=%q", rec.Code, rig.origin.Hit(), rec.Body.String())
	}
	if got := rig.origin.Path(); got != "/private/a.jpg" {
		t.Fatalf("origin path %q, want /private/a.jpg", got)
	}
}
