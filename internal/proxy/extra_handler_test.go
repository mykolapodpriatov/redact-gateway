package proxy_test

import (
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"redact-gateway/internal/audit"
	"redact-gateway/internal/detect"
	"redact-gateway/internal/policy"
	"redact-gateway/internal/pool"
	"redact-gateway/internal/proxy"
	"redact-gateway/internal/testutil"
)

func TestNoRouteReturns502(t *testing.T) {
	// A policy with a single non-matching prefix and no default → no route.
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/specific", Action: policy.ActionRedact, Detectors: []string{"region-marker"}, MaxBytes: 1 << 20},
	}})
	rec := rig.doRaw(t, http.MethodPost, "/elsewhere", "image/png", []byte("x"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 for no route, got %d", rec.Code)
	}
	if rig.origin.Hit() {
		t.Fatal("no-route request should not reach origin")
	}
}

func TestRawBodyTooLarge413(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/o", Action: policy.ActionRedact, Detectors: []string{"region-marker"}, MaxBytes: 16},
	}})
	big := testutil.EncodePNG(testutil.SolidRGBA(64, 64, color.White)) // > 16 bytes
	rec := rig.doRaw(t, http.MethodPut, "/o/key", "image/png", big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 for oversize raw body, got %d", rec.Code)
	}
	if rig.origin.Hit() {
		t.Fatal("oversize raw body should not reach origin")
	}
}

func TestRawNonImagePassRouteVerbatim(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, MaxBytes: 1 << 20},
	}})
	doc := []byte("just some plain text, definitely not an image at all")
	rec := rig.doRaw(t, http.MethodPut, "/p/note.txt", "text/plain", doc)
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
	if string(rig.origin.Body()) != string(doc) {
		t.Fatalf("non-image pass body altered: %q", rig.origin.Body())
	}
}

func TestPassRoutePNGForwardedAudited(t *testing.T) {
	// A PNG on a pass route with strip_metadata: the PNG chunk-stripper runs,
	// but this PNG carries no metadata chunks, so stripping is a byte-identical
	// round-trip (only IHDR/IDAT/IEND survive, exactly what png.Encode emitted).
	// It is forwarded unmodified and audited as action=pass.
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, MaxBytes: 1 << 20},
	}})
	png := markerPNG(20, 20, image.Rect(2, 2, 6, 6))
	rec := rig.doRaw(t, http.MethodPut, "/p/a.png", "image/png", png)
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
	if string(rig.origin.Body()) != string(png) {
		t.Fatal("metadata-free pass-route PNG should round-trip unmodified")
	}
	if !strings.Contains(rig.audit.String(), `"action":"pass"`) {
		t.Fatalf("pass route PNG not audited: %s", rig.audit.String())
	}
}

// TestOriginBasePathJoined exercises singleJoin: an origin URL that itself has
// a base path must be joined with the request path with a single slash.
func TestOriginBasePathJoined(t *testing.T) {
	origin := newRecordingOrigin(t)
	base, _ := url.Parse(origin.server.URL + "/prefix")
	pol, _ := policy.New([]policy.Route{
		{PathPrefix: "/", Action: policy.ActionPass, MaxBytes: 1 << 20},
	})
	san := &proxy.Sanitizer{
		Registry:  map[string]detect.Detector{},
		Audit:     audit.NewLogger(&strings.Builder{}, audit.SystemClock{}),
		MaxPixels: 40_000_000,
	}
	h := proxy.New(proxy.Config{
		Origin:    base,
		Policy:    pol,
		Sanitizer: san,
		Pool:      pool.New(2, 0),
	})

	// Send a non-image so the pass route just forwards it.
	req := httptest.NewRequest(http.MethodPut, "/file.txt", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !origin.Hit() {
		t.Fatal("origin not hit")
	}
}
