package proxy_test

import (
	"image/color"
	"net/http"
	"testing"

	"redact-gateway/internal/policy"
	"redact-gateway/internal/testutil"
)

func jpegOnlyRoute(prefix string) policy.Route {
	return policy.Route{
		PathPrefix:      prefix,
		Action:          policy.ActionRedact,
		Detectors:       []string{"region-marker"},
		MaxBytes:        2 << 20,
		AcceptedFormats: []string{"jpeg"},
	}
}

func TestAcceptedFormatsJPEGAllowlistAcceptsJPEG(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{jpegOnlyRoute("/u")}})
	jpg := testutil.EncodeJPEG(testutil.SolidRGBA(16, 16, color.White), 90)
	rec := rig.doRaw(t, http.MethodPut, "/u/ok.jpg", "image/jpeg", jpg)
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("jpeg allowlist rejected jpeg: status=%d hit=%v body=%q", rec.Code, rig.origin.Hit(), rec.Body.String())
	}
}

func TestAcceptedFormatsJPEGAllowlist415sPNGNoLeak(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{jpegOnlyRoute("/u")}})
	secret := []byte("PNG-ALLOWLIST-SECRET")
	png := embedSecret(testutil.EncodePNG(testutil.SolidRGBA(16, 16, color.White)), secret)
	rec := rig.doRaw(t, http.MethodPut, "/u/no.png", "image/png", png)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("want 415 for png on jpeg allowlist, got %d body=%q", rec.Code, rec.Body.String())
	}
	if rig.origin.Hit() {
		t.Fatal("415 must not forward to origin")
	}
	assertNoSecretInResponse(t, rec, secret)
	assertAuditNoLeak(t, rig.audit.Bytes(), secret)
}

func TestEmptyAcceptedFormatsStillAcceptsJPEGAndPNG(t *testing.T) {
	jpg := testutil.EncodeJPEG(testutil.SolidRGBA(12, 12, color.White), 90)
	png := testutil.EncodePNG(testutil.SolidRGBA(12, 12, color.White))

	rigJ := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}})
	recJ := rigJ.doRaw(t, http.MethodPut, "/u/a.jpg", "image/jpeg", jpg)
	if recJ.Code != http.StatusOK || !rigJ.origin.Hit() {
		t.Fatalf("empty allowlist rejected jpeg: status=%d hit=%v", recJ.Code, rigJ.origin.Hit())
	}

	rigP := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}})
	recP := rigP.doRaw(t, http.MethodPut, "/u/a.png", "image/png", png)
	if recP.Code != http.StatusOK || !rigP.origin.Hit() {
		t.Fatalf("empty allowlist rejected png: status=%d hit=%v", recP.Code, rigP.origin.Hit())
	}
}
