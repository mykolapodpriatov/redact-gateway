package proxy_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"image"
	"image/color"
	"image/png"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"redact-gateway/internal/policy"
	"redact-gateway/internal/testutil"
)

func redactRoute(prefix string) policy.Route {
	return policy.Route{
		PathPrefix: prefix,
		Action:     policy.ActionRedact,
		Detectors:  []string{"region-marker"},
		MaxBytes:   2 << 20,
	}
}

// --- Happy path: sanitized image reaches origin -----------------------------

func TestMultipartImageSanitizedAtOrigin(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/upload")}})
	rect := image.Rect(10, 10, 30, 30)
	img := markerPNG(64, 64, rect)

	rec := rig.doMultipart(t, "/upload", []filePart{
		{field: "file", filename: "a.png", content: img},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if !rig.origin.Hit() {
		t.Fatal("origin did not receive the sanitized upload")
	}

	// The origin's body is multipart; extract the file part and confirm the
	// masked region is now solid black (changed) while the background remains.
	sanitized := extractFirstFilePart(t, rig.origin.Body(), rig.origin.ContentType())
	mid := decodePixel(t, sanitized, 20, 20) // inside the masked rect
	r, g, b, _ := mid.RGBA()
	if r != 0 || g != 0 || b != 0 {
		t.Fatalf("masked region not blacked out: got %v", mid)
	}
	// The background corner must remain light (the mask only touched the marker
	// rectangle); a fully-decoded-and-checked corner is a stronger assertion
	// than scanning compressed bytes for the literal marker color.
	corner := decodePixel(t, sanitized, 0, 0)
	cr, cg, cb, _ := corner.RGBA()
	if cr>>8 < 200 || cg>>8 < 200 || cb>>8 < 200 {
		t.Fatalf("background corner unexpectedly dark: %v", corner)
	}
}

func TestMultipleFilesAllSanitized(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/upload")}})
	rectA := image.Rect(5, 5, 15, 15)
	rectB := image.Rect(20, 20, 35, 35)
	rec := rig.doMultipart(t, "/upload", []filePart{
		{field: "a", filename: "a.png", content: markerPNG(48, 48, rectA)},
		{field: "b", filename: "b.png", content: markerPNG(48, 48, rectB)},
	})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
	parts := extractAllFileParts(t, rig.origin.Body(), rig.origin.ContentType())
	if len(parts) != 2 {
		t.Fatalf("want 2 file parts at origin, got %d", len(parts))
	}
	// Both images masked: their marker regions are now black.
	if px := decodePixel(t, parts[0], 10, 10); !isBlack(px) {
		t.Fatalf("file a not masked at (10,10): %v", px)
	}
	if px := decodePixel(t, parts[1], 27, 27); !isBlack(px) {
		t.Fatalf("file b not masked at (27,27): %v", px)
	}
}

func TestMixedTextAndFileResplicedContentLengthAndBoundary(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/upload")}})
	textVal := []byte("hello-text-field-value")
	rec := rig.doMultipart(t, "/upload", []filePart{
		{field: "caption", content: textVal},
		{field: "file", filename: "p.png", content: markerPNG(40, 40, image.Rect(5, 5, 12, 12))},
		{field: "tag", content: []byte("vacation")},
	})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v body=%q", rec.Code, rig.origin.Hit(), rec.Body.String())
	}

	body := rig.origin.Body()
	ct := rig.origin.ContentType()

	// The forwarded Content-Type must preserve the ORIGINAL boundary verbatim.
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("origin content-type parse: %v", err)
	}
	gotBoundary := params["boundary"]
	if gotBoundary == "" || !bytes.Contains(body, []byte("--"+gotBoundary)) {
		t.Fatalf("forwarded body does not use the declared boundary %q", gotBoundary)
	}

	// Text parts must be copied verbatim.
	if !bytes.Contains(body, textVal) {
		t.Fatal("text caption not forwarded verbatim")
	}
	if !bytes.Contains(body, []byte("vacation")) {
		t.Fatal("text tag not forwarded verbatim")
	}

	// The outer Content-Length the origin received must equal the actual
	// re-spliced body length (the forward path recomputes it from the buffered
	// body, never trusting the inbound length).
	if !contentLengthMatches(rig.origin.ContentLength(), body) {
		t.Fatalf("outer Content-Length %q does not match re-spliced body length %d",
			rig.origin.ContentLength(), len(body))
	}
}

func TestNonImagePartPassesThroughVerbatim(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/upload")}})
	doc := []byte("%PDF-1.4 not really a pdf but definitely not an image")
	rec := rig.doMultipart(t, "/upload", []filePart{
		{field: "doc", filename: "d.bin", content: doc},
	})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
	if !bytes.Contains(rig.origin.Body(), doc) {
		t.Fatal("non-image part not forwarded verbatim")
	}
}

func TestThreeImagesArriveInOriginalOrder(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/upload")}, poolSize: 3})
	// Distinguish images by a marker at a different unique location each.
	mk := func(loc int) []byte {
		return markerPNG(60, 60, image.Rect(loc, loc, loc+6, loc+6))
	}
	rec := rig.doMultipart(t, "/upload", []filePart{
		{field: "first", filename: "1.png", content: mk(2)},
		{field: "second", filename: "2.png", content: mk(20)},
		{field: "third", filename: "3.png", content: mk(40)},
	})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
	names := extractFileFieldOrder(t, rig.origin.Body(), rig.origin.ContentType())
	want := []string{"first", "second", "third"}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("parts out of order: got %v want %v", names, want)
	}
}

// --- Presigned raw PUT ------------------------------------------------------

func TestRawPutBodySanitized(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/object")}})
	img := markerJPEG(50, 50, image.Rect(10, 10, 25, 25))
	rec := rig.doRaw(t, http.MethodPut, "/object/key.jpg", "image/jpeg", img)
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("status=%d hit=%v body=%q", rec.Code, rig.origin.Hit(), rec.Body.String())
	}
	// Origin body is the raw sanitized JPEG; masked region must be dark.
	if px := decodePixel(t, rig.origin.Body(), 17, 17); !isDarkish(px) {
		t.Fatalf("raw PUT masked region not dark: %v", px)
	}
}

// --- Fail-closed / no-leak adversarial set ----------------------------------

// assertBlockedNoLeak asserts the origin got nothing and that no original
// bytes appear in the gateway's own response (body or headers).
func assertBlockedNoLeak(t *testing.T, rec *httptest.ResponseRecorder, origin *recordingOrigin, secret []byte) {
	t.Helper()
	if origin.Hit() {
		t.Fatal("FAIL-CLOSED VIOLATION: origin received bytes")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("expected a non-200 block status, got %d", rec.Code)
	}
	assertNoSecretInResponse(t, rec, secret)
}

func assertNoSecretInResponse(t *testing.T, rec *httptest.ResponseRecorder, secret []byte) {
	t.Helper()
	respBody := rec.Body.Bytes()
	forms := map[string][]byte{
		"raw":    secret,
		"hex":    []byte(hex.EncodeToString(secret)),
		"base64": []byte(base64.StdEncoding.EncodeToString(secret)),
	}
	for name, needle := range forms {
		if len(needle) == 0 {
			continue
		}
		if bytes.Contains(respBody, needle) {
			t.Fatalf("gateway error body leaked input bytes (%s form)", name)
		}
		for k, vv := range rec.Header() {
			for _, v := range vv {
				if bytes.Contains([]byte(v), needle) {
					t.Fatalf("gateway error header %q leaked input bytes (%s form)", k, name)
				}
			}
		}
	}
	// The error body must be short (a status string), never a whole image.
	if len(respBody) > 256 {
		t.Fatalf("gateway error body too long (%d bytes) — may contain image data", len(respBody))
	}
}

func TestDetectorErrorBlocksNoLeak(t *testing.T) {
	secret := []byte("DETECTOR-ERR-SECRET-PIXELS")
	img := embedSecret(markerPNG(40, 40, image.Rect(5, 5, 10, 10)), secret)
	rig := newRig(t, rigOptions{
		routes:   []policy.Route{{PathPrefix: "/u", Action: policy.ActionRedact, Detectors: []string{"boom"}, MaxBytes: 2 << 20}},
		registry: errRegistry(),
	})
	rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.png", content: img}})
	assertBlockedNoLeak(t, rec, rig.origin, secret)
	assertAuditNoLeak(t, rig.audit.Bytes(), secret)
}

func TestUndecodableImageBlocked(t *testing.T) {
	// Bytes that sniff as PNG (magic) but are not a valid PNG → decode fails.
	secret := []byte("UNDECODABLE-SECRET")
	bad := append([]byte("\x89PNG\r\n\x1a\n"), secret...)
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}})
	rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.png", content: bad}})
	assertBlockedNoLeak(t, rec, rig.origin, secret)
	assertAuditNoLeak(t, rig.audit.Bytes(), secret)
}

func TestUnsupportedFormatOnRedactBlocked(t *testing.T) {
	// A real GIF (sniffs as an image) on a redact route MUST be blocked, not
	// passed through.
	secret := []byte("GIF-SECRET-PIXELS")
	gif := append([]byte("GIF89a\x10\x00\x10\x00\x80\x00\x00"), secret...)
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}})
	rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.gif", content: gif}})
	assertBlockedNoLeak(t, rec, rig.origin, secret)
}

func TestReEncodeFailureBlocked(t *testing.T) {
	secret := []byte("REENCODE-FAIL-SECRET")
	img := embedSecret(markerPNG(40, 40, image.Rect(5, 5, 10, 10)), secret)
	rig := newRig(t, rigOptions{
		routes: []policy.Route{redactRoute("/u")},
		encode: failEncode, // forces re-encode failure
	})
	rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.png", content: img}})
	assertBlockedNoLeak(t, rec, rig.origin, secret)
	assertAuditNoLeak(t, rig.audit.Bytes(), secret)
}

func TestMidDetectorFailureBlocks(t *testing.T) {
	// Two detectors: one finds regions, a later one errors. The whole upload
	// must be blocked (fail-closed), origin gets nothing.
	secret := []byte("MID-DETECTOR-SECRET")
	img := embedSecret(markerPNG(40, 40, image.Rect(5, 5, 10, 10)), secret)
	rig := newRig(t, rigOptions{
		routes:   []policy.Route{{PathPrefix: "/u", Action: policy.ActionRedact, Detectors: []string{"region-marker", "boom"}, MaxBytes: 2 << 20}},
		registry: mixedRegistry(),
	})
	rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.png", content: img}})
	assertBlockedNoLeak(t, rec, rig.origin, secret)
}

func TestClientDisconnectOriginGetsNothing(t *testing.T) {
	secret := []byte("DISCONNECT-SECRET")
	img := embedSecret(markerJPEG(40, 40, image.Rect(5, 5, 10, 10)), secret)
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}})

	body, boundary := buildMultipart(t, []filePart{{field: "f", filename: "f.jpg", content: img}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-canceled context simulates a vanished client
	req := httptest.NewRequest(http.MethodPost, "/u", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	rec := httptest.NewRecorder()
	rig.handler.ServeHTTP(rec, req)

	if rig.origin.Hit() {
		t.Fatal("origin received bytes after client disconnect")
	}
	assertAuditNoLeak(t, rig.audit.Bytes(), secret)
}

func TestDropRejected(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{{PathPrefix: "/d", Action: policy.ActionDrop, MaxBytes: 2 << 20}}})
	rec := rig.doMultipart(t, "/d", []filePart{{field: "f", filename: "f.png", content: markerPNG(20, 20, image.Rect(2, 2, 5, 5))}})
	if rig.origin.Hit() {
		t.Fatal("drop route forwarded to origin")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("drop should not return 200, got %d", rec.Code)
	}
}

func TestPerPartMaxBytes413(t *testing.T) {
	// One small part and one part exceeding MaxBytes; total body might be
	// small-ish but the single oversize part must yield 413.
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/u", Action: policy.ActionRedact, Detectors: []string{"region-marker"}, MaxBytes: 1024},
	}})
	big := bytes.Repeat([]byte("X"), 4096) // > 1024 cap
	rec := rig.doMultipart(t, "/u", []filePart{
		{field: "small", content: []byte("ok")},
		{field: "big", filename: "big.bin", content: big},
	})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if rig.origin.Hit() {
		t.Fatal("oversize part should not reach origin")
	}
}

func TestDecompressionBombBlocked(t *testing.T) {
	secret := []byte("BOMB-SECRET")
	bomb := embedSecret(testutil.JPEGBomb(60000, 60000), secret)
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}})
	rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.jpg", content: bomb}})
	assertBlockedNoLeak(t, rec, rig.origin, secret)
}

func TestTruncatedJPEGBlocked(t *testing.T) {
	trunc := testutil.TruncatedJPEG()
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}})
	rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.jpg", content: trunc}})
	if rig.origin.Hit() {
		t.Fatal("truncated JPEG reached origin (must be blocked or full, never partial)")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("truncated JPEG should be blocked, got %d", rec.Code)
	}
}

// --- Pass route -------------------------------------------------------------

func TestPassRouteStripsMetadataAndAudits(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, MaxBytes: 2 << 20},
	}})
	withMeta := testutil.JPEGWithMetadata(testutil.MetaOptions{
		EXIF: true, IPTC: true, COM: true, ThumbnailMarker: []byte("THUMB-LEAK-XYZ"),
	})
	rec := rig.doMultipart(t, "/p", []filePart{{field: "f", filename: "f.jpg", content: withMeta}})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("pass route status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
	fwd := extractFirstFilePart(t, rig.origin.Body(), rig.origin.ContentType())
	if testutil.HasSegment(fwd, 0xE1) || testutil.HasSegment(fwd, 0xED) || testutil.HasSegment(fwd, 0xFE) {
		t.Fatal("pass route forwarded metadata segments (not stripped)")
	}
	if bytes.Contains(fwd, []byte("THUMB-LEAK-XYZ")) {
		t.Fatal("pass route leaked embedded thumbnail")
	}
	// Audit recorded the pass action.
	if !bytes.Contains(rig.audit.Bytes(), []byte(`"action":"pass"`)) {
		t.Fatalf("pass route not audited: %s", rig.audit.String())
	}
}

func TestPassRouteStripErrorBlocked(t *testing.T) {
	// A malformed JPEG (sniffs as JPEG via magic bytes) on a pass route with
	// strip_metadata must be BLOCKED when the strip errors.
	secret := []byte("STRIP-ERR-SECRET")
	// FFD8 SOI then a bogus APP1 length that overruns → exif.Strip errors.
	bad := append([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFE}, secret...)
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, MaxBytes: 2 << 20},
	}})
	rec := rig.doMultipart(t, "/p", []filePart{{field: "f", filename: "f.jpg", content: bad}})
	if rig.origin.Hit() {
		t.Fatal("pass+strip-error forwarded to origin (privacy leak)")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("pass+strip-error should be blocked, got %d", rec.Code)
	}
	assertNoSecretInResponse(t, rec, secret)
}

func TestPassRouteFailOpenForwardsOnStripError(t *testing.T) {
	// With fail_open=true the same strip error forwards the ORIGINAL bytes
	// (documented unsafe behavior).
	bad := append([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFE}, []byte("payload")...)
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, FailOpen: true, MaxBytes: 2 << 20},
	}})
	rec := rig.doMultipart(t, "/p", []filePart{{field: "f", filename: "f.jpg", content: bad}})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("fail-open pass should forward, status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
}

func TestPassRoutePNGStripsMetadataChunks(t *testing.T) {
	// A pre-existing PNG carrying eXIf (GPS) and tEXt chunks on a
	// pass+strip_metadata route must be forwarded with NEITHER chunk, and the
	// forwarded bytes must still decode as a PNG.
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, MaxBytes: 2 << 20},
	}})
	withMeta := testutil.PNGWithMetadata()
	rec := rig.doMultipart(t, "/p", []filePart{{field: "f", filename: "f.png", content: withMeta}})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("pass route status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
	fwd := extractFirstFilePart(t, rig.origin.Body(), rig.origin.ContentType())
	if testutil.HasPNGChunk(fwd, "eXIf") || testutil.HasPNGChunk(fwd, "tEXt") {
		t.Fatal("pass route forwarded PNG metadata chunks (not stripped)")
	}
	if bytes.Contains(fwd, []byte("FAKE-PNG-GPS")) || bytes.Contains(fwd, []byte("PNG-TEXT-SECRET")) {
		t.Fatal("pass route leaked PNG metadata payload")
	}
	if _, err := png.Decode(bytes.NewReader(fwd)); err != nil {
		t.Fatalf("forwarded PNG no longer decodes: %v", err)
	}
}

func TestPassRouteUnstrippableImageFormatBlocked(t *testing.T) {
	// A GIF (sniffs as an image, but the gateway cannot strip its metadata) on a
	// pass+strip_metadata route that is NOT fail_open must be blocked: the
	// origin receives nothing.
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, MaxBytes: 2 << 20},
	}})
	g := testutil.EncodeGIF(testutil.SolidRGBA(8, 8, nil))
	rec := rig.doMultipart(t, "/p", []filePart{{field: "f", filename: "f.gif", content: g}})
	if rig.origin.Hit() {
		t.Fatal("unstrippable image on pass+strip_metadata reached origin (privacy leak)")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("unstrippable image on pass+strip_metadata should be blocked, got %d", rec.Code)
	}
}

func TestPassRouteUnstrippableImageFailOpenForwards(t *testing.T) {
	// The same GIF on a fail_open pass+strip_metadata route forwards verbatim
	// (documented unsafe behavior).
	rig := newRig(t, rigOptions{routes: []policy.Route{
		{PathPrefix: "/p", Action: policy.ActionPass, StripMetadata: true, FailOpen: true, MaxBytes: 2 << 20},
	}})
	g := testutil.EncodeGIF(testutil.SolidRGBA(8, 8, nil))
	rec := rig.doMultipart(t, "/p", []filePart{{field: "f", filename: "f.gif", content: g}})
	if rec.Code != http.StatusOK || !rig.origin.Hit() {
		t.Fatalf("fail-open pass should forward unstrippable image, status=%d hit=%v", rec.Code, rig.origin.Hit())
	}
}

// --- Backpressure -----------------------------------------------------------

func TestBackpressure503(t *testing.T) {
	// Pool size 1, zero acquire timeout via a tiny value, and a detector that
	// blocks so the slot stays held while a second request tries to acquire.
	release := make(chan struct{})
	rig := newRig(t, rigOptions{
		routes:    []policy.Route{redactRoute("/u")},
		registry:  blockingRegistry(release),
		poolSize:  1,
		acquireTO: 30_000_000, // 30ms
	})
	img := markerPNG(40, 40, image.Rect(5, 5, 10, 10))

	// First request occupies the single slot (blocks in the detector).
	firstDone := make(chan int, 1)
	go func() {
		rec := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.png", content: img}})
		firstDone <- rec.Code
	}()

	// Give the first request time to acquire the slot and enter the detector.
	waitFor(t, func() bool { return rig.pool.InFlight() == 1 })

	// Second request cannot get a slot within the acquire timeout → 503.
	rec2 := rig.doMultipart(t, "/u", []filePart{{field: "f", filename: "f.png", content: img}})
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 under backpressure, got %d", rec2.Code)
	}

	close(release) // let the first request finish
	<-firstDone
}

// --- helpers for assembling secrets and registries are in helper_test.go and
// below ---------------------------------------------------------------------

func isBlack(c color.Color) bool {
	r, g, b, _ := c.RGBA()
	return r == 0 && g == 0 && b == 0
}

func isDarkish(c color.Color) bool {
	r, g, b, _ := c.RGBA()
	return (r>>8) < 64 && (g>>8) < 64 && (b>>8) < 64
}

// embedSecret appends a recognizable marker to image bytes so tests can assert
// it never leaks. It is appended after the valid image data (PNG/JPEG ignore
// trailing bytes for our purposes, and decode still works for valid images).
func embedSecret(img, secret []byte) []byte {
	return append(append([]byte(nil), img...), secret...)
}

// contentLengthMatches confirms a forwarded body's declared length equals its
// actual length, when a Content-Length is present.
func contentLengthMatches(headerVal string, body []byte) bool {
	if headerVal == "" {
		return true
	}
	n, err := strconv.Atoi(strings.TrimSpace(headerVal))
	if err != nil {
		return false
	}
	return n == len(body)
}
