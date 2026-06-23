package proxy_test

import (
	"bytes"
	"image"
	"image/color"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"sync"
	"testing"
	"time"

	"redact-gateway/internal/audit"
	"redact-gateway/internal/detect"
	"redact-gateway/internal/imageproc"
	"redact-gateway/internal/policy"
	"redact-gateway/internal/pool"
	"redact-gateway/internal/proxy"
	"redact-gateway/internal/testutil"
)

// markerColor is the magenta zone color the RegionMarkerDetector looks for.
var markerColor = color.RGBA{R: 255, G: 0, B: 255, A: 255}

// recordingOrigin is a fake upstream that captures whether it was hit and the
// exact bytes/headers it received. For fail-closed assertions the test checks
// Hit() is false (origin received NOTHING).
type recordingOrigin struct {
	mu            sync.Mutex
	hit           bool
	body          []byte
	contentType   string
	contentLength string
	server        *httptest.Server
}

func newRecordingOrigin(t *testing.T) *recordingOrigin {
	t.Helper()
	o := &recordingOrigin{}
	o.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		o.mu.Lock()
		o.hit = true
		o.body = b
		o.contentType = r.Header.Get("Content-Type")
		o.contentLength = r.Header.Get("Content-Length")
		o.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "stored")
	}))
	t.Cleanup(o.server.Close)
	return o
}

func (o *recordingOrigin) Hit() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hit
}

func (o *recordingOrigin) Body() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte(nil), o.body...)
}

func (o *recordingOrigin) ContentType() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.contentType
}

func (o *recordingOrigin) ContentLength() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.contentLength
}

// testRig bundles a handler, its origin, and its audit buffer for assertions.
type testRig struct {
	handler *proxy.Handler
	origin  *recordingOrigin
	audit   *bytes.Buffer
	pool    *pool.Pool
}

// rigOptions configures the handler under test.
type rigOptions struct {
	routes    []policy.Route
	registry  map[string]detect.Detector
	encode    proxy.EncodeFunc
	poolSize  int
	acquireTO time.Duration
	maxPixels int64
}

func newRig(t *testing.T, opts rigOptions) *testRig {
	t.Helper()
	origin := newRecordingOrigin(t)
	originURL, err := url.Parse(origin.server.URL)
	if err != nil {
		t.Fatalf("parse origin url: %v", err)
	}
	pol, err := policy.New(opts.routes)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	reg := opts.registry
	if reg == nil {
		reg = map[string]detect.Detector{
			"region-marker": &detect.RegionMarkerDetector{Marker: markerColor, Tolerance: 16},
		}
	}
	auditBuf := &bytes.Buffer{}
	maxPixels := opts.maxPixels
	if maxPixels == 0 {
		maxPixels = 40_000_000
	}
	san := &proxy.Sanitizer{
		Registry:    reg,
		Audit:       audit.NewLogger(auditBuf, audit.SystemClock{}),
		Encode:      opts.encode,
		MaxPixels:   maxPixels,
		JPEGQuality: 90,
		BlurRadius:  4,
	}
	size := opts.poolSize
	if size == 0 {
		size = 4
	}
	to := opts.acquireTO
	if to == 0 {
		to = 2 * time.Second
	}
	wp := pool.New(size, to)
	h := proxy.New(proxy.Config{
		Origin:    originURL,
		Policy:    pol,
		Sanitizer: san,
		Pool:      wp,
	})
	return &testRig{handler: h, origin: origin, audit: auditBuf, pool: wp}
}

// markerPNG builds a PNG with a magenta marker rectangle the detector will find.
func markerPNG(w, h int, rect image.Rectangle) []byte {
	return testutil.MarkerImagePNG(w, h, color.RGBA{R: 240, G: 240, B: 240, A: 255}, markerColor, rect)
}

// markerJPEG builds a JPEG with a magenta marker rectangle.
func markerJPEG(w, h int, rect image.Rectangle) []byte {
	img := testutil.WithRect(testutil.SolidRGBA(w, h, color.RGBA{R: 240, G: 240, B: 240, A: 255}), rect, markerColor)
	return testutil.EncodeJPEG(img, 95)
}

// filePart describes one multipart part.
type filePart struct {
	field    string
	filename string // empty => a plain text field
	content  []byte
	header   textproto.MIMEHeader // optional extra headers
}

// buildMultipart serializes parts into a multipart/form-data body, returning
// the body bytes and the boundary.
func buildMultipart(t *testing.T, parts []filePart) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		hdr := textproto.MIMEHeader{}
		if p.filename != "" {
			hdr.Set("Content-Disposition",
				`form-data; name="`+p.field+`"; filename="`+p.filename+`"`)
			hdr.Set("Content-Type", "application/octet-stream")
		} else {
			hdr.Set("Content-Disposition", `form-data; name="`+p.field+`"`)
		}
		for k, vv := range p.header {
			for _, v := range vv {
				hdr.Add(k, v)
			}
		}
		pw, err := w.CreatePart(hdr)
		if err != nil {
			t.Fatalf("create part: %v", err)
		}
		if _, err := pw.Write(p.content); err != nil {
			t.Fatalf("write part: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes(), w.Boundary()
}

// doMultipart sends a multipart POST through the handler and returns the
// response recorder.
func (rig *testRig) doMultipart(t *testing.T, path string, parts []filePart) *httptest.ResponseRecorder {
	t.Helper()
	body, boundary := buildMultipart(t, parts)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	rec := httptest.NewRecorder()
	rig.handler.ServeHTTP(rec, req)
	return rec
}

// doRaw sends a raw (non-multipart) body through the handler.
func (rig *testRig) doRaw(t *testing.T, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	rig.handler.ServeHTTP(rec, req)
	return rec
}

// failEncode is an EncodeFunc that always errors, to force the re-encode
// fail-closed path.
func failEncode(image.Image, imageproc.Format, imageproc.EncodeOptions) ([]byte, error) {
	return nil, io.ErrClosedPipe
}

// decodePNGRegion is a helper to read a pixel from PNG/JPEG bytes for the
// "masked region differs" assertion.
func decodePixel(t *testing.T, data []byte, x, y int) color.Color {
	t.Helper()
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode for pixel check: %v", err)
	}
	return img.At(x, y)
}
