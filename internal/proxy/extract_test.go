package proxy_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"image"
	"io"
	"mime"
	"mime/multipart"
	"testing"
	"time"

	"redact-gateway/internal/detect"
)

// extractAllFileParts returns the bodies of every multipart part that has a
// filename (a "file" part), in order.
func extractAllFileParts(t *testing.T, body []byte, contentType string) [][]byte {
	t.Helper()
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("parse content-type %q: %v", contentType, err)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var out [][]byte
	for {
		p, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		data, _ := io.ReadAll(p)
		if p.FileName() != "" {
			out = append(out, data)
		}
	}
	return out
}

func extractFirstFilePart(t *testing.T, body []byte, contentType string) []byte {
	t.Helper()
	parts := extractAllFileParts(t, body, contentType)
	if len(parts) == 0 {
		t.Fatal("no file parts in forwarded body")
	}
	return parts[0]
}

// extractFileFieldOrder returns the form-field names of file parts in the
// order they appear in the forwarded body.
func extractFileFieldOrder(t *testing.T, body []byte, contentType string) []string {
	t.Helper()
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("parse content-type: %v", err)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var names []string
	for {
		p, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		_, _ = io.ReadAll(p)
		if p.FileName() != "" {
			names = append(names, p.FormName())
		}
	}
	return names
}

// assertAuditNoLeak asserts the audit log does not contain the secret in raw,
// hex, or base64 form (the audit must never store original pixels).
func assertAuditNoLeak(t *testing.T, auditBytes, secret []byte) {
	t.Helper()
	forms := map[string][]byte{
		"raw":    secret,
		"hex":    []byte(hex.EncodeToString(secret)),
		"base64": []byte(base64.StdEncoding.EncodeToString(secret)),
	}
	for name, needle := range forms {
		if len(needle) == 0 {
			continue
		}
		if bytes.Contains(auditBytes, needle) {
			t.Fatalf("audit log leaked input bytes (%s form): %s", name, auditBytes)
		}
	}
}

// waitFor polls cond until true or a timeout, failing the test on timeout.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// --- detector registries for adversarial cases ------------------------------

type erroringDetector struct{ name string }

func (d *erroringDetector) Name() string { return d.name }
func (d *erroringDetector) Detect(context.Context, image.Image) ([]detect.Region, error) {
	return nil, errors.New("detector exploded")
}

func errRegistry() map[string]detect.Detector {
	return map[string]detect.Detector{"boom": &erroringDetector{name: "boom"}}
}

func mixedRegistry() map[string]detect.Detector {
	return map[string]detect.Detector{
		"region-marker": &detect.RegionMarkerDetector{Marker: markerColor, Tolerance: 16},
		"boom":          &erroringDetector{name: "boom"},
	}
}

// blockingDetector blocks in Detect until release is closed (or ctx is done),
// to hold a pool slot for backpressure / shutdown-race testing. After release
// it delegates to a real RegionMarkerDetector so the image is genuinely masked
// (the shutdown-race test asserts a fully sanitized body).
type blockingDetector struct {
	release <-chan struct{}
	inner   *detect.RegionMarkerDetector
}

func (d *blockingDetector) Name() string { return "blocking" }
func (d *blockingDetector) Detect(ctx context.Context, img image.Image) ([]detect.Region, error) {
	select {
	case <-d.release:
		return d.inner.Detect(ctx, img)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func blockingRegistry(release <-chan struct{}) map[string]detect.Detector {
	return map[string]detect.Detector{"region-marker": &blockingDetector{
		release: release,
		inner:   &detect.RegionMarkerDetector{Marker: markerColor, Tolerance: 16},
	}}
}
