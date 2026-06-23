package proxy_test

import (
	"bytes"
	"context"
	"image"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"redact-gateway/internal/policy"
)

// TestShutdownRaceCompleteOrNothing asserts that when a redaction job is
// in-flight and the pool is drained, the origin receives either a COMPLETE
// sanitized body or nothing — never a partial/unsanitized body. Because the
// handler buffers the entire sanitized body before contacting the origin, a
// completing job delivers the whole masked image atomically.
func TestShutdownRaceCompleteOrNothing(t *testing.T) {
	release := make(chan struct{})
	rig := newRig(t, rigOptions{
		routes:   []policy.Route{redactRoute("/u")},
		registry: blockingRegistry(release),
		poolSize: 1,
	})
	img := markerPNG(48, 48, image.Rect(6, 6, 18, 18))

	body, boundary := buildMultipart(t, []filePart{{field: "f", filename: "f.png", content: img}})
	req := httptest.NewRequest(http.MethodPost, "/u", bytes.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	rec := httptest.NewRecorder()

	reqDone := make(chan struct{})
	go func() {
		rig.handler.ServeHTTP(rec, req)
		close(reqDone)
	}()

	// Wait until the job holds the single slot (it is parked in the detector).
	waitFor(t, func() bool { return rig.pool.InFlight() == 1 })

	// Begin draining with a generous deadline, in a goroutine.
	drainErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		drainErr <- rig.pool.Drain(ctx)
	}()

	// Let the in-flight job finish; drain should then complete and the request
	// should deliver a full sanitized body to the origin.
	close(release)

	select {
	case err := <-drainErr:
		if err != nil {
			t.Fatalf("drain returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not complete")
	}

	select {
	case <-reqDone:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not complete")
	}

	if !rig.origin.Hit() {
		t.Fatal("origin received nothing for a completing job")
	}
	// Complete-or-nothing: the forwarded body must be a COMPLETE, parseable
	// multipart whose image part is fully masked (not a truncated stream).
	fwd := extractFirstFilePart(t, rig.origin.Body(), rig.origin.ContentType())
	if px := decodePixel(t, fwd, 12, 12); !isBlack(px) {
		t.Fatalf("forwarded image not fully sanitized: %v", px)
	}
}

// TestShutdownRejectsNewJobs asserts that once draining starts, a new masking
// request is refused (503) rather than admitted — and the origin never sees it.
func TestShutdownRejectsNewJobs(t *testing.T) {
	rig := newRig(t, rigOptions{routes: []policy.Route{redactRoute("/u")}, poolSize: 1})

	// Drain immediately (no in-flight work) so the pool is closed.
	if err := rig.pool.Drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	rec := rig.doMultipart(t, "/u", []filePart{
		{field: "f", filename: "f.png", content: markerPNG(20, 20, image.Rect(2, 2, 6, 6))},
	})
	if rig.origin.Hit() {
		t.Fatal("a draining pool admitted a job to the origin")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 from a draining pool, got %d", rec.Code)
	}
}
