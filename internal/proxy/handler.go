package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"redact-gateway/internal/imageproc"
	"redact-gateway/internal/intercept"
	"redact-gateway/internal/policy"
	"redact-gateway/internal/pool"
)

// sniffLen is how many leading bytes are examined for magic-byte
// classification. http.DetectContentType also reads at most 512 bytes.
const sniffLen = 512

// Handler is the inbound reverse proxy. It intercepts uploads, sanitizes image
// parts/bodies per policy (fail-closed by default), and forwards the sanitized
// payload to the origin. It NEVER forwards bytes it could not sanitize when the
// route required sanitization, and its own error responses contain only a short
// status string (no request or image bytes).
type Handler struct {
	origin    *url.URL
	policy    *policy.Policy
	sanitizer *Sanitizer
	pool      *pool.Pool
	client    *http.Client
}

// Config bundles the Handler dependencies.
type Config struct {
	// Origin is the upstream base URL the sanitized request is forwarded to.
	Origin *url.URL
	// Policy resolves a request path to a route.
	Policy *policy.Policy
	// Sanitizer performs per-item redaction.
	Sanitizer *Sanitizer
	// Pool bounds concurrent image jobs.
	Pool *pool.Pool
	// Client forwards the sanitized request upstream. Defaults to a client
	// with no timeout (the request context governs cancellation).
	Client *http.Client
}

// New constructs a Handler.
func New(cfg Config) *Handler {
	client := cfg.Client
	if client == nil {
		client = &http.Client{}
	}
	return &Handler{
		origin:    cfg.Origin,
		policy:    cfg.Policy,
		sanitizer: cfg.Sanitizer,
		pool:      cfg.Pool,
		client:    client,
	}
}

// writeStatus writes a gateway-own error response whose body is ONLY a short
// status string — never request, image, or upstream bytes. It also strips any
// risk of leaking via headers by setting just a plain content type.
func writeStatus(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, msg+"\n")
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := h.policy.Match(r.URL.Path)
	if !ok {
		// No route and no default: refuse rather than blind-forward.
		writeStatus(w, http.StatusBadGateway, "no route for path")
		return
	}

	ctx := r.Context()
	body, contentType, err := h.process(ctx, r, route)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Complete-or-nothing: only now, with a fully sanitized body in hand, do
	// we contact the origin.
	h.forward(w, r, body, contentType)
}

// process reads, classifies, and sanitizes the request body, returning the
// fully sanitized body bytes and the Content-Type to forward (with the
// original multipart boundary preserved). A non-nil error is a block/drop/413
// decision; the body is never partially produced.
func (h *Handler) process(ctx context.Context, r *http.Request, route policy.Route) (body []byte, contentType string, err error) {
	ct := r.Header.Get("Content-Type")
	if boundary, isMultipart := intercept.ParseBoundary(ct); isMultipart {
		return h.processMultipart(ctx, r, route, boundary, ct)
	}
	return h.processRaw(ctx, r, route, ct)
}

// processMultipart parses each part under the per-part cap, sanitizes image
// parts concurrently (results written back by original index), copies
// text/non-image parts verbatim, and re-serializes using the ORIGINAL boundary
// so the forwarded Content-Type's boundary= is unchanged.
func (h *Handler) processMultipart(ctx context.Context, r *http.Request, route policy.Route, boundary, ct string) ([]byte, string, error) {
	payload, err := intercept.ParseMultipart(r.Body, boundary, route.MaxBytes)
	if err != nil {
		if errors.Is(err, intercept.ErrTooLarge) {
			return nil, "", errTooLarge
		}
		return nil, "", newBlock("malformed multipart body")
	}

	// Sanitize each part concurrently; write outputs back by index.
	outputs := make([][]byte, len(payload.Parts))
	errs := make([]error, len(payload.Parts))
	var wg sync.WaitGroup
	for i := range payload.Parts {
		part := &payload.Parts[i]
		wg.Add(1)
		go func(idx int, p *intercept.Part) {
			defer wg.Done()
			out, perr := h.sanitizeItem(ctx, route, p.Body)
			outputs[idx] = out
			errs[idx] = perr
		}(i, part)
	}
	wg.Wait()

	// First non-nil error blocks the whole upload (origin gets nothing).
	for _, e := range errs {
		if e != nil {
			return nil, "", e
		}
	}

	// Substitute sanitized bodies back into the parts, then serialize with the
	// original boundary.
	for i := range payload.Parts {
		payload.Parts[i].Body = outputs[i]
	}
	serialized, err := payload.Serialize()
	if err != nil {
		return nil, "", newBlock("re-serialization failed")
	}
	return serialized, ct, nil
}

// processRaw reads a single non-multipart body under the cap and sanitizes it.
// The forwarded Content-Type is the original (the body is a single object).
func (h *Handler) processRaw(ctx context.Context, r *http.Request, route policy.Route, ct string) ([]byte, string, error) {
	raw, err := intercept.ReadRawBody(r.Body, route.MaxBytes)
	if err != nil {
		if errors.Is(err, intercept.ErrTooLarge) {
			return nil, "", errTooLarge
		}
		return nil, "", newBlock("body read failed")
	}
	out, perr := h.sanitizeItem(ctx, route, raw.Bytes)
	if perr != nil {
		return nil, "", perr
	}
	return out, ct, nil
}

// sanitizeItem classifies one item by magic bytes and runs it through the
// sanitizer under a pool slot (the per-image-job bound). Backpressure maps to a
// 503 sentinel; context cancellation maps to a block (origin gets nothing).
func (h *Handler) sanitizeItem(ctx context.Context, route policy.Route, data []byte) ([]byte, error) {
	isImage := sniffIsImage(data)

	// Only acquire a pool slot for work that actually decodes/encodes an image
	// (masking routes on image data). Verbatim pass-through of a non-image part
	// or a pass-route item is cheap and need not consume a slot.
	needsSlot := route.Action.Masks() && isImage
	if needsSlot {
		release, err := h.pool.Acquire(ctx)
		if err != nil {
			if errors.Is(err, pool.ErrBackpressure) || errors.Is(err, pool.ErrDraining) {
				return nil, errBackpressure
			}
			// Context canceled while waiting: block, never forward.
			return nil, newBlock("request canceled")
		}
		defer release()
	}

	res, err := h.sanitizer.SanitizeImage(ctx, route, data, isImage)
	if err != nil {
		return nil, err
	}
	return res.Output, nil
}

// forward sends the sanitized body to the origin and copies the origin's
// response back to the client. The forwarded request preserves the method,
// path, query, and most headers, sets a recomputed Content-Length, and uses
// the provided Content-Type (boundary preserved). The gateway's own failure to
// reach the origin yields a short 502 with no body bytes.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, body []byte, contentType string) {
	target := *h.origin
	target.Path = singleJoin(h.origin.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		writeStatus(w, http.StatusBadGateway, "upstream request build failed")
		return
	}
	copyHeaders(outReq.Header, r.Header)
	if contentType != "" {
		outReq.Header.Set("Content-Type", contentType)
	}
	outReq.Header.Del("Content-Length")
	outReq.ContentLength = int64(len(body))
	outReq.Header.Set("Content-Length", strconv.Itoa(len(body)))

	resp, err := h.client.Do(outReq)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// Client went away; nothing to write.
			return
		}
		writeStatus(w, http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// writeError maps a process error to the correct gateway status, always with a
// short byte-free body.
func (h *Handler) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTooLarge):
		writeStatus(w, http.StatusRequestEntityTooLarge, "payload too large")
	case errors.Is(err, errBackpressure):
		writeStatus(w, http.StatusServiceUnavailable, "server busy")
	case IsDrop(err):
		writeStatus(w, http.StatusUnprocessableEntity, "upload rejected")
	case IsBlock(err):
		writeStatus(w, http.StatusUnprocessableEntity, "upload blocked")
	default:
		writeStatus(w, http.StatusBadGateway, "gateway error")
	}
}

// Sentinel errors for status mapping. Their messages are never written to
// clients (writeError substitutes fixed short strings).
var (
	errTooLarge     = errors.New("proxy: payload too large")
	errBackpressure = errors.New("proxy: backpressure")
)

// sniffIsImage classifies by magic bytes (never Content-Type). It examines at
// most the leading sniffLen bytes.
func sniffIsImage(data []byte) bool {
	n := len(data)
	if n > sniffLen {
		n = sniffLen
	}
	return imageproc.SniffIsImage(data[:n])
}

// copyHeaders copies hop-by-hop-safe headers from src into dst. Hop-by-hop
// headers and Content-Length are skipped (Content-Length is recomputed by the
// caller; the body is re-buffered).
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func isHopByHop(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding",
		"Te", "Trailer", "Upgrade", "Content-Length":
		return true
	default:
		return false
	}
}

// singleJoin joins two URL path segments with exactly one slash.
func singleJoin(a, b string) string {
	switch {
	case a == "" || a == "/":
		return b
	case b == "":
		return a
	}
	aSlash := a[len(a)-1] == '/'
	bSlash := b[0] == '/'
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	default:
		return a + b
	}
}
