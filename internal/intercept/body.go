// Package intercept reads inbound upload payloads into memory under strict
// per-part size limits so the redaction pipeline can inspect and rewrite them.
// It handles two request shapes: multipart/form-data (each part read
// separately, capped individually) and a raw single-object body (PUT or
// non-multipart POST). Classification of which parts are images is done later
// by magic-byte sniffing, never by Content-Type.
package intercept

import (
	"errors"
	"fmt"
	"io"
)

// ErrTooLarge indicates a part or body exceeded the configured per-item size
// cap. The proxy maps it to HTTP 413. It is deliberately distinct from a
// generic read error so the handler can choose the right status.
var ErrTooLarge = errors.New("intercept: payload exceeds size limit")

// readLimited reads up to max bytes from r and returns them. If r yields more
// than max bytes it returns ErrTooLarge (without buffering the overflow). A
// max <= 0 is treated as "no data allowed" to avoid an accidental unbounded
// read; callers always pass a positive cap.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, ErrTooLarge
	}
	// Read one extra byte to detect overflow deterministically.
	limited := io.LimitReader(r, max+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("intercept: read: %w", err)
	}
	if int64(len(buf)) > max {
		return nil, ErrTooLarge
	}
	return buf, nil
}

// RawBody is a single non-multipart upload body read under a size cap.
type RawBody struct {
	// Bytes is the full body (<= max).
	Bytes []byte
}

// ReadRawBody reads an entire non-multipart request body under the per-body
// cap maxBytes. It returns ErrTooLarge if the body exceeds the cap.
func ReadRawBody(r io.Reader, maxBytes int64) (*RawBody, error) {
	b, err := readLimited(r, maxBytes)
	if err != nil {
		return nil, err
	}
	return &RawBody{Bytes: b}, nil
}
