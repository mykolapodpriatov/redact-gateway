package intercept

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strconv"
)

// Part is one parsed multipart part: its original MIME header (preserved
// verbatim on re-serialization) and its body bytes (read under the per-part
// cap). Index records the original ordinal position so concurrently-processed
// parts can be reassembled in the original order.
type Part struct {
	Index  int
	Header textproto.MIMEHeader
	Body   []byte
	// FormName and FileName are convenience copies parsed from the
	// Content-Disposition header (may be empty).
	FormName string
	FileName string
}

// MultipartPayload is a fully-parsed multipart/form-data body: the ordered
// parts and the boundary token, which MUST be reused verbatim when
// re-serializing so the forwarded Content-Type's boundary= parameter is
// unchanged.
type MultipartPayload struct {
	Boundary string
	Parts    []Part
}

// ParseBoundary extracts the boundary token from a multipart Content-Type
// header value. It returns ("", false) if the media type is not multipart or
// lacks a boundary.
func ParseBoundary(contentType string) (string, bool) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false
	}
	if mediaType != "multipart/form-data" && mediaType != "multipart/mixed" {
		return "", false
	}
	b, ok := params["boundary"]
	if !ok || b == "" {
		return "", false
	}
	return b, true
}

// ParseMultipart reads every part of a multipart body under a per-part size
// cap. Each individual part is capped at maxBytesPerPart (NOT just the outer
// body), so N parts each just under the cap cannot consume N*cap unbounded.
// The original boundary is captured for verbatim re-serialization. A part that
// exceeds the cap returns ErrTooLarge.
func ParseMultipart(body io.Reader, boundary string, maxBytesPerPart int64) (*MultipartPayload, error) {
	mr := multipart.NewReader(body, boundary)
	payload := &MultipartPayload{Boundary: boundary}
	idx := 0
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("intercept: read part %d: %w", idx, err)
		}
		data, rerr := readLimited(part, maxBytesPerPart)
		// Close the part before handling errors so resources are released.
		_ = part.Close()
		if rerr != nil {
			return nil, rerr
		}
		// Copy the header so later mutation of Content-Length does not alias
		// the reader's internal map.
		hdr := make(textproto.MIMEHeader, len(part.Header))
		for k, v := range part.Header {
			cp := make([]string, len(v))
			copy(cp, v)
			hdr[k] = cp
		}
		payload.Parts = append(payload.Parts, Part{
			Index:    idx,
			Header:   hdr,
			Body:     data,
			FormName: part.FormName(),
			FileName: part.FileName(),
		})
		idx++
	}
	return payload, nil
}

// Serialize writes the parts back into a multipart body using the ORIGINAL
// boundary token (so the forwarded Content-Type boundary= matches), preserving
// each part's original header and writing the parts in ascending Index order.
// Any per-part Content-Length header is recomputed to the (possibly rewritten)
// body length. It returns the serialized bytes; the caller sets the outer
// Content-Length from len(result).
func (m *MultipartPayload) Serialize() ([]byte, error) {
	// Order parts by Index defensively (callers fill a slice by index, but be
	// robust to any ordering).
	ordered := make([]*Part, len(m.Parts))
	for i := range m.Parts {
		p := &m.Parts[i]
		if p.Index < 0 || p.Index >= len(ordered) {
			return nil, fmt.Errorf("intercept: part index %d out of range", p.Index)
		}
		if ordered[p.Index] != nil {
			return nil, fmt.Errorf("intercept: duplicate part index %d", p.Index)
		}
		ordered[p.Index] = p
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(m.Boundary); err != nil {
		return nil, fmt.Errorf("intercept: set boundary: %w", err)
	}
	for i, p := range ordered {
		if p == nil {
			return nil, fmt.Errorf("intercept: missing part at index %d", i)
		}
		hdr := cloneHeader(p.Header)
		// Recompute any per-part Content-Length to the new body size.
		if _, ok := hdr["Content-Length"]; ok {
			hdr.Set("Content-Length", strconv.Itoa(len(p.Body)))
		}
		pw, err := w.CreatePart(hdr)
		if err != nil {
			return nil, fmt.Errorf("intercept: create part %d: %w", i, err)
		}
		if _, err := pw.Write(p.Body); err != nil {
			return nil, fmt.Errorf("intercept: write part %d: %w", i, err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("intercept: close writer: %w", err)
	}
	return buf.Bytes(), nil
}

func cloneHeader(h textproto.MIMEHeader) textproto.MIMEHeader {
	out := make(textproto.MIMEHeader, len(h))
	for k, v := range h {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}
