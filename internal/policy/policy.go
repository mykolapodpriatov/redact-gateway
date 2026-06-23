// Package policy maps request paths to a redaction Action and the per-route
// safety settings (fail-open opt-in, per-part size cap, metadata stripping,
// detector selection). Matching is longest-prefix and deterministic.
package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Action is what the gateway does to an image on a matched route.
type Action string

const (
	// ActionRedact masks the union of detected regions with a solid box, then
	// re-encodes.
	ActionRedact Action = "redact"
	// ActionBlur masks the union of detected regions with a box blur, then
	// re-encodes.
	ActionBlur Action = "blur"
	// ActionDrop rejects the whole upload with a clear status.
	ActionDrop Action = "drop"
	// ActionPass performs no masking but still strips metadata (if enabled)
	// and writes an audit entry.
	ActionPass Action = "pass"
)

// Valid reports whether a is a recognized action.
func (a Action) Valid() bool {
	switch a {
	case ActionRedact, ActionBlur, ActionDrop, ActionPass:
		return true
	default:
		return false
	}
}

// Masks reports whether the action decodes and re-encodes the image (redact or
// blur). Drop and pass do not.
func (a Action) Masks() bool {
	return a == ActionRedact || a == ActionBlur
}

// Route is a single policy rule. PathPrefix is matched longest-first against
// the request path; Action is applied to the union of all detector regions;
// Detectors names which configured detectors run; FailOpen, when true, lets
// the route forward original bytes on a sanitize failure (UNSAFE, default
// false); MaxBytes caps each individual part/body (per-part, not just outer);
// StripMetadata removes EXIF/IPTC/COM from forwarded original bytes.
type Route struct {
	PathPrefix    string
	Action        Action
	Detectors     []string
	FailOpen      bool
	MaxBytes      int64
	StripMetadata bool
}

// Policy is the ordered set of routes plus a default applied when no route
// prefix matches.
type Policy struct {
	routes   []Route
	defroute Route
	hasDef   bool
}

// New builds a Policy from routes. Routes are sorted by descending PathPrefix
// length so Match returns the longest-prefix winner deterministically (ties
// broken by lexical order for stability). A route with an empty PathPrefix (or
// "/") acts as the catch-all default.
func New(routes []Route) (*Policy, error) {
	p := &Policy{}
	sorted := make([]Route, len(routes))
	copy(sorted, routes)
	sort.SliceStable(sorted, func(i, j int) bool {
		li, lj := len(sorted[i].PathPrefix), len(sorted[j].PathPrefix)
		if li != lj {
			return li > lj // longer prefix first
		}
		return sorted[i].PathPrefix < sorted[j].PathPrefix
	})
	for _, r := range sorted {
		if !r.Action.Valid() {
			return nil, fmt.Errorf("policy: route %q has invalid action %q", r.PathPrefix, r.Action)
		}
		if r.PathPrefix == "" || r.PathPrefix == "/" {
			if p.hasDef {
				// Keep the first (already longest-or-equal) default.
				continue
			}
			p.defroute = r
			p.hasDef = true
			continue
		}
		p.routes = append(p.routes, r)
	}
	return p, nil
}

// Match returns the route whose PathPrefix is the longest prefix of path. If
// none matches, the default route is returned (ok=true). If there is no
// default and nothing matches, ok=false.
func (p *Policy) Match(path string) (Route, bool) {
	for _, r := range p.routes {
		if strings.HasPrefix(path, r.PathPrefix) {
			return r, true
		}
	}
	if p.hasDef {
		return p.defroute, true
	}
	return Route{}, false
}

// FailClosed reports whether a sanitize failure on this route must block the
// upload (the safe default). It is the logical negation of FailOpen and is
// provided for readable call sites.
func (r Route) FailClosed() bool { return !r.FailOpen }
