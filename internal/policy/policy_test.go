package policy_test

import (
	"testing"

	"redact-gateway/internal/policy"
)

func TestLongestPrefixMatch(t *testing.T) {
	p, err := policy.New([]policy.Route{
		{PathPrefix: "/upload", Action: policy.ActionBlur, MaxBytes: 1},
		{PathPrefix: "/upload/avatars", Action: policy.ActionRedact, MaxBytes: 1},
		{PathPrefix: "/", Action: policy.ActionPass, MaxBytes: 1},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	cases := []struct {
		path   string
		action policy.Action
		prefix string
	}{
		{"/upload/avatars/123.jpg", policy.ActionRedact, "/upload/avatars"},
		{"/upload/docs/file.png", policy.ActionBlur, "/upload"},
		{"/other/path", policy.ActionPass, "/"},
		{"/", policy.ActionPass, "/"},
	}
	for _, c := range cases {
		r, ok := p.Match(c.path)
		if !ok {
			t.Fatalf("%s: no match", c.path)
		}
		if r.Action != c.action || r.PathPrefix != c.prefix {
			t.Fatalf("%s: got action=%s prefix=%s, want action=%s prefix=%s",
				c.path, r.Action, r.PathPrefix, c.action, c.prefix)
		}
	}
}

func TestNoMatchNoDefault(t *testing.T) {
	p, err := policy.New([]policy.Route{
		{PathPrefix: "/api", Action: policy.ActionRedact, MaxBytes: 1},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, ok := p.Match("/nope"); ok {
		t.Fatal("expected no match without a default route")
	}
	if r, ok := p.Match("/api/x"); !ok || r.Action != policy.ActionRedact {
		t.Fatalf("expected /api match, got ok=%v action=%v", ok, r.Action)
	}
}

func TestInvalidActionRejected(t *testing.T) {
	_, err := policy.New([]policy.Route{
		{PathPrefix: "/x", Action: policy.Action("nonsense"), MaxBytes: 1},
	})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestActionHelpers(t *testing.T) {
	if !policy.ActionRedact.Masks() || !policy.ActionBlur.Masks() {
		t.Fatal("redact/blur should mask")
	}
	if policy.ActionPass.Masks() || policy.ActionDrop.Masks() {
		t.Fatal("pass/drop should not mask")
	}
	if !policy.ActionPass.Valid() || policy.Action("zzz").Valid() {
		t.Fatal("Valid() wrong")
	}
}

func TestFailClosedDefault(t *testing.T) {
	open := policy.Route{PathPrefix: "/o", Action: policy.ActionRedact, FailOpen: true, MaxBytes: 1}
	closed := policy.Route{PathPrefix: "/c", Action: policy.ActionRedact, MaxBytes: 1}
	if open.FailClosed() {
		t.Fatal("fail-open route reported fail-closed")
	}
	if !closed.FailClosed() {
		t.Fatal("default route should be fail-closed")
	}
}

func TestDefaultRouteResolution(t *testing.T) {
	p, err := policy.New([]policy.Route{
		{PathPrefix: "", Action: policy.ActionDrop, MaxBytes: 1},
		{PathPrefix: "/keep", Action: policy.ActionPass, MaxBytes: 1},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r, ok := p.Match("/anything")
	if !ok || r.Action != policy.ActionDrop {
		t.Fatalf("empty-prefix default not applied: ok=%v action=%v", ok, r.Action)
	}
}
