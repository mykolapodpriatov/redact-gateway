package main

import (
	"os"
	"path/filepath"
	"testing"

	"redact-gateway/internal/config"
)

func TestRunInvalidConfigFails(t *testing.T) {
	// Missing origin → config validation error, returned before any server
	// start (so the test does not bind a port).
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"routes": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(p); err == nil {
		t.Fatal("expected run to fail on invalid config")
	}
}

func TestBuildRegistryHasDefaultDetectors(t *testing.T) {
	reg := buildRegistry()
	if _, ok := reg["region-marker"]; !ok {
		t.Fatal("region-marker detector not wired")
	}
	if _, ok := reg["regex-pii"]; !ok {
		t.Fatal("regex-pii detector not wired")
	}
	// The default build must NOT wire any ML detector by name.
	for _, ml := range []string{"face", "qr", "vlm", "ocr"} {
		if _, ok := reg[ml]; ok {
			t.Fatalf("ML detector %q must not be in the default registry", ml)
		}
	}
}

func TestBuildPolicyTranslatesRoutes(t *testing.T) {
	strip := true
	cfg := &config.Config{
		StripMetadata: false,
		Routes: []config.RouteConfig{
			{PathPrefix: "/u", Action: "redact", Detectors: []string{"region-marker"}, MaxBytes: 1024, StripMetadata: &strip},
			{PathPrefix: "/p", Action: "pass", MaxBytes: 2048},
		},
	}
	pol, err := buildPolicy(cfg)
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	r, ok := pol.Match("/u/file")
	if !ok || string(r.Action) != "redact" || !r.StripMetadata || r.MaxBytes != 1024 {
		t.Fatalf("route /u translated wrong: %+v ok=%v", r, ok)
	}
	r2, ok := pol.Match("/p/x")
	if !ok || string(r2.Action) != "pass" {
		t.Fatalf("route /p translated wrong: %+v", r2)
	}
}

func TestBuildPolicyAppliesGlobalFailOpen(t *testing.T) {
	// Regression: a global fail_open:true must reach the resolved policy.Route
	// for a route that does not set fail_open (previously buildPolicy read only
	// the per-route value, making the global a silent no-op). A route that
	// explicitly sets fail_open:false must stay fail-closed.
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	body := `{
		"origin": "http://o:1",
		"fail_open": true,
		"routes": [
			{"path_prefix": "/inherits", "action": "pass"},
			{"path_prefix": "/closed", "action": "pass", "fail_open": false}
		]
	}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	pol, err := buildPolicy(cfg)
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	inh, ok := pol.Match("/inherits/x")
	if !ok || !inh.FailOpen {
		t.Fatalf("route inheriting global fail_open is not fail-open: %+v", inh)
	}
	closed, ok := pol.Match("/closed/x")
	if !ok || closed.FailOpen {
		t.Fatalf("route with explicit fail_open:false is not fail-closed: %+v", closed)
	}
}

func TestOpenAuditStdoutAndFile(t *testing.T) {
	w, closeFn, err := openAudit("")
	if err != nil {
		t.Fatalf("stdout audit: %v", err)
	}
	if w != os.Stdout {
		t.Fatal("empty path should select stdout")
	}
	closeFn()

	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	w2, close2, err := openAudit(p)
	if err != nil {
		t.Fatalf("file audit: %v", err)
	}
	if _, err := w2.Write([]byte("line\n")); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	close2()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("audit file not created: %v", err)
	}
}
