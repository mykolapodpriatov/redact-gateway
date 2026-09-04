package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestValidateConfigValidConfigPasses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	body := `{
		"origin": "http://o:1",
		"routes": [
			{"path_prefix": "/", "action": "pass"}
		]
	}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, originURL, pol, err := validateConfig(p)
	if err != nil {
		t.Fatalf("expected valid config to pass validation: %v", err)
	}
	if cfg == nil || originURL == nil || pol == nil {
		t.Fatal("validateConfig returned nil result alongside a nil error")
	}
}

func TestValidateConfigInvalidConfigFails(t *testing.T) {
	// Missing origin → config validation error, same failure run() would hit.
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"routes": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := validateConfig(p); err == nil {
		t.Fatal("expected validateConfig to fail on invalid config")
	}
}

func TestValidateConfigDoesNotTouchAuditFile(t *testing.T) {
	// audit_path points inside a directory that does not exist, so run()
	// would fail trying to open it — but validateConfig must succeed because
	// it never calls openAudit. This is the acceptance criterion from #9: a
	// bad audit path (or any other side effect run() has) must not stand in
	// the way of validating routes/policy.
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	body := `{
		"origin": "http://o:1",
		"audit_path": "` + filepath.Join(dir, "missing-dir", "audit.log") + `",
		"routes": [
			{"path_prefix": "/", "action": "pass"}
		]
	}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := validateConfig(p); err != nil {
		t.Fatalf("validateConfig should not touch audit_path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "missing-dir")); err == nil {
		t.Fatal("validateConfig must not create the audit directory/file")
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

func TestBuildPolicyCopiesAcceptedFormats(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{PathPrefix: "/j", Action: "redact", MaxBytes: 1024, AcceptedFormats: []string{"jpeg"}},
		},
	}
	pol, err := buildPolicy(cfg)
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	r, ok := pol.Match("/j/x")
	if !ok || len(r.AcceptedFormats) != 1 || r.AcceptedFormats[0] != "jpeg" {
		t.Fatalf("accepted_formats not copied onto policy.Route: %+v", r)
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

// ---- CLI surface -----------------------------------------------------------

// runCLI is the whole CLI: -version short-circuits before any config is read,
// so the flag works on a machine with no config file at all.
func TestVersionFlagPrintsBuildVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d, want 0; stderr: %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Errorf("printed %q, want %q", got, version)
	}
	if stderr.Len() != 0 {
		t.Errorf("wrote %q to stderr, want nothing", stderr.String())
	}
}

// An unstamped build reports "dev", matching what a plain `go build` produces.
func TestDefaultVersionIsDev(t *testing.T) {
	if version != "dev" {
		t.Errorf("version = %q, want %q for an unstamped build", version, "dev")
	}
}

// An unknown flag is a usage error, not a crash and not a silent start.
func TestUnknownFlagIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"-nope"}, &stdout, &stderr); code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Error("nothing written to stderr for an unknown flag")
	}
}

// -validate reports a bad config on stderr with exit 1, and a good one on
// stdout with exit 0, without binding a listener.
func TestValidateFlagExitCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"-validate", "-config", filepath.Join(t.TempDir(), "missing.json")}, &stdout, &stderr); code != 1 {
		t.Errorf("missing config: exit code %d, want 1", code)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen":":0","origin":"http://127.0.0.1:1","routes":[{"path_prefix":"/u","action":"pass"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"-validate", "-config", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("valid config: exit code %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "config OK") {
		t.Errorf("stdout = %q, want it to contain \"config OK\"", stdout.String())
	}
}
