package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"redact-gateway/internal/config"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestLoadDefaultsAndRoutes(t *testing.T) {
	p := writeConfig(t, `{
		"origin": "http://origin.example:9000",
		"routes": [
			{"path_prefix": "/upload", "action": "redact", "detectors": ["region-marker"]}
		]
	}`)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != config.DefaultListen {
		t.Fatalf("listen default wrong: %q", cfg.Listen)
	}
	if cfg.WorkerPoolSize != config.DefaultWorkerPoolSize {
		t.Fatalf("pool default wrong: %d", cfg.WorkerPoolSize)
	}
	if cfg.MaxBytes != config.DefaultMaxBytes {
		t.Fatalf("max_bytes default wrong: %d", cfg.MaxBytes)
	}
	if cfg.MaxPixels != config.DefaultMaxPixels {
		t.Fatalf("max_pixels default wrong: %d", cfg.MaxPixels)
	}
	// Per-route MaxBytes inherits the global default.
	if cfg.Routes[0].MaxBytes != config.DefaultMaxBytes {
		t.Fatalf("route max_bytes not inherited: %d", cfg.Routes[0].MaxBytes)
	}
}

func TestEnvOverrides(t *testing.T) {
	p := writeConfig(t, `{"origin": "http://from-file:1", "routes": []}`)
	t.Setenv("REDACT_ORIGIN", "http://from-env:2")
	t.Setenv("REDACT_LISTEN", ":7777")
	t.Setenv("REDACT_WORKER_POOL_SIZE", "3")
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Origin != "http://from-env:2" {
		t.Fatalf("env origin not applied: %q", cfg.Origin)
	}
	if cfg.Listen != ":7777" {
		t.Fatalf("env listen not applied: %q", cfg.Listen)
	}
	if cfg.WorkerPoolSize != 3 {
		t.Fatalf("env pool size not applied: %d", cfg.WorkerPoolSize)
	}
}

func TestValidateMissingOrigin(t *testing.T) {
	p := writeConfig(t, `{"routes": []}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for missing origin")
	}
}

func TestValidateBadOrigin(t *testing.T) {
	p := writeConfig(t, `{"origin": "not-a-url", "routes": []}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for non-absolute origin URL")
	}
}

func TestValidateMemoryCeiling(t *testing.T) {
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"worker_pool_size": 100,
		"max_bytes": 104857600,
		"routes": []
	}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error: 100 * 100MiB exceeds default 512MiB ceiling")
	}
}

func TestValidateUnknownDetector(t *testing.T) {
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"routes": [{"path_prefix": "/u", "action": "redact", "detectors": ["does-not-exist"]}]
	}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for unknown detector")
	}
}

func TestValidateInvalidAction(t *testing.T) {
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"routes": [{"path_prefix": "/u", "action": "explode"}]
	}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestRejectsUnknownFields(t *testing.T) {
	p := writeConfig(t, `{"origin": "http://o:1", "routes": [], "bogus_field": 1}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for unknown config field")
	}
}

func TestDurationMarshalRoundTrip(t *testing.T) {
	d := config.Duration(750 * time.Millisecond)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `"750ms"` {
		t.Fatalf("marshal got %s, want \"750ms\"", b)
	}
	var back config.Duration
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if time.Duration(back) != 750*time.Millisecond {
		t.Fatalf("round-trip mismatch: %v", time.Duration(back))
	}
}

func TestDurationFloatAndInvalid(t *testing.T) {
	var d config.Duration
	if err := json.Unmarshal([]byte("1000000000"), &d); err != nil {
		t.Fatalf("numeric duration: %v", err)
	}
	if time.Duration(d) != time.Second {
		t.Fatalf("numeric duration = %v", time.Duration(d))
	}
	if err := json.Unmarshal([]byte(`"not-a-duration"`), &d); err == nil {
		t.Fatal("expected error for bad duration string")
	}
	if err := json.Unmarshal([]byte(`true`), &d); err == nil {
		t.Fatal("expected error for bool duration")
	}
}

func TestEnvOverridesNumeric(t *testing.T) {
	p := writeConfig(t, `{"origin": "http://o:1", "routes": []}`)
	t.Setenv("REDACT_AUDIT_PATH", "/tmp/audit.log")
	t.Setenv("REDACT_MAX_BYTES", "2048")
	t.Setenv("REDACT_MAX_PIXELS", "1000000")
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AuditPath != "/tmp/audit.log" {
		t.Fatalf("audit path env: %q", cfg.AuditPath)
	}
	if cfg.MaxBytes != 2048 {
		t.Fatalf("max_bytes env: %d", cfg.MaxBytes)
	}
	if cfg.MaxPixels != 1000000 {
		t.Fatalf("max_pixels env: %d", cfg.MaxPixels)
	}
}

func TestValidateRouteMaxBytesPositive(t *testing.T) {
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"routes": [{"path_prefix": "/u", "action": "redact", "max_bytes": -1}]
	}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for negative route max_bytes")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	if _, err := config.Load("/does/not/exist.json"); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadEmptyPathStillValidates(t *testing.T) {
	// No file, but REDACT_ORIGIN is supplied via env → loads with defaults.
	t.Setenv("REDACT_ORIGIN", "http://env-only:1234")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("load empty path: %v", err)
	}
	if cfg.Origin != "http://env-only:1234" {
		t.Fatalf("origin: %q", cfg.Origin)
	}
}

func TestFailOpenGlobalInheritedByRoute(t *testing.T) {
	// A global fail_open:true with a route that does NOT set fail_open must make
	// that route fail-open (the documented UNSAFE escape hatch must not be a
	// silent no-op).
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"fail_open": true,
		"routes": [{"path_prefix": "/u", "action": "pass"}]
	}`)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Routes[0].FailOpen == nil {
		t.Fatal("route fail_open pointer not populated by applyDefaults")
	}
	if !*cfg.Routes[0].FailOpen {
		t.Fatal("route did not inherit global fail_open:true")
	}
}

func TestFailOpenExplicitFalseOverridesGlobalTrue(t *testing.T) {
	// An explicit per-route fail_open:false must win even under a global true,
	// keeping that route fail-closed.
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"fail_open": true,
		"routes": [
			{"path_prefix": "/closed", "action": "pass", "fail_open": false},
			{"path_prefix": "/inherits", "action": "pass"}
		]
	}`)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	byPrefix := map[string]*bool{}
	for _, r := range cfg.Routes {
		byPrefix[r.PathPrefix] = r.FailOpen
	}
	if byPrefix["/closed"] == nil || *byPrefix["/closed"] {
		t.Fatalf("explicit fail_open:false did not stay fail-closed: %v", byPrefix["/closed"])
	}
	if byPrefix["/inherits"] == nil || !*byPrefix["/inherits"] {
		t.Fatalf("route without fail_open did not inherit global true: %v", byPrefix["/inherits"])
	}
}

func TestFailOpenDefaultsFalse(t *testing.T) {
	// With no global and no per-route fail_open, the route is fail-closed.
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"routes": [{"path_prefix": "/u", "action": "pass"}]
	}`)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Routes[0].FailOpen == nil || *cfg.Routes[0].FailOpen {
		t.Fatalf("route fail_open should default to false, got %v", cfg.Routes[0].FailOpen)
	}
}

func TestDurationParsing(t *testing.T) {
	p := writeConfig(t, `{
		"origin": "http://o:1",
		"routes": [],
		"acquire_timeout": "750ms",
		"drain_timeout": "5s"
	}`)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if time.Duration(cfg.AcquireTimeout) != 750*time.Millisecond {
		t.Fatalf("acquire_timeout = %v", time.Duration(cfg.AcquireTimeout))
	}
	if time.Duration(cfg.DrainTimeout) != 5*time.Second {
		t.Fatalf("drain_timeout = %v", time.Duration(cfg.DrainTimeout))
	}
}
