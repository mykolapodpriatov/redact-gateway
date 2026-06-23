// Package config loads and validates the gateway configuration from a JSON
// file with environment-variable overrides. Validation is strict and
// safety-oriented: it bounds the N*max_bytes memory product against a ceiling,
// rejects a missing origin, unknown detectors, and invalid actions, and fills
// safe defaults (fail-closed, a sane MaxBytes, a ~40MP pixel cap).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Defaults applied when fields are omitted.
const (
	DefaultListen         = ":8080"
	DefaultWorkerPoolSize = 8
	DefaultMaxBytes       = 10 << 20   // 10 MiB
	DefaultMaxPixels      = 40_000_000 // ~40 MP
	DefaultMemoryCeiling  = 512 << 20  // 512 MiB ceiling on N*max_bytes
	DefaultJPEGQuality    = 90
	DefaultBlurRadius     = 8
	DefaultAcquireTimeout = 2 * time.Second
	DefaultDrainTimeout   = 15 * time.Second
)

// RouteConfig is the JSON shape of a single route. FailOpen and StripMetadata
// are pointers so an omitted field can inherit the global value while an
// explicit per-route value (including false) wins.
type RouteConfig struct {
	PathPrefix    string   `json:"path_prefix"`
	Action        string   `json:"action"`
	Detectors     []string `json:"detectors"`
	FailOpen      *bool    `json:"fail_open"`
	MaxBytes      int64    `json:"max_bytes"`
	StripMetadata *bool    `json:"strip_metadata"`
}

// Config is the full gateway configuration.
type Config struct {
	Listen         string        `json:"listen"`
	Origin         string        `json:"origin"`
	Routes         []RouteConfig `json:"routes"`
	AuditPath      string        `json:"audit_path"`
	WorkerPoolSize int           `json:"worker_pool_size"`
	MaxBytes       int64         `json:"max_bytes"`
	MaxPixels      int64         `json:"max_pixels"`
	FailOpen       bool          `json:"fail_open"`
	StripMetadata  bool          `json:"strip_metadata"`
	JPEGQuality    int           `json:"jpeg_quality"`
	BlurRadius     int           `json:"blur_radius"`
	MemoryCeiling  int64         `json:"memory_ceiling"`
	AcquireTimeout Duration      `json:"acquire_timeout"`
	DrainTimeout   Duration      `json:"drain_timeout"`
}

// Duration is a time.Duration that marshals to/from a Go duration string (for
// example "2s") in JSON.
type Duration time.Duration

// UnmarshalJSON parses a duration string or an integer number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case string:
		parsed, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("config: invalid duration %q: %w", val, err)
		}
		*d = Duration(parsed)
	case float64:
		*d = Duration(time.Duration(val))
	default:
		return fmt.Errorf("config: invalid duration value %v", v)
	}
	return nil
}

// MarshalJSON renders the duration as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// KnownDetectors is the set of detector names the default build can wire by
// name. Config validation rejects any route detector outside this set so a
// typo fails fast rather than silently disabling redaction.
var KnownDetectors = map[string]bool{
	"region-marker": true,
	"regex-pii":     true,
	"fake":          true,
}

// Load reads and parses the JSON config at path, applies environment
// overrides, fills defaults, and validates. A path of "" loads an
// all-defaults config (still requiring REDACT_ORIGIN via env or it fails
// validation).
func Load(path string) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %q: %w", path, err)
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("config: parse %q: %w", path, err)
		}
	}
	applyEnv(cfg)
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv overrides selected fields from environment variables. Only a small,
// documented set is supported (the rest live in the file).
func applyEnv(cfg *Config) {
	if v := os.Getenv("REDACT_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("REDACT_ORIGIN"); v != "" {
		cfg.Origin = v
	}
	if v := os.Getenv("REDACT_AUDIT_PATH"); v != "" {
		cfg.AuditPath = v
	}
	if v := os.Getenv("REDACT_WORKER_POOL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.WorkerPoolSize = n
		}
	}
	if v := os.Getenv("REDACT_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxBytes = n
		}
	}
	if v := os.Getenv("REDACT_MAX_PIXELS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxPixels = n
		}
	}
}

func (cfg *Config) applyDefaults() {
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if cfg.WorkerPoolSize == 0 {
		cfg.WorkerPoolSize = DefaultWorkerPoolSize
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxPixels == 0 {
		cfg.MaxPixels = DefaultMaxPixels
	}
	if cfg.MemoryCeiling == 0 {
		cfg.MemoryCeiling = DefaultMemoryCeiling
	}
	if cfg.JPEGQuality == 0 {
		cfg.JPEGQuality = DefaultJPEGQuality
	}
	if cfg.BlurRadius == 0 {
		cfg.BlurRadius = DefaultBlurRadius
	}
	if cfg.AcquireTimeout == 0 {
		cfg.AcquireTimeout = Duration(DefaultAcquireTimeout)
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = Duration(DefaultDrainTimeout)
	}
	// Per-route defaults: inherit the global MaxBytes, strip_metadata, and
	// fail_open when a route does not set them. An explicit per-route value
	// (including a literal false) always wins over the global.
	for i := range cfg.Routes {
		if cfg.Routes[i].MaxBytes == 0 {
			cfg.Routes[i].MaxBytes = cfg.MaxBytes
		}
		if cfg.Routes[i].StripMetadata == nil {
			v := cfg.StripMetadata
			cfg.Routes[i].StripMetadata = &v
		}
		if cfg.Routes[i].FailOpen == nil {
			v := cfg.FailOpen
			cfg.Routes[i].FailOpen = &v
		}
	}
}

// Validate enforces the safety-critical invariants.
func (cfg *Config) Validate() error {
	if cfg.Origin == "" {
		return fmt.Errorf("config: origin is required (set in file or REDACT_ORIGIN)")
	}
	if u, err := url.Parse(cfg.Origin); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("config: origin %q must be an absolute URL", cfg.Origin)
	}
	if cfg.WorkerPoolSize < 1 {
		return fmt.Errorf("config: worker_pool_size must be >= 1, got %d", cfg.WorkerPoolSize)
	}
	if cfg.MaxBytes < 1 {
		return fmt.Errorf("config: max_bytes must be >= 1, got %d", cfg.MaxBytes)
	}
	if cfg.MaxPixels < 1 {
		return fmt.Errorf("config: max_pixels must be >= 1, got %d", cfg.MaxPixels)
	}
	// Bound the worst-case peak image-buffer memory (N * max_bytes) so an
	// operator cannot silently configure a multi-GB peak.
	product := cfg.MaxBytes * int64(cfg.WorkerPoolSize)
	if cfg.MaxBytes != 0 && product/cfg.MaxBytes != int64(cfg.WorkerPoolSize) {
		return fmt.Errorf("config: worker_pool_size * max_bytes overflows")
	}
	if product > cfg.MemoryCeiling {
		return fmt.Errorf("config: worker_pool_size*max_bytes=%d exceeds memory_ceiling=%d", product, cfg.MemoryCeiling)
	}
	for _, r := range cfg.Routes {
		action := Action(r.Action)
		if !action.valid() {
			return fmt.Errorf("config: route %q has invalid action %q", r.PathPrefix, r.Action)
		}
		if r.MaxBytes < 1 {
			return fmt.Errorf("config: route %q max_bytes must be >= 1", r.PathPrefix)
		}
		for _, d := range r.Detectors {
			if !KnownDetectors[d] {
				return fmt.Errorf("config: route %q references unknown detector %q", r.PathPrefix, d)
			}
		}
	}
	return nil
}

// Action mirrors policy.Action for local validation without importing policy
// (config is a leaf). The proxy wiring translates these strings into
// policy.Action.
type Action string

func (a Action) valid() bool {
	switch a {
	case "redact", "blur", "drop", "pass":
		return true
	default:
		return false
	}
}
