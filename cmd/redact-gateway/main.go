// Command redact-gateway is an inbound-upload reverse proxy that masks
// sensitive regions in images before they reach the origin storage. It loads a
// JSON config, builds the redaction pipeline (detectors, policy, worker pool,
// audit log), and serves HTTP with graceful shutdown: on a signal it drains
// in-flight image jobs (complete-or-nothing) before shutting the server.
//
// The default build is stdlib-only; heavyweight ML detectors are optional
// adapters behind build tags (see internal/detect/ml).
package main

import (
	"context"
	"flag"
	"fmt"
	"image/color"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"redact-gateway/internal/audit"
	"redact-gateway/internal/config"
	"redact-gateway/internal/detect"
	"redact-gateway/internal/metrics"
	"redact-gateway/internal/policy"
	"redact-gateway/internal/pool"
	"redact-gateway/internal/proxy"
)

func main() {
	configPath := flag.String("config", "", "path to JSON config file (env REDACT_* overrides apply)")
	validate := flag.Bool("validate", false, "load and validate the config (routes, policy), then exit without starting the server")
	flag.Parse()

	if *validate {
		if _, _, _, err := validateConfig(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "redact-gateway: config invalid: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("config OK")
		return
	}

	if err := run(*configPath); err != nil {
		log.Fatalf("redact-gateway: %v", err)
	}
}

// validateConfig runs every check that does not require opening the audit
// file or binding a listener: config.Load (parse + env overrides + defaults +
// Config.Validate), origin URL parsing, and buildPolicy. run() calls this
// first and then layers the side effects (audit file, listeners) on top, so
// -validate exercises exactly the same validation path a real run would hit
// before anything observable happens.
func validateConfig(configPath string) (*config.Config, *url.URL, *policy.Policy, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, nil, err
	}

	originURL, err := url.Parse(cfg.Origin)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse origin: %w", err)
	}

	pol, err := buildPolicy(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	return cfg, originURL, pol, nil
}

func run(configPath string) error {
	cfg, originURL, pol, err := validateConfig(configPath)
	if err != nil {
		return err
	}

	// Audit log destination.
	auditW, closeAudit, err := openAudit(cfg.AuditPath)
	if err != nil {
		return err
	}
	defer closeAudit()

	registry := buildRegistry()

	wp := pool.New(cfg.WorkerPoolSize, time.Duration(cfg.AcquireTimeout))

	met := metrics.New()

	sanitizer := &proxy.Sanitizer{
		Registry:    registry,
		Audit:       audit.NewLogger(auditW, audit.SystemClock{}),
		MaxPixels:   cfg.MaxPixels,
		JPEGQuality: cfg.JPEGQuality,
		BlurRadius:  cfg.BlurRadius,
		Metrics:     met,
	}

	handler := proxy.New(proxy.Config{
		Origin:    originURL,
		Policy:    pol,
		Sanitizer: sanitizer,
		Pool:      wp,
	})

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: handler,
	}

	// Optional admin listener for /healthz + /metrics on a SEPARATE address so
	// health/metrics can never be interceptable as an upload on the proxy
	// listener. Disabled when metrics_listen is empty (the default).
	var admin *http.Server
	if cfg.MetricsListen != "" {
		admin = &http.Server{
			Addr:    cfg.MetricsListen,
			Handler: met.Handler(),
		}
	}

	return serve(srv, admin, wp, time.Duration(cfg.DrainTimeout))
}

// serve runs the HTTP server (and the optional admin listener) and performs
// graceful shutdown on SIGINT/SIGTERM: it drains in-flight image jobs
// (complete-or-nothing within the deadline) BEFORE shutting the servers down.
// admin may be nil (metrics disabled).
func serve(srv, admin *http.Server, wp *pool.Pool, drainTimeout time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if admin != nil {
		go func() {
			log.Printf("redact-gateway: admin (healthz+metrics) listening on %s", admin.Addr)
			if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("redact-gateway: admin listener error: %v", err)
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("redact-gateway: listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Printf("redact-gateway: shutdown signal received, draining...")
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	// Drain in-flight image jobs first (complete-or-nothing), THEN shut the
	// server. Order matters: the pool must quiesce before the server stops so
	// no job is left mid-forward.
	if err := wp.Drain(drainCtx); err != nil {
		log.Printf("redact-gateway: drain deadline hit: %v", err)
	}
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("redact-gateway: server shutdown: %v", err)
	}
	if admin != nil {
		if err := admin.Shutdown(drainCtx); err != nil {
			log.Printf("redact-gateway: admin shutdown: %v", err)
		}
	}
	return nil
}

// openAudit opens the audit-log destination. An empty path logs to stdout.
func openAudit(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// buildPolicy translates the config routes into a policy.Policy.
func buildPolicy(cfg *config.Config) (*policy.Policy, error) {
	routes := make([]policy.Route, 0, len(cfg.Routes))
	for _, rc := range cfg.Routes {
		// applyDefaults populates these pointers from the global value when a
		// route omits them; an explicit per-route value (including false) wins.
		// The nil-guards keep buildPolicy safe if a Config is built without Load.
		strip := cfg.StripMetadata
		if rc.StripMetadata != nil {
			strip = *rc.StripMetadata
		}
		failOpen := cfg.FailOpen
		if rc.FailOpen != nil {
			failOpen = *rc.FailOpen
		}
		routes = append(routes, policy.Route{
			PathPrefix:      rc.PathPrefix,
			Action:          policy.Action(rc.Action),
			Detectors:       rc.Detectors,
			FailOpen:        failOpen,
			MaxBytes:        rc.MaxBytes,
			StripMetadata:   strip,
			AcceptedFormats: rc.AcceptedFormats,
		})
	}
	return policy.New(routes)
}

// buildRegistry wires the default-build (stdlib) detectors by name. ML
// detectors are NOT wired here; they are optional build-tag adapters.
func buildRegistry() map[string]detect.Detector {
	return map[string]detect.Detector{
		"region-marker": &detect.RegionMarkerDetector{
			// Magenta marker by default; operators paint zones to redact.
			Marker:    color.RGBA{R: 255, G: 0, B: 255, A: 255},
			Tolerance: 16,
		},
		"regex-pii": &detect.RegexPIIDetector{
			// Default no-op OCR: finds nothing until a real OCR adapter is
			// plugged in. Documented behavior.
			OCR:      detect.NopOCR{},
			Patterns: detect.DefaultPIIPatterns(),
		},
		// Deterministic "mask everything" detector for locked-down routes.
		"full-image": &detect.FullImageDetector{},
	}
}
