// Command certific shuttles Traefik's acme.json between a single writer
// and many readers via S3. A single binary picks its behaviour from the
// --mode flag: "upload" watches a local acme.json and pushes changes to
// S3; "download" polls S3 and atomically replaces the local file.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/getlydian/certific/internal/certific"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Resolve `*_FILE` env vars into their plain-named counterparts
	// before anything else reads the environment. This is the standard
	// Docker secret-mounting pattern (Postgres, MySQL, Traefik, etc.):
	// mount the secret as a file under /run/secrets and point a
	// `FOO_FILE=/run/secrets/foo` env var at it. Critical for AWS
	// credentials, which the SDK only reads from `AWS_ACCESS_KEY_ID` /
	// `AWS_SECRET_ACCESS_KEY` directly, not from file paths.
	if err := resolveFileEnv(os.Environ(), os.Setenv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// resolveFileEnv reads every `FOO_FILE=path` from environ and, for each
// one where `FOO` is not already set, calls setenv("FOO", contents). The
// trailing newline of secret files (most editors add one, swarm doesn't,
// but operators copy-pasting through `bin/secrets-edit` often do) is
// stripped so `cat secretfile | tr -d '\n'` isn't required at every
// callsite. A `FOO_FILE` whose path is unreadable is fatal — failing
// loudly beats starting up with a half-populated credential chain.
func resolveFileEnv(environ []string, setenv func(string, string) error) error {
	for _, kv := range environ {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key, path := kv[:eq], kv[eq+1:]
		if !strings.HasSuffix(key, "_FILE") || path == "" {
			continue
		}
		target := strings.TrimSuffix(key, "_FILE")
		if target == "" {
			continue
		}
		if _, set := os.LookupEnv(target); set {
			// Existing value wins so an operator can override a
			// mounted secret with a plain env var for local debugging
			// without un-mounting the file.
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s=%s: %w", key, path, err)
		}
		if err := setenv(target, strings.TrimRight(string(body), "\r\n")); err != nil {
			return fmt.Errorf("set %s: %w", target, err)
		}
	}
	return nil
}

// run is the testable entry point. It parses args, dispatches to a mode,
// and returns any error so main can decide the exit code.
func run(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer) error {
	_ = stdout

	cfg, err := certific.LoadConfig(args, environ, stderr)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))

	switch cfg.Mode {
	case certific.ModeUpload:
		return runUpload(ctx, cfg, logger)
	case certific.ModeDownload:
		return runDownload(ctx, cfg, logger)
	default:
		// LoadConfig already rejected unknown/empty mode, so this is
		// unreachable in practice — kept as a defensive guard.
		return fmt.Errorf("unknown mode %q", cfg.Mode)
	}
}

func runUpload(ctx context.Context, cfg certific.Config, logger *slog.Logger) error {
	store, err := certific.NewS3Store(ctx, cfg)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	u := &certific.Uploader{
		Store:  store,
		Path:   cfg.Path,
		Key:    cfg.Key,
		Logger: logger,
	}
	return withHealth(ctx, cfg, u, cfg.HealthGrace, logger, u.Run)
}

func runDownload(ctx context.Context, cfg certific.Config, logger *slog.Logger) error {
	store, err := certific.NewS3Store(ctx, cfg)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	d := &certific.Downloader{
		Store:    store,
		OutDir:   cfg.OutDir,
		Key:      cfg.Key,
		Interval: cfg.Interval,
		Keep:     cfg.Keep,
		Logger:   logger,
	}
	// Downloader's freshness budget is 2×interval: one interval to
	// notice the change, one to recover from a single failed cycle.
	return withHealth(ctx, cfg, d, 2*cfg.Interval, logger, d.Run)
}

// withHealth optionally spins up the health server alongside the main
// worker. If HealthAddr is empty the worker runs unchanged. Otherwise
// the two goroutines share ctx — cancelling either tears down the
// whole process — and the worker's error wins (the health server's
// shutdown is best-effort).
func withHealth(
	ctx context.Context,
	cfg certific.Config,
	syncer certific.LastSyncer,
	freshness time.Duration,
	logger *slog.Logger,
	worker func(context.Context) error,
) error {
	if cfg.HealthAddr == "" {
		return worker(ctx)
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg        sync.WaitGroup
		healthErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Cancel the worker if the health server returns first (port
		// bind failure, unexpected Serve error) so we don't keep
		// running blind. Successful shutdown via ctx returns nil and
		// doesn't trigger the cancel — workerCtx is already cancelled.
		healthErr = certific.RunHealthServer(workerCtx, cfg.HealthAddr, syncer, freshness, logger)
		cancel()
	}()

	workerErr := worker(workerCtx)
	cancel()
	wg.Wait()

	// Worker errors are the operationally interesting ones; surface a
	// health-server bind error only if the worker didn't have its own
	// complaint.
	if workerErr != nil {
		return workerErr
	}
	return healthErr
}
