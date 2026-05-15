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
	"sync"
	"syscall"
	"time"

	"github.com/getlydian/certific/internal/certific"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
		Path:     cfg.Path,
		Key:      cfg.Key,
		Interval: cfg.Interval,
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
