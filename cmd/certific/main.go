// Command certific shuttles Traefik's acme.json between a single writer
// and many readers via S3. A single binary picks its behaviour from the
// --mode flag: "upload" watches a local acme.json and pushes changes to
// S3; "download" polls S3 and atomically replaces the local file.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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

// errNotImplemented is returned by mode dispatch arms that haven't landed
// yet. It lets the skeleton be exercised end-to-end (flags parse, mode
// dispatches) without pretending the binary is functional.
var errNotImplemented = errors.New("not implemented")

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
		return runDownload(ctx)
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
	return u.Run(ctx)
}

func runDownload(_ context.Context) error {
	return fmt.Errorf("download: %w", errNotImplemented)
}
