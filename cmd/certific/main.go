// Command certific shuttles Traefik's acme.json between a single writer
// and many readers via S3. A single binary picks its behaviour from the
// --mode flag: "upload" watches a local acme.json and pushes changes to
// S3; "download" polls S3 and atomically replaces the local file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// errNotImplemented is returned by both mode dispatch arms until the real
// upload/download implementations land in later commits. It lets the
// skeleton be exercised end-to-end (flags parse, mode dispatches) without
// pretending the binary is functional.
var errNotImplemented = errors.New("not implemented")

// run is the testable entry point. It parses args, dispatches to a mode,
// and returns any error so main can decide the exit code.
func run(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer) error {
	_ = environ // consumed by the config loader in a later commit
	_ = stdout

	fs := flag.NewFlagSet("certific", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "", "run mode: upload|download")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch *mode {
	case "upload":
		return runUpload(ctx)
	case "download":
		return runDownload(ctx)
	case "":
		return fmt.Errorf("--mode is required (upload|download)")
	default:
		return fmt.Errorf("unknown mode %q (want upload|download)", *mode)
	}
}

func runUpload(_ context.Context) error {
	return fmt.Errorf("upload: %w", errNotImplemented)
}

func runDownload(_ context.Context) error {
	return fmt.Errorf("download: %w", errNotImplemented)
}
