package main

import (
	"context"
	"io"
	"testing"
)

// TestRunRequiresMode confirms the dispatcher refuses to run without an
// explicit mode rather than silently picking one.
func TestRunRequiresMode(t *testing.T) {
	err := run(context.Background(), nil, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error when --mode is missing, got nil")
	}
}

// TestRunRejectsUnknownMode confirms early validation surfaces typos.
func TestRunRejectsUnknownMode(t *testing.T) {
	err := run(context.Background(), []string{"--mode", "sideload"}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

// TestRunRejectsBadInterval pins the config wiring for download mode:
// an out-of-range --interval must surface from LoadConfig rather than
// reaching the Downloader. The unit tests on Downloader assume a valid
// interval; this confirms the boundary.
func TestRunRejectsBadInterval(t *testing.T) {
	err := run(
		context.Background(),
		[]string{
			"--mode", "download",
			"--path", "/tmp/acme.json",
			"--bucket", "b",
			"--interval", "1s",
		},
		nil, io.Discard, io.Discard,
	)
	if err == nil {
		t.Fatal("expected error for sub-minimum interval, got nil")
	}
}
