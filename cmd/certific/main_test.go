package main

import (
	"context"
	"errors"
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

// TestRunUploadNotImplemented locks in the placeholder behaviour so the
// real implementation in a later commit has to consciously replace it.
func TestRunUploadNotImplemented(t *testing.T) {
	err := run(context.Background(), []string{"--mode", "upload"}, nil, io.Discard, io.Discard)
	if !errors.Is(err, errNotImplemented) {
		t.Fatalf("upload: got %v, want errNotImplemented", err)
	}
}

func TestRunDownloadNotImplemented(t *testing.T) {
	err := run(context.Background(), []string{"--mode", "download"}, nil, io.Discard, io.Discard)
	if !errors.Is(err, errNotImplemented) {
		t.Fatalf("download: got %v, want errNotImplemented", err)
	}
}
