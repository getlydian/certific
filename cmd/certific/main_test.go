package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
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

// TestResolveFileEnv pins the Docker secrets-file pattern: a `FOO_FILE`
// env pointing at a readable file populates `FOO` with the file's
// contents (trailing newline trimmed), without clobbering an
// already-set `FOO`. Failures to read the file are surfaced as errors,
// not silently swallowed — a misconfigured credential mount must not
// fall through to anonymous SDK calls.
func TestResolveFileEnv(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	keyPath := writeFile("aws-key", "AKIAEXAMPLE\n")
	secretPath := writeFile("aws-secret", "supersecret")

	set := map[string]string{}
	setenv := func(k, v string) error { set[k] = v; return nil }

	environ := []string{
		"AWS_ACCESS_KEY_ID_FILE=" + keyPath,
		"AWS_SECRET_ACCESS_KEY_FILE=" + secretPath,
		"PLAIN=value",        // no _FILE suffix, must be ignored
		"_FILE=/should/skip", // empty target name, must be ignored
		"MISSING_FILE=",      // empty path, must be ignored
	}

	if err := resolveFileEnv(environ, setenv); err != nil {
		t.Fatalf("resolveFileEnv: %v", err)
	}
	if got := set["AWS_ACCESS_KEY_ID"]; got != "AKIAEXAMPLE" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want trimmed contents", got)
	}
	if got := set["AWS_SECRET_ACCESS_KEY"]; got != "supersecret" {
		t.Errorf("AWS_SECRET_ACCESS_KEY = %q", got)
	}
	if _, ok := set[""]; ok {
		t.Error("empty target was set")
	}
	if _, ok := set["PLAIN"]; ok {
		t.Error("non-_FILE key produced a setenv call")
	}
	if _, ok := set["MISSING"]; ok {
		t.Error("empty-path _FILE produced a setenv call")
	}
}

// TestResolveFileEnvRespectsExisting locks in the override rule:
// if `FOO` is already in the process env, `FOO_FILE` is ignored. Lets
// operators override a mounted secret with a plain env var for local
// debugging without un-mounting the file.
func TestResolveFileEnvRespectsExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("CERTIFIC_REGION", "from-env")

	set := map[string]string{}
	setenv := func(k, v string) error { set[k] = v; return nil }

	err := resolveFileEnv([]string{"CERTIFIC_REGION_FILE=" + p}, setenv)
	if err != nil {
		t.Fatalf("resolveFileEnv: %v", err)
	}
	if _, ok := set["CERTIFIC_REGION"]; ok {
		t.Error("setenv called even though target was already set")
	}
}

// TestResolveFileEnvFailsOnUnreadablePath surfaces a missing secret as
// an error rather than silently leaving the target unset. Starting up
// with half-populated credentials would let the SDK fall through to
// IMDS/anonymous and produce confusing 403s downstream.
func TestResolveFileEnvFailsOnUnreadablePath(t *testing.T) {
	err := resolveFileEnv(
		[]string{"AWS_ACCESS_KEY_ID_FILE=/nope/does/not/exist"},
		func(string, string) error { return nil },
	)
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
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
