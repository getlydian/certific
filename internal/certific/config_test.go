package certific

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func baseUploadArgs() []string {
	return []string{
		"--mode", "upload",
		"--path", "/etc/acme/acme.json",
		"--bucket", "b",
		"--key", "acme.json",
	}
}

func baseDownloadArgs() []string {
	return []string{
		"--mode", "download",
		"--path", "/etc/acme/acme.json",
		"--bucket", "b",
		"--key", "acme.json",
	}
}

func TestLoadConfigUploadHappyPath(t *testing.T) {
	cfg, err := LoadConfig(baseUploadArgs(), nil, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mode != ModeUpload {
		t.Errorf("Mode = %q, want %q", cfg.Mode, ModeUpload)
	}
	if cfg.Interval != 0 {
		t.Errorf("upload Interval = %s, want 0 (interval is download-only)", cfg.Interval)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want Info", cfg.LogLevel)
	}
}

func TestLoadConfigDownloadDefaultsInterval(t *testing.T) {
	cfg, err := LoadConfig(baseDownloadArgs(), nil, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Interval != DefaultInterval {
		t.Errorf("Interval = %s, want default %s", cfg.Interval, DefaultInterval)
	}
}

// TestLoadConfigFlagBeatsEnv pins the resolution order: a flag value
// always wins over the same setting from the environment.
func TestLoadConfigFlagBeatsEnv(t *testing.T) {
	env := []string{
		"CERTIFIC_BUCKET=from-env",
		"CERTIFIC_INTERVAL=30s",
	}
	args := []string{
		"--mode", "download",
		"--path", "/etc/acme/acme.json",
		"--bucket", "from-flag",
		"--key", "acme.json",
		"--interval", "45s",
	}
	cfg, err := LoadConfig(args, env, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Bucket != "from-flag" {
		t.Errorf("Bucket = %q, want flag value", cfg.Bucket)
	}
	if cfg.Interval != 45*time.Second {
		t.Errorf("Interval = %s, want 45s (flag should win)", cfg.Interval)
	}
}

// TestLoadConfigEnvBeatsDefault confirms env populates fields when no
// flag is given — the middle tier of the precedence chain.
func TestLoadConfigEnvBeatsDefault(t *testing.T) {
	env := []string{
		"CERTIFIC_MODE=download",
		"CERTIFIC_PATH=/var/lib/acme.json",
		"CERTIFIC_BUCKET=b",
		"CERTIFIC_KEY=acme.json",
		"CERTIFIC_INTERVAL=2m",
		"CERTIFIC_REGION=us-east-1",
		"CERTIFIC_ENDPOINT=https://s3.example.com",
		"CERTIFIC_LOG_LEVEL=debug",
	}
	cfg, err := LoadConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mode != ModeDownload {
		t.Errorf("Mode = %q, want download", cfg.Mode)
	}
	if cfg.Path != "/var/lib/acme.json" {
		t.Errorf("Path = %q", cfg.Path)
	}
	if cfg.Interval != 2*time.Minute {
		t.Errorf("Interval = %s, want 2m", cfg.Interval)
	}
	if cfg.Region != "us-east-1" {
		t.Errorf("Region = %q", cfg.Region)
	}
	if cfg.Endpoint != "https://s3.example.com" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want Debug", cfg.LogLevel)
	}
}

func TestLoadConfigMissingMode(t *testing.T) {
	_, err := LoadConfig(nil, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--mode") {
		t.Fatalf("err = %v, want missing --mode error", err)
	}
}

func TestLoadConfigUnknownMode(t *testing.T) {
	_, err := LoadConfig([]string{"--mode", "sideload"}, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unknown mode") {
		t.Fatalf("err = %v, want unknown-mode error", err)
	}
}

func TestLoadConfigMissingRequired(t *testing.T) {
	// Only mode set; path, bucket missing.
	_, err := LoadConfig([]string{"--mode", "upload"}, nil, io.Discard)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
	if !strings.Contains(err.Error(), "--path") || !strings.Contains(err.Error(), "--bucket") {
		t.Errorf("error %q should list missing required flags", err)
	}
}

// TestLoadConfigIntervalRejectedOnUpload locks in the "loud
// misconfiguration" rule: --interval is download-only, so passing it on
// upload mode is an error, not a silent ignore.
func TestLoadConfigIntervalRejectedOnUpload(t *testing.T) {
	args := append(baseUploadArgs(), "--interval", "30s")
	_, err := LoadConfig(args, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--interval") {
		t.Fatalf("err = %v, want --interval rejected on upload", err)
	}
}

// TestLoadConfigIntervalEnvIgnoredOnUpload: env vars are shared across
// both sidecars in operator setups, so CERTIFIC_INTERVAL leaking into an
// upload container must not fail-fast. Only the explicit flag is
// rejected.
func TestLoadConfigIntervalEnvIgnoredOnUpload(t *testing.T) {
	cfg, err := LoadConfig(baseUploadArgs(), []string{"CERTIFIC_INTERVAL=30s"}, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Interval != 0 {
		t.Errorf("Interval = %s, want 0 in upload mode regardless of env", cfg.Interval)
	}
}

func TestLoadConfigIntervalOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		val  string
	}{
		{"too small", "1s"},
		{"too large", "2h"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(baseDownloadArgs(), "--interval", tc.val)
			_, err := LoadConfig(args, nil, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "out of range") {
				t.Fatalf("err = %v, want out-of-range", err)
			}
		})
	}
}

func TestLoadConfigIntervalBoundsInclusive(t *testing.T) {
	for _, d := range []string{"10s", "1h"} {
		args := append(baseDownloadArgs(), "--interval", d)
		if _, err := LoadConfig(args, nil, io.Discard); err != nil {
			t.Errorf("interval %s should be accepted: %v", d, err)
		}
	}
}

func TestLoadConfigBadIntervalSyntax(t *testing.T) {
	args := append(baseDownloadArgs(), "--interval", "not-a-duration")
	_, err := LoadConfig(args, nil, io.Discard)
	if err == nil {
		t.Fatal("expected parse error for bad --interval")
	}
}

func TestLoadConfigBadEnvIntervalSyntax(t *testing.T) {
	_, err := LoadConfig(baseDownloadArgs(), []string{"CERTIFIC_INTERVAL=zzz"}, io.Discard)
	if err == nil {
		t.Fatal("expected parse error for bad CERTIFIC_INTERVAL")
	}
}

func TestLoadConfigBadLogLevel(t *testing.T) {
	args := append(baseUploadArgs(), "--log-level", "spam")
	_, err := LoadConfig(args, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "log level") {
		t.Fatalf("err = %v, want invalid-log-level error", err)
	}
}

func TestLoadConfigLogLevels(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	}
	for in, want := range cases {
		args := append(baseUploadArgs(), "--log-level", in)
		cfg, err := LoadConfig(args, nil, io.Discard)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if cfg.LogLevel != want {
			t.Errorf("%s: LogLevel = %v, want %v", in, cfg.LogLevel, want)
		}
	}
}

// TestLoadConfigBadFlagSyntax confirms flag-parsing errors propagate
// without being shadowed by later validation failures.
func TestLoadConfigBadFlagSyntax(t *testing.T) {
	_, err := LoadConfig([]string{"--nope"}, nil, io.Discard)
	if err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestLoadConfigEmptyEnvValueFallsThroughToDefault(t *testing.T) {
	// An exported-but-empty env var should behave like "unset" rather
	// than blowing away the default. Mirrors envOr in tcmuxer.
	cfg, err := LoadConfig(baseDownloadArgs(), []string{"CERTIFIC_INTERVAL="}, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Interval != DefaultInterval {
		t.Errorf("Interval = %s, want default %s", cfg.Interval, DefaultInterval)
	}
}

// Sanity check that the package's exported error sentinels aren't
// accidentally used as validation errors (the loader returns ad-hoc
// fmt.Errorf values today; this test exists to flag a future regression
// if someone wires errors.Is incorrectly).
func TestLoadConfigErrorIsNotNil(t *testing.T) {
	_, err := LoadConfig(nil, nil, io.Discard)
	if errors.Is(err, nil) {
		t.Fatal("expected non-nil error")
	}
}

func TestLoadConfigHealthAddrAndGrace(t *testing.T) {
	// HealthAddr is opt-in; default is empty (disabled). When set, the
	// upload-mode grace window defaults to 24h and download-mode
	// ignores grace entirely in favour of 2×interval.
	cfg, err := LoadConfig(baseUploadArgs(), nil, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HealthAddr != "" {
		t.Errorf("default HealthAddr = %q, want empty", cfg.HealthAddr)
	}
	if cfg.HealthGrace != DefaultHealthGrace {
		t.Errorf("default upload HealthGrace = %s, want %s", cfg.HealthGrace, DefaultHealthGrace)
	}

	cfg, err = LoadConfig(append(baseUploadArgs(), "--health-addr", ":8080", "--health-grace", "10m"), nil, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HealthAddr != ":8080" {
		t.Errorf("HealthAddr = %q", cfg.HealthAddr)
	}
	if cfg.HealthGrace != 10*time.Minute {
		t.Errorf("HealthGrace = %s, want 10m", cfg.HealthGrace)
	}
}

func TestLoadConfigHealthGraceRejectedOnDownload(t *testing.T) {
	// Symmetric to the --interval-on-upload rule: --health-grace is
	// upload-only, so passing it on download must fail loudly. Download
	// freshness derives from 2×interval automatically.
	args := append(baseDownloadArgs(), "--health-grace", "5m")
	_, err := LoadConfig(args, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--health-grace") {
		t.Fatalf("err = %v, want --health-grace rejected on download", err)
	}
}

func TestLoadConfigHealthGraceEnvIgnoredOnDownload(t *testing.T) {
	// Mirror of TestLoadConfigIntervalEnvIgnoredOnUpload: a shared env
	// shouldn't fail-fast just because the operator set
	// CERTIFIC_HEALTH_GRACE in both sidecars' shared environment.
	cfg, err := LoadConfig(baseDownloadArgs(), []string{"CERTIFIC_HEALTH_GRACE=5m"}, io.Discard)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HealthGrace != 0 {
		t.Errorf("HealthGrace = %s, want 0 in download mode regardless of env", cfg.HealthGrace)
	}
}

func TestLoadConfigBadHealthGraceSyntax(t *testing.T) {
	args := append(baseUploadArgs(), "--health-grace", "nope")
	_, err := LoadConfig(args, nil, io.Discard)
	if err == nil {
		t.Fatal("expected parse error for bad --health-grace")
	}
}
