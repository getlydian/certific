package certific

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// Mode selects the binary's run-mode. The same image runs as either an
// uploader (single writer watching acme.json) or a downloader (many
// readers pulling from S3); LoadConfig dispatches on this value.
type Mode string

const (
	ModeUpload   Mode = "upload"
	ModeDownload Mode = "download"
)

// DefaultInterval is the download poll interval when nothing else is set.
// One minute keeps Head traffic cheap while staying well inside the
// 2×interval health budget operators alert on.
const DefaultInterval = 60 * time.Second

// MinInterval and MaxInterval bound --interval. The lower bound exists so
// a misconfigured "1s" doesn't hammer S3; the upper bound exists so the
// health endpoint's 2×interval window remains operationally meaningful.
const (
	MinInterval = 10 * time.Second
	MaxInterval = time.Hour
)

// DefaultHealthGrace is the staleness window applied to the upload-mode
// health endpoint. Upload is event-driven — a healthy uploader with no
// cert renewals does no S3 work — so the freshness budget has to be
// generous enough to span a quiet day. Operators who want a tighter
// signal can shrink it via --health-grace.
const DefaultHealthGrace = 24 * time.Hour

// Config is the resolved configuration for a single run. Fields are
// populated by LoadConfig from flags, environment variables, and
// defaults, in that precedence.
type Config struct {
	Mode        Mode
	Path        string
	Bucket      string
	Key         string
	Region      string
	Endpoint    string
	Interval    time.Duration
	LogLevel    slog.Level
	HealthAddr  string        // empty → health server disabled
	HealthGrace time.Duration // upload-mode staleness window; download mode uses 2×Interval
}

// LoadConfig resolves configuration from args and environ. Resolution
// order is flag → env (CERTIFIC_*) → default. Validation runs after
// parsing so flag-syntax errors don't get masked by missing-field errors.
//
// stderr is used as the flag set's error sink; pass io.Discard in tests
// that want to swallow the usage banner.
func LoadConfig(args []string, environ []string, stderr io.Writer) (Config, error) {
	env := envMap(environ)

	cfg := Config{
		Mode:       Mode(envOr(env, "CERTIFIC_MODE", "")),
		Path:       envOr(env, "CERTIFIC_PATH", ""),
		Bucket:     envOr(env, "CERTIFIC_BUCKET", ""),
		Key:        envOr(env, "CERTIFIC_KEY", "acme.json"),
		Region:     envOr(env, "CERTIFIC_REGION", ""),
		Endpoint:   envOr(env, "CERTIFIC_ENDPOINT", ""),
		HealthAddr: envOr(env, "CERTIFIC_HEALTH_ADDR", ""),
	}

	var err error
	if cfg.Interval, err = envDuration(env, "CERTIFIC_INTERVAL", DefaultInterval); err != nil {
		return Config{}, err
	}
	if cfg.HealthGrace, err = envDuration(env, "CERTIFIC_HEALTH_GRACE", DefaultHealthGrace); err != nil {
		return Config{}, err
	}
	if cfg.LogLevel, err = envLogLevel(env, "CERTIFIC_LOG_LEVEL", slog.LevelInfo); err != nil {
		return Config{}, err
	}

	fs := flag.NewFlagSet("certific", flag.ContinueOnError)
	fs.SetOutput(stderr)
	modeStr := string(cfg.Mode)
	logStr := cfg.LogLevel.String()
	fs.StringVar(&modeStr, "mode", modeStr, "run mode: upload|download (CERTIFIC_MODE)")
	fs.StringVar(&cfg.Path, "path", cfg.Path, "local acme.json path (CERTIFIC_PATH)")
	fs.StringVar(&cfg.Bucket, "bucket", cfg.Bucket, "S3 bucket name (CERTIFIC_BUCKET)")
	fs.StringVar(&cfg.Key, "key", cfg.Key, "S3 object key (CERTIFIC_KEY)")
	fs.StringVar(&cfg.Region, "region", cfg.Region, "S3 region (CERTIFIC_REGION)")
	fs.StringVar(&cfg.Endpoint, "endpoint", cfg.Endpoint, "S3 endpoint URL for non-AWS stores (CERTIFIC_ENDPOINT)")
	// Sentinel so we can detect whether --interval was actually passed
	// vs. inherited from env/default — needed because --interval only
	// applies to download mode and we want to reject it on upload.
	intervalFlag := fs.String("interval", "", "download poll interval, 10s ≤ x ≤ 1h (CERTIFIC_INTERVAL)")
	fs.StringVar(&cfg.HealthAddr, "health-addr", cfg.HealthAddr, "listen address for /healthz and /metrics (e.g. :8080); empty = disabled (CERTIFIC_HEALTH_ADDR)")
	healthGraceFlag := fs.String("health-grace", "", "upload-mode staleness window for /healthz (CERTIFIC_HEALTH_GRACE, default 24h); ignored in download mode (uses 2×--interval)")
	fs.StringVar(&logStr, "log-level", logStr, "log level: debug|info|warn|error (CERTIFIC_LOG_LEVEL)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg.Mode = Mode(modeStr)

	intervalFromFlag := *intervalFlag != ""
	if intervalFromFlag {
		d, err := time.ParseDuration(*intervalFlag)
		if err != nil {
			return Config{}, fmt.Errorf("--interval: %w", err)
		}
		cfg.Interval = d
	}

	healthGraceFromFlag := *healthGraceFlag != ""
	if healthGraceFromFlag {
		d, err := time.ParseDuration(*healthGraceFlag)
		if err != nil {
			return Config{}, fmt.Errorf("--health-grace: %w", err)
		}
		cfg.HealthGrace = d
	}

	if err := parseLogLevel(logStr, &cfg.LogLevel); err != nil {
		return Config{}, err
	}

	if err := cfg.validate(intervalFromFlag, healthGraceFromFlag); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate enforces the mode-specific required-field rules and the
// "don't set download-only flags on upload" rule. intervalFromFlag and
// healthGraceFromFlag report whether each flag was provided on the
// command line, since env vs. flag have different rejection semantics
// (env is ignored for non-applicable modes; flags are rejected).
func (c *Config) validate(intervalFromFlag, healthGraceFromFlag bool) error {
	switch c.Mode {
	case "":
		return fmt.Errorf("--mode is required (upload|download)")
	case ModeUpload, ModeDownload:
	default:
		return fmt.Errorf("unknown mode %q (want upload|download)", c.Mode)
	}

	var missing []string
	if c.Path == "" {
		missing = append(missing, "--path")
	}
	if c.Bucket == "" {
		missing = append(missing, "--bucket")
	}
	if c.Key == "" {
		missing = append(missing, "--key")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}

	if c.Mode == ModeUpload && intervalFromFlag {
		return fmt.Errorf("--interval is only valid in download mode")
	}

	if c.Mode == ModeDownload {
		if c.Interval < MinInterval || c.Interval > MaxInterval {
			return fmt.Errorf("--interval %s out of range [%s, %s]", c.Interval, MinInterval, MaxInterval)
		}
		// HealthGrace is upload-only — reject the flag on download to keep
		// misconfigurations loud, but ignore an inherited env value (the
		// same env may be shared with an uploader sidecar).
		if healthGraceFromFlag {
			return fmt.Errorf("--health-grace is only valid in upload mode (download uses 2×--interval)")
		}
		c.HealthGrace = 0
	} else {
		// Upload mode doesn't use Interval; zero it so accidental reads
		// downstream produce an obvious "0s" rather than a stale default.
		c.Interval = 0
		if c.HealthGrace <= 0 {
			return fmt.Errorf("--health-grace must be > 0, got %s", c.HealthGrace)
		}
	}

	return nil
}

func envMap(environ []string) map[string]string {
	out := make(map[string]string, len(environ))
	for _, kv := range environ {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			continue
		}
		out[kv[:i]] = kv[i+1:]
	}
	return out
}

func envOr(env map[string]string, key, def string) string {
	if v, ok := env[key]; ok && v != "" {
		return v
	}
	return def
}

func envDuration(env map[string]string, key string, def time.Duration) (time.Duration, error) {
	v, ok := env[key]
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func envLogLevel(env map[string]string, key string, def slog.Level) (slog.Level, error) {
	v, ok := env[key]
	if !ok || v == "" {
		return def, nil
	}
	var lvl slog.Level
	if err := parseLogLevel(v, &lvl); err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return lvl, nil
}

func parseLogLevel(s string, out *slog.Level) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		*out = slog.LevelInfo
	case "debug":
		*out = slog.LevelDebug
	case "warn", "warning":
		*out = slog.LevelWarn
	case "error":
		*out = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q (want debug|info|warn|error)", s)
	}
	return nil
}
