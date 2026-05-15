package certific

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Uploader watches a local acme.json and pushes changes to S3. One
// instance per process — there is only ever one writer in the design.
//
// Lifecycle:
//  1. Bootstrap: try to Get the current S3 object and write it to Path,
//     seeding the issuer's cache before Traefik starts. A 404 here is
//     fine (first-ever deploy); anything else is fatal.
//  2. Watch: subscribe to fsnotify events on Path's parent directory and
//     react to writes/renames/creates that target Path. Watching the
//     parent (not the file) is what lets us survive atomic writers that
//     swap a new file into place — fsnotify on the old inode would stop
//     firing after the rename.
//  3. Upload: read Path, sha256 it, skip if unchanged since the last
//     successful upload, else Put. Transient S3 failures retry with
//     exponential backoff + jitter; we never crash on them because
//     downstream gateways keep serving stale-but-valid certs.
type Uploader struct {
	Store    ObjectStore
	Path     string
	Key      string
	Logger   *slog.Logger
	Debounce time.Duration // 0 → defaultDebounce
	Backoff  BackoffConfig // zero → defaultBackoff

	// lastHash / hasHash track the sha256 of the last successfully-
	// uploaded (or bootstrapped) content. Run is the only goroutine that
	// reads or writes these, so no lock is needed.
	lastHash [sha256.Size]byte
	hasHash  bool
}

// BackoffConfig controls Put retry pacing. Exposed so tests can drop the
// wait to milliseconds; in production the defaults apply.
type BackoffConfig struct {
	Initial    time.Duration
	Max        time.Duration
	Multiplier float64
	JitterFrac float64 // ±fraction of the current delay
}

const (
	defaultDebounce = 500 * time.Millisecond
	// shutdownFlushTimeout bounds the flush-on-cancel upload. The watch
	// loop drains a pending debounced change after ctx is cancelled, but
	// uploadWithRetry on its own would back off forever on a flaky S3 and
	// hang container shutdown. Capping the flush keeps SIGTERM → exit
	// within a predictable window; if the upload doesn't land in time the
	// caller will retry on next boot.
	shutdownFlushTimeout = 5 * time.Second
)

var defaultBackoff = BackoffConfig{
	Initial:    1 * time.Second,
	Max:        60 * time.Second,
	Multiplier: 2.0,
	JitterFrac: 0.2,
}

// Run blocks until ctx is cancelled or an unrecoverable error occurs
// (bootstrap failure on a non-404 error, or fsnotify setup failure).
// Transient Put errors are logged and retried; they do not exit Run.
func (u *Uploader) Run(ctx context.Context) error {
	if u.Logger == nil {
		u.Logger = slog.Default()
	}
	debounce := u.Debounce
	if debounce <= 0 {
		debounce = defaultDebounce
	}
	backoff := u.Backoff
	if backoff == (BackoffConfig{}) {
		backoff = defaultBackoff
	}

	if err := u.bootstrap(ctx); err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify new watcher: %w", err)
	}
	defer watcher.Close()

	// Watch the parent directory: atomic writers (Traefik included) rename
	// a tempfile into place, which destroys the original inode the watcher
	// is bound to. Parent-directory watching survives that.
	dir := filepath.Dir(u.Path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("fsnotify watch %s: %w", dir, err)
	}

	// Initial upload after bootstrap so a Path written by the operator
	// before certific started gets pushed up. The dedup hash makes this
	// a no-op when bootstrap already wrote the same bytes back to disk.
	u.uploadWithRetry(ctx, backoff)

	var (
		debounceTimer *time.Timer
		debounceCh    <-chan time.Time
	)
	scheduleUpload := func() {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(debounce)
			debounceCh = debounceTimer.C
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceTimer.Reset(debounce)
		debounceCh = debounceTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			// Flush pending change before returning so a Traefik write that
			// landed inside the debounce window isn't dropped on shutdown.
			// Bound the flush so a wedged S3 can't stall container exit;
			// the next boot will re-read the file and re-upload.
			if debounceCh != nil {
				flushCtx, flushCancel := context.WithTimeout(context.Background(), shutdownFlushTimeout)
				u.uploadWithRetry(flushCtx, backoff)
				flushCancel()
			}
			return nil
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !u.eventMatches(ev) {
				continue
			}
			u.Logger.Debug("fsnotify event", "op", ev.Op.String(), "name", ev.Name)
			scheduleUpload()
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			u.Logger.Warn("fsnotify error", "err", err)
		case <-debounceCh:
			debounceCh = nil
			u.uploadWithRetry(ctx, backoff)
		}
	}
}

// eventMatches filters parent-directory events down to those that touch
// Path. fsnotify gives us every change in the directory; only the ones
// naming our file matter.
func (u *Uploader) eventMatches(ev fsnotify.Event) bool {
	if filepath.Clean(ev.Name) != filepath.Clean(u.Path) {
		return false
	}
	// Write, Create, Rename all indicate the file's contents may have
	// changed (Rename fires on the old name when an atomic writer moves
	// a tempfile over the target; Create fires when something writes
	// straight to the path). Chmod alone doesn't change bytes.
	return ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0
}

// bootstrap seeds Path from S3 before the watch loop starts. A missing
// object is the first-deploy case and is logged but tolerated; any other
// error is fatal because we can't tell if S3 has newer state than the
// local file.
func (u *Uploader) bootstrap(ctx context.Context) error {
	body, etag, err := u.Store.Get(ctx, u.Key)
	if errors.Is(err, ErrNotFound) {
		u.Logger.Info("bootstrap: no object in S3 yet", "key", u.Key)
		// Leave lastHash unset on 404: if the operator has already
		// written a Path locally, the initial-upload pass after the
		// watcher is up should push it to S3 (it's the source of
		// truth — S3 is empty).
		return nil
	}
	if err != nil {
		return fmt.Errorf("bootstrap get: %w", err)
	}
	defer body.Close()
	buf, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("bootstrap read body: %w", err)
	}
	if err := writeFileAtomic(u.Path, buf, 0o600); err != nil {
		return fmt.Errorf("bootstrap write %s: %w", u.Path, err)
	}
	u.lastHash = sha256.Sum256(buf)
	u.hasHash = true
	u.Logger.Info("bootstrap: seeded local file from S3", "key", u.Key, "etag", etag, "bytes", len(buf))
	return nil
}

// uploadWithRetry reads Path, dedupes against lastHash, and Puts to S3
// with exponential backoff on transient errors. Returns when the upload
// succeeds, the file is unchanged, or ctx is cancelled.
func (u *Uploader) uploadWithRetry(ctx context.Context, backoff BackoffConfig) {
	buf, err := os.ReadFile(u.Path)
	if err != nil {
		// The file may not exist yet (an atomic writer between unlink and
		// rename) or may be momentarily unreadable. Log and let the next
		// fsnotify event re-trigger; this is not fatal.
		if !errors.Is(err, os.ErrNotExist) {
			u.Logger.Warn("read acme.json", "path", u.Path, "err", err)
		}
		return
	}
	hash := sha256.Sum256(buf)
	if u.hasHash && hash == u.lastHash {
		u.Logger.Debug("upload: content unchanged, skipping", "path", u.Path)
		return
	}

	delay := backoff.Initial
	for attempt := 1; ; attempt++ {
		if err := u.Store.Put(ctx, u.Key, bytes.NewReader(buf), int64(len(buf))); err != nil {
			if ctx.Err() != nil {
				u.Logger.Warn("upload cancelled", "err", ctx.Err())
				return
			}
			u.Logger.Warn("upload failed, will retry", "attempt", attempt, "delay", delay, "err", err)
			if !sleepCtx(ctx, jitter(delay, backoff.JitterFrac)) {
				return
			}
			delay = nextDelay(delay, backoff)
			continue
		}
		u.lastHash = hash
		u.hasHash = true
		u.Logger.Info("upload ok", "key", u.Key, "bytes", len(buf), "attempt", attempt)
		return
	}
}

func nextDelay(cur time.Duration, b BackoffConfig) time.Duration {
	next := time.Duration(float64(cur) * b.Multiplier)
	if next > b.Max {
		next = b.Max
	}
	return next
}

func jitter(d time.Duration, frac float64) time.Duration {
	if frac <= 0 {
		return d
	}
	// ±frac of d, uniformly distributed
	delta := (rand.Float64()*2 - 1) * frac * float64(d)
	out := time.Duration(float64(d) + delta)
	if out < 0 {
		out = 0
	}
	return out
}

// sleepCtx sleeps for d or until ctx is cancelled. Returns false if
// cancelled (caller should return), true if the full sleep elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// writeFileAtomic writes data to path via a tempfile-in-same-dir + rename
// so a reader (Traefik) never sees a half-written file. acme.json
// contains private keys, so mode is forced to 0o600.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
