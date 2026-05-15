package certific

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// Downloader polls S3 for changes to a single object and atomically
// replaces a local file when the remote etag changes. One instance per
// gateway: the design assumes many readers per writer, and each gateway
// runs its own copy alongside its Traefik replica.
//
// Lifecycle:
//  1. Each cycle, call Head on the object. Compare etag with the
//     last-seen value. Same etag → skip (the common case once the
//     cluster is in steady state).
//  2. Different etag (or first iteration): Get to a tempfile in the
//     same directory as Path, chmod 0600, then os.Rename onto Path.
//     Same-filesystem rename is atomic, so the colocated Traefik never
//     reads a partial file.
//  3. ErrNotFound on Head is tolerated — it's the first-deploy case
//     (writer hasn't uploaded yet). Other errors retry with
//     exponential backoff + jitter.
//
// "Head before Get" matters because acme.json grows with every issued
// cert; in steady state we Get nothing and pay one ~200-byte Head per
// interval instead of refetching the whole blob.
type Downloader struct {
	Store    ObjectStore
	Path     string
	Key      string
	Interval time.Duration
	Logger   *slog.Logger
	Backoff  BackoffConfig // zero → defaultBackoff

	// After is a seam for tests. Production leaves it nil and the loop
	// uses time.After; tests inject a fake clock to drive cycles
	// deterministically without sleeping for --interval.
	After func(time.Duration) <-chan time.Time

	// lastEtag is the etag of the most recently downloaded object. Empty
	// means "we have not successfully downloaded anything yet" — used to
	// force a Get on the first successful Head even if Head and a
	// previous Get on another process happen to agree.
	lastEtag string
}

// Run blocks until ctx is cancelled. Transient S3 errors are logged and
// retried on the next cycle; they do not return an error. The only way
// Run returns non-nil is if the loop set-up itself fails, which is
// currently impossible — kept as an error return so future additions
// (e.g. health-endpoint registration in step 8) have a place to surface
// fatal startup errors.
func (d *Downloader) Run(ctx context.Context) error {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Interval <= 0 {
		return fmt.Errorf("downloader: interval must be > 0, got %s", d.Interval)
	}
	backoff := d.Backoff
	if backoff == (BackoffConfig{}) {
		backoff = defaultBackoff
	}
	after := d.After
	if after == nil {
		after = time.After
	}

	// First cycle runs immediately so the gateway converges as fast as
	// possible after boot. Waiting one full --interval before the first
	// fetch would mean up to 60s of stale (or missing) certs after a
	// restart for no reason.
	d.cycle(ctx, backoff)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-after(d.Interval):
			d.cycle(ctx, backoff)
		}
	}
}

// cycle runs one Head-then-maybe-Get pass. Errors are logged but never
// returned: the downloader's contract with operators is "keep running,
// alert externally on last-sync age." A Head failure this cycle just
// means we try again next cycle.
func (d *Downloader) cycle(ctx context.Context, backoff BackoffConfig) {
	delay := backoff.Initial
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		err := d.tryCycle(ctx)
		if err == nil {
			return
		}
		if errors.Is(err, errSkipped) {
			// Etag unchanged — common case, debug-level only.
			d.Logger.Debug("download: etag unchanged, skipping", "key", d.Key, "etag", d.lastEtag)
			return
		}
		if errors.Is(err, ErrNotFound) {
			// First-deploy: writer hasn't uploaded yet. Not an error
			// state in the operational sense; we'll check again next
			// cycle. Log at info so it's visible during bring-up but
			// doesn't trip warning-level alerts.
			d.Logger.Info("download: object not in S3 yet", "key", d.Key)
			return
		}
		d.Logger.Warn("download cycle failed, will retry", "attempt", attempt, "delay", delay, "err", err)
		if !sleepCtx(ctx, jitter(delay, backoff.JitterFrac)) {
			return
		}
		delay = nextDelay(delay, backoff)
	}
}

// errSkipped is an internal sentinel meaning "Head said the etag matches
// what we already have." Treated as success by cycle so the retry loop
// exits cleanly without logging at warning level.
var errSkipped = errors.New("etag unchanged")

func (d *Downloader) tryCycle(ctx context.Context) error {
	etag, _, err := d.Store.Head(ctx, d.Key)
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}
	if etag != "" && etag == d.lastEtag {
		return errSkipped
	}

	body, getEtag, err := d.Store.Get(ctx, d.Key)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer body.Close()

	buf, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if err := writeFileAtomic(d.Path, buf, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", d.Path, err)
	}

	// Prefer the Head etag (the value we'll compare on the next cycle)
	// but fall back to the Get etag if Head returned an empty string —
	// some S3-compatible stores omit the header on Head responses.
	newEtag := etag
	if newEtag == "" {
		newEtag = getEtag
	}
	d.lastEtag = newEtag
	d.Logger.Info("download ok", "key", d.Key, "bytes", len(buf), "etag", newEtag, "path", d.Path)
	return nil
}
