package certific

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"
)

// DefaultKeepVersions is the number of past rendered snapshots retained
// under <OutDir>/versions/ after a successful swap. One is enough to roll
// back manually if a bad acme.json reaches gateways; more is wasted disk.
const DefaultKeepVersions = 2

// Downloader polls S3 for changes to acme.json and, when the remote
// etag changes, fetches it, parses it into per-domain cert/key PEMs,
// and atomically swaps a `current` symlink under OutDir to point at the
// new versioned snapshot. Traefik's file provider, pointed at
// <OutDir>/current, sees a consistent directory at all times.
//
// The gateway-side Traefik has NO certificatesResolvers configured — it
// can't even attempt ACME. It only loads the cert files the file
// provider points it at. That's the whole point of this design: the
// raw acme.json never reaches gateways, only the cert material it
// happens to contain.
//
// Lifecycle:
//  1. Each cycle, call Head on the object. Compare etag with the
//     last-seen value. Same etag → skip (the common case once the
//     cluster is in steady state).
//  2. Different etag (or first iteration): Get the object, parse it,
//     render PEMs to <OutDir>/versions/<id>/, swap the
//     <OutDir>/current symlink. Same-directory rename of the symlink
//     is atomic, so Traefik never sees a half-applied update.
//  3. ErrNotFound on Head/Get is tolerated — it's the first-deploy case
//     (writer hasn't uploaded yet). We render an empty snapshot so
//     <OutDir>/current still exists; Traefik's file provider needs a
//     directory to start against. Other errors retry with exponential
//     backoff + jitter.
//
// "Head before Get" matters because acme.json grows with every issued
// cert; in steady state we Get nothing and pay one ~200-byte Head per
// interval instead of refetching the whole blob.
type Downloader struct {
	Store ObjectStore
	// OutDir is the directory under which `current/` (symlink) and
	// `versions/<id>/` snapshots live. Traefik should be pointed at
	// `<OutDir>/current` via --providers.file.directory.
	OutDir   string
	Key      string
	Interval time.Duration
	Logger   *slog.Logger
	Backoff  BackoffConfig // zero → defaultBackoff
	// Keep is the number of past snapshots to retain after each
	// successful render. Zero falls back to DefaultKeepVersions; pass a
	// negative value to retain none.
	Keep int

	// After is a seam for tests. Production leaves it nil and the loop
	// uses time.After; tests inject a fake clock to drive cycles
	// deterministically without sleeping for --interval.
	After func(time.Duration) <-chan time.Time

	// lastEtag is the etag of the most recently downloaded object. Empty
	// means "we have not successfully downloaded anything yet" — used to
	// force a Get on the first successful Head even if Head and a
	// previous Get on another process happen to agree.
	lastEtag string

	// lastSyncUnixNano is the unix-nano timestamp of the most recent
	// successful cycle (Head returning a result, including "etag
	// unchanged" and ErrNotFound). Read concurrently by the health
	// endpoint; stored as atomic.Int64 to avoid a mutex on the hot path.
	lastSyncUnixNano atomic.Int64
}

// LastSync returns the time of the most recent successful poll cycle.
// "Successful" includes etag-unchanged skips and 404 responses — both
// confirm S3 is reachable. The zero value means "nothing successful
// yet"; used by the health endpoint to decide /healthz status. Safe to
// call from any goroutine.
func (d *Downloader) LastSync() time.Time {
	n := d.lastSyncUnixNano.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func (d *Downloader) markSync(t time.Time) {
	d.lastSyncUnixNano.Store(t.UnixNano())
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
			// Etag unchanged — common case, debug-level only. Still a
			// successful Head; refresh lastSync so /healthz reflects
			// reachability not staleness.
			d.markSync(time.Now())
			d.Logger.Debug("download: etag unchanged, skipping", "key", d.Key, "etag", d.lastEtag)
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
		if errors.Is(err, ErrNotFound) {
			// First-deploy: writer hasn't uploaded acme.json yet. Render
			// an empty snapshot so <OutDir>/current exists and Traefik's
			// file provider can start with an empty tls.certificates
			// list. Without this, a gateway pointed at a not-yet-extant
			// directory hangs on startup (or, with a directory-existence
			// healthcheck, loops unhealthy forever).
			return d.renderEmpty()
		}
		return fmt.Errorf("head: %w", err)
	}
	if etag != "" && etag == d.lastEtag {
		return errSkipped
	}

	body, getEtag, err := d.Store.Get(ctx, d.Key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Head→Get race: object disappeared between calls. Same
			// reasoning as the Head-404 branch.
			return d.renderEmpty()
		}
		return fmt.Errorf("get: %w", err)
	}
	defer func() { _ = body.Close() }()

	buf, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	certs, err := ParseAcme(buf)
	if err != nil {
		// A parse error is loud but recoverable: the issuer may have
		// uploaded a transient bad file, or the format may have changed.
		// We don't poison lastEtag — next cycle re-Gets and tries again.
		return fmt.Errorf("parse acme.json: %w", err)
	}

	keep := d.Keep
	if keep == 0 {
		keep = DefaultKeepVersions
	}
	versionDir, pruned, err := Render(d.OutDir, certs, keep)
	if err != nil {
		return fmt.Errorf("render to %s: %w", d.OutDir, err)
	}

	// Prefer the Head etag (the value we'll compare on the next cycle)
	// but fall back to the Get etag if Head returned an empty string —
	// some S3-compatible stores omit the header on Head responses.
	newEtag := etag
	if newEtag == "" {
		newEtag = getEtag
	}
	d.lastEtag = newEtag
	d.markSync(time.Now())
	d.Logger.Info("download ok",
		"key", d.Key,
		"bytes", len(buf),
		"etag", newEtag,
		"version", versionDir,
		"certs", len(certs),
		"pruned", len(pruned),
	)
	return nil
}

// renderEmpty writes a versioned snapshot with no certs and points
// `current` at it. Used when acme.json is missing or contains no usable
// certs: Traefik still needs <OutDir>/current to exist so the file
// provider can load (an empty tls.certificates list is valid).
//
// lastEtag stays empty so the very next cycle re-Heads and re-Gets once
// the writer uploads — the Render call is content-addressed, so calling
// it repeatedly with the same empty input is a cheap no-op after the
// first one.
func (d *Downloader) renderEmpty() error {
	keep := d.Keep
	if keep == 0 {
		keep = DefaultKeepVersions
	}
	versionDir, _, err := Render(d.OutDir, nil, keep)
	if err != nil {
		return fmt.Errorf("render empty snapshot to %s: %w", d.OutDir, err)
	}
	d.markSync(time.Now())
	// Debug-level: this fires every cycle while acme.json is missing or
	// empty, and the first-deploy state can persist indefinitely. Render
	// itself is a content-addressed no-op after the first call, so the
	// log line is the only per-cycle cost worth suppressing.
	d.Logger.Debug("download: no certs yet, re-rendered empty snapshot (idempotent)",
		"key", d.Key,
		"version", versionDir,
	)
	return nil
}
