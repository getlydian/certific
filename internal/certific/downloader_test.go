package certific

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock drives the downloader's After channel deterministically. The
// downloader's loop calls After(interval) once per cycle and blocks on
// the returned channel; tests advance the clock by sending on the
// pending channel rather than sleeping.
type fakeClock struct {
	mu      sync.Mutex
	pending []chan time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{} }

// After mirrors time.After: returns a channel that yields when the test
// calls tick(). The duration argument is ignored — the test, not the
// clock, decides when "interval" has elapsed.
func (c *fakeClock) After(_ time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.pending = append(c.pending, ch)
	return ch
}

// waitForWaiter blocks until at least one pending After channel exists.
// The downloader's loop registers its waiter asynchronously after each
// cycle; tests that tick immediately after a cycle would otherwise race
// the registration.
func (c *fakeClock) waitForWaiter(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.pending)
		c.mu.Unlock()
		if n > 0 {
			return
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no After waiter registered within 2s")
}

// tick releases one pending After channel, simulating one interval
// elapsing. Returns true if a waiter was released, false if none was
// pending (test bug, usually).
func (c *fakeClock) tick() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return false
	}
	ch := c.pending[0]
	c.pending = c.pending[1:]
	ch <- time.Now()
	return true
}

// startDownloader runs d.Run in a goroutine and returns cancel + done
// so tests deterministically tear it down. Mirrors startUploader.
func startDownloader(t *testing.T, d *Downloader) (cancel context.CancelFunc, done chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		if err := d.Run(ctx); err != nil {
			t.Errorf("Run returned error: %v", err)
		}
		close(done)
	}()
	return cancel, done
}

// fakeCert represents one cert+key pair used to build a synthetic
// acme.json payload. ParseAcme only base64-decodes the bytes — it does
// not verify PEM structure — so test fixtures don't need to be real
// X.509. Any deterministic byte string is fine and keeps the tests
// fast and dependency-free.
type fakeCert struct {
	main string
	sans []string
	cert []byte
	key  []byte
}

// buildAcmeJSON renders a minimal Traefik-shaped acme.json carrying the
// given certs under one resolver name. Used by tests that need real
// downstream rendering, not just an opaque blob.
func buildAcmeJSON(resolver string, certs ...fakeCert) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `{%q:{"Account":{},"Certificates":[`, resolver)
	for i, c := range certs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"domain":{"main":%q`, c.main)
		if len(c.sans) > 0 {
			b.WriteString(`,"sans":[`)
			for j, s := range c.sans {
				if j > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, "%q", s)
			}
			b.WriteByte(']')
		}
		fmt.Fprintf(&b, `},"certificate":%q,"key":%q}`,
			base64.StdEncoding.EncodeToString(c.cert),
			base64.StdEncoding.EncodeToString(c.key),
		)
	}
	b.WriteString(`]}}`)
	return b.Bytes()
}

// waitForRendered polls until <outDir>/current/<slug>.crt contains want,
// or the deadline expires. The downloader rewrites the symlink atomically
// at the end of each successful cycle, so any read through `current/`
// either sees the previous snapshot or the new one — never a partial.
func waitForRendered(t *testing.T, outDir, slug string, want []byte, deadline time.Duration) {
	t.Helper()
	path := filepath.Join(outDir, "current", slug+".crt")
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		got, err := os.ReadFile(path)
		if err == nil && bytes.Equal(got, want) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to equal %d bytes", path, len(want))
}

// waitForEmptySnapshot polls until <outDir>/current resolves to a
// directory whose tls.yml lists no certificates. Used after a
// 404-on-first-cycle to confirm we still produced a directory Traefik
// can start against — even though no certs have been issued yet.
func waitForEmptySnapshot(t *testing.T, outDir string, deadline time.Duration) {
	t.Helper()
	tlsPath := filepath.Join(outDir, "current", "tls.yml")
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		body, err := os.ReadFile(tlsPath)
		if err == nil && bytes.Contains(body, []byte("certificates: []")) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for empty snapshot at %s", tlsPath)
}

func TestDownloaderFirstCycleRendersCerts(t *testing.T) {
	// Boot path: object is already in S3 (writer ran first). Downloader
	// must fetch and render to <OutDir>/current on its first cycle
	// without waiting for an interval.
	outDir := t.TempDir()

	store := newFakeStore()
	payload := buildAcmeJSON("dns", fakeCert{
		main: "example.com",
		cert: []byte("---cert-bytes---"),
		key:  []byte("---key-bytes---"),
	})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForRendered(t, outDir, "example.com", []byte("---cert-bytes---"), 2*time.Second)

	// tls.yml should reference the rendered cert by relative filename so
	// Traefik's file provider, pointed at <outDir>/current, can load it
	// without any path translation.
	tlsYml, err := os.ReadFile(filepath.Join(outDir, "current", "tls.yml"))
	if err != nil {
		t.Fatalf("read tls.yml: %v", err)
	}
	if !bytes.Contains(tlsYml, []byte("example.com.crt")) {
		t.Errorf("tls.yml missing cert reference: %s", tlsYml)
	}
}

func TestDownloaderSkipsUnchangedEtag(t *testing.T) {
	// Steady-state: writer hasn't issued any new certs, etag is stable.
	// Downloader must Head every interval but Get nothing.
	outDir := t.TempDir()

	store := newFakeStore()
	payload := buildAcmeJSON("dns", fakeCert{
		main: "example.com",
		cert: []byte("cert"),
		key:  []byte("key"),
	})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	counts := &countingStore{inner: store}
	clock := newFakeClock()

	d := &Downloader{
		Store:    counts,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	// First cycle fires immediately on Run; wait for the cert to land.
	waitForRendered(t, outDir, "example.com", []byte("cert"), 2*time.Second)
	firstGets := atomic.LoadInt32(&counts.getCalls)
	if firstGets != 1 {
		t.Fatalf("first cycle should Get once, got %d", firstGets)
	}

	// Drive three more cycles. Etag is stable, so Head fires three more
	// times but Get must not.
	for i := 0; i < 3; i++ {
		clock.waitForWaiter(t)
		if !clock.tick() {
			t.Fatal("expected pending waiter")
		}
	}
	clock.waitForWaiter(t)

	gets := atomic.LoadInt32(&counts.getCalls)
	heads := atomic.LoadInt32(&counts.headCalls)
	if gets != 1 {
		t.Errorf("Get calls = %d, want 1 (etag was unchanged across cycles)", gets)
	}
	if heads < 4 {
		t.Errorf("Head calls = %d, want >= 4 (one per cycle)", heads)
	}
}

func TestDownloaderFetchesOnEtagChange(t *testing.T) {
	// Writer issues a new cert → acme.json changes → etag changes →
	// downloader Gets, re-renders, and swaps `current` to the new dir.
	outDir := t.TempDir()

	store := newFakeStore()
	v1 := buildAcmeJSON("dns", fakeCert{main: "example.com", cert: []byte("v1cert"), key: []byte("v1key")})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(v1), int64(len(v1))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForRendered(t, outDir, "example.com", []byte("v1cert"), 2*time.Second)

	// Mutate the S3 object: same key, new bytes → new etag.
	v2 := buildAcmeJSON("dns", fakeCert{main: "example.com", cert: []byte("v2cert"), key: []byte("v2key")})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(v2), int64(len(v2))); err != nil {
		t.Fatal(err)
	}

	clock.waitForWaiter(t)
	clock.tick()

	waitForRendered(t, outDir, "example.com", []byte("v2cert"), 2*time.Second)
}

func TestDownloaderTolerates404OnFirstCycle(t *testing.T) {
	// First-ever deploy: bucket is empty. Downloader must not crash and
	// must still produce <OutDir>/current — pointing at an empty
	// snapshot — so Traefik can start its file provider against a real
	// directory instead of looping unhealthy.
	outDir := t.TempDir()

	store := newFakeStore()
	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	clock.waitForWaiter(t)
	waitForEmptySnapshot(t, outDir, 2*time.Second)

	// Now the writer uploads. Tick the clock and expect the rendered
	// cert to appear — confirms the 404-tolerant path doesn't poison
	// lastEtag.
	payload := buildAcmeJSON("dns", fakeCert{main: "finally.example", cert: []byte("therecert"), key: []byte("therekey")})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	clock.tick()
	waitForRendered(t, outDir, "finally.example", []byte("therecert"), 2*time.Second)
}

func TestDownloaderToleratesEmptyAcmeJSON(t *testing.T) {
	// An uploader bug (or a bad hand-edit) can land 0 bytes in S3.
	// Without a guard, the downloader retries-forever on
	// "unexpected end of JSON input" and never renders <OutDir>/current,
	// stranding Traefik. Empty body should be treated like first-deploy.
	outDir := t.TempDir()

	store := newFakeStore()
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(nil), 0); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForEmptySnapshot(t, outDir, 2*time.Second)

	// Once real content lands, the downloader must pick it up — the
	// empty-body branch must not poison lastEtag.
	clock.waitForWaiter(t)
	payload := buildAcmeJSON("dns", fakeCert{main: "later.example", cert: []byte("realcert"), key: []byte("realkey")})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	clock.tick()
	waitForRendered(t, outDir, "later.example", []byte("realcert"), 2*time.Second)
}

func TestDownloaderRetriesOnTransientError(t *testing.T) {
	// S3 hiccups during a cycle must not crash the downloader. cycle()
	// retries within the same tick using backoff; we verify the file
	// eventually lands after two transient Head failures.
	outDir := t.TempDir()

	inner := newFakeStore()
	payload := buildAcmeJSON("dns", fakeCert{main: "retry.example", cert: []byte("worksbytes"), key: []byte("keybytes")})
	if err := inner.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	flaky := &flakyHeadStore{
		inner:     inner,
		failHeads: 2,
		err:       errors.New("transient head failure"),
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    flaky,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForRendered(t, outDir, "retry.example", []byte("worksbytes"), 2*time.Second)
	if got := atomic.LoadInt32(&flaky.failed); got != 2 {
		t.Errorf("expected 2 failed Heads before success, got %d", got)
	}
}

func TestDownloaderWritesMode0600(t *testing.T) {
	// Rendered .crt/.key files contain private keys. The renderer must
	// end with mode 0600 on every output file, even if the umask would
	// otherwise produce a wider mode.
	outDir := t.TempDir()

	store := newFakeStore()
	payload := buildAcmeJSON("dns", fakeCert{main: "secret.example", cert: []byte("cert"), key: []byte("private")})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForRendered(t, outDir, "secret.example", []byte("cert"), 2*time.Second)

	for _, name := range []string{"secret.example.crt", "secret.example.key", "tls.yml"} {
		info, err := os.Stat(filepath.Join(outDir, "current", name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, perm)
		}
	}
}

func TestDownloaderAtomicSwap(t *testing.T) {
	// Verify the symlink-swap pattern by pre-populating OutDir with an
	// older snapshot pointed-at by `current`. After a successful cycle,
	// `current` must still resolve to a populated, internally-consistent
	// directory (no half-written tls.yml). We approximate atomicity by
	// checking that `current` is a symlink targeting a `versions/<id>/`
	// dir, and that no `.tmp` staging dirs remain after success.
	outDir := t.TempDir()

	store := newFakeStore()
	v1 := buildAcmeJSON("dns", fakeCert{main: "first.example", cert: []byte("a"), key: []byte("b")})
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(v1), int64(len(v1))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForRendered(t, outDir, "first.example", []byte("a"), 2*time.Second)

	// current must be a symlink, not a real directory — that's the
	// whole atomicity contract.
	info, err := os.Lstat(filepath.Join(outDir, "current"))
	if err != nil {
		t.Fatalf("lstat current: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("current is not a symlink (mode=%v)", info.Mode())
	}

	// No leftover .tmp staging dirs after the cycle.
	entries, err := os.ReadDir(filepath.Join(outDir, "versions"))
	if err != nil {
		t.Fatalf("read versions: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover staging dir: %s", e.Name())
		}
	}
}

func TestDownloaderCancellationReturns(t *testing.T) {
	// Context cancellation must stop Run promptly even while waiting on
	// the After channel. Without this property, SIGTERM would hang for
	// up to one interval (60s in production) before the container exits.
	outDir := t.TempDir()
	store := newFakeStore()
	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: time.Hour, // long enough that real time.After would hang the test
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)

	clock.waitForWaiter(t)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}
}

func TestDownloaderRejectsZeroInterval(t *testing.T) {
	// Defensive: LoadConfig validates Interval bounds, but the
	// Downloader is also reachable from tests / future callers. A zero
	// interval would busy-loop, so it's worth a sharp error.
	d := &Downloader{
		Store:    newFakeStore(),
		OutDir:   "/tmp/never-used",
		Key:      "acme.json",
		Interval: 0,
	}
	err := d.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for zero interval, got nil")
	}
}

func TestDownloaderPrunesOldSnapshots(t *testing.T) {
	// After three distinct renders with Keep=1, `versions/` should
	// contain at most two dirs: the active one and one prior. Sanity
	// check on the prune wiring; full prune logic is exercised by
	// render_test.go.
	outDir := t.TempDir()
	store := newFakeStore()
	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		OutDir:   outDir,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
		Keep:     1,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	for i, body := range [][]byte{
		buildAcmeJSON("dns", fakeCert{main: "a.example", cert: []byte("a1"), key: []byte("k1")}),
		buildAcmeJSON("dns", fakeCert{main: "a.example", cert: []byte("a2"), key: []byte("k2")}),
		buildAcmeJSON("dns", fakeCert{main: "a.example", cert: []byte("a3"), key: []byte("k3")}),
	} {
		if err := store.Put(context.Background(), "acme.json", bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
		// Wait for the loop's After waiter to register before ticking.
		// On i=0 the immediate-first cycle has typically already raced
		// past our Put and 404'd, so we still need a tick to pick up the
		// freshly-staged payload — the 404 path leaves lastEtag empty,
		// so the next Head will trigger a Get.
		clock.waitForWaiter(t)
		clock.tick()
		// Each render embeds a wall-clock second in the version id, so
		// without this pause two consecutive renders can land in the
		// same id and short-circuit to "directory already exists" —
		// which is correct behaviour but defeats the test.
		time.Sleep(1100 * time.Millisecond)
		// Wait for the cert from this iteration to be the active one.
		wantCert := []byte(fmt.Sprintf("a%d", i+1))
		waitForRendered(t, outDir, "a.example", wantCert, 2*time.Second)
	}

	entries, err := os.ReadDir(filepath.Join(outDir, "versions"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs int
	for _, e := range entries {
		if e.IsDir() && filepath.Ext(e.Name()) != ".tmp" {
			dirs++
		}
	}
	// active + Keep=1 prior = 2 expected.
	if dirs > 2 {
		t.Errorf("versions/ contains %d dirs, want ≤ 2 with Keep=1", dirs)
	}
}

// countingStore wraps a fakeStore and counts Head/Get calls so tests can
// assert "Head fires every cycle, Get only on etag change."
type countingStore struct {
	inner     *fakeStore
	headCalls int32
	getCalls  int32
}

func (c *countingStore) Head(ctx context.Context, key string) (string, time.Time, error) {
	atomic.AddInt32(&c.headCalls, 1)
	return c.inner.Head(ctx, key)
}
func (c *countingStore) Get(ctx context.Context, key string) (io.ReadCloser, string, error) {
	atomic.AddInt32(&c.getCalls, 1)
	return c.inner.Get(ctx, key)
}
func (c *countingStore) Put(ctx context.Context, key string, body io.Reader, n int64) error {
	return c.inner.Put(ctx, key, body, n)
}

// flakyHeadStore fails the first N Head calls, then forwards. Exercises
// the downloader's same-cycle retry loop without needing a flaky Get
// (which would race the atomic-replace).
type flakyHeadStore struct {
	inner     *fakeStore
	mu        sync.Mutex
	failHeads int
	failed    int32
	err       error
}

func (f *flakyHeadStore) Head(ctx context.Context, key string) (string, time.Time, error) {
	f.mu.Lock()
	if f.failHeads > 0 {
		f.failHeads--
		f.mu.Unlock()
		atomic.AddInt32(&f.failed, 1)
		return "", time.Time{}, f.err
	}
	f.mu.Unlock()
	return f.inner.Head(ctx, key)
}
func (f *flakyHeadStore) Get(ctx context.Context, key string) (io.ReadCloser, string, error) {
	return f.inner.Get(ctx, key)
}
func (f *flakyHeadStore) Put(ctx context.Context, key string, body io.Reader, n int64) error {
	return f.inner.Put(ctx, key, body, n)
}

var (
	_ ObjectStore = (*countingStore)(nil)
	_ ObjectStore = (*flakyHeadStore)(nil)
)
