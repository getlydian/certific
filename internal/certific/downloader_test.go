package certific

import (
	"bytes"
	"context"
	"errors"
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

// waitForFile polls until path contains want or the deadline expires.
// Same shape as waitForObject on the uploader side.
func waitForFile(t *testing.T, path string, want []byte, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		got, err := os.ReadFile(path)
		if err == nil && bytes.Equal(got, want) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to equal %q", path, want)
}

func TestDownloaderFirstCycleFetches(t *testing.T) {
	// Boot path: object is already in S3 (writer ran first). Downloader
	// must fetch it on its first cycle without waiting for an interval.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	payload := []byte(`{"first":"download"}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForFile(t, path, payload, 2*time.Second)
}

func TestDownloaderSkipsUnchangedEtag(t *testing.T) {
	// Steady-state: writer hasn't issued any new certs, etag is stable.
	// Downloader must Head every interval but Get nothing.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	payload := []byte(`{"unchanged":"yes"}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	counts := &countingStore{inner: store}
	clock := newFakeClock()

	d := &Downloader{
		Store:    counts,
		Path:     path,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	// First cycle fires immediately on Run; wait for the file to land.
	waitForFile(t, path, payload, 2*time.Second)
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
	// Wait for the third extra cycle to complete by waiting for the
	// next After registration.
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
	// downloader Gets the new bytes and atomically replaces the file.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	v1 := []byte(`{"v":1}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(v1), int64(len(v1))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForFile(t, path, v1, 2*time.Second)

	// Mutate the S3 object: same key, new bytes → new etag.
	v2 := []byte(`{"v":2}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(v2), int64(len(v2))); err != nil {
		t.Fatal(err)
	}

	clock.waitForWaiter(t)
	clock.tick()

	waitForFile(t, path, v2, 2*time.Second)
}

func TestDownloaderTolerates404OnFirstCycle(t *testing.T) {
	// First-ever deploy: bucket is empty. Downloader must not crash and
	// must not create a local file out of nothing.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	clock.waitForWaiter(t)

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("local file should not exist after empty-bucket cycle, stat err=%v", err)
	}

	// Now the writer uploads. Tick the clock and expect the file to
	// appear — confirms the 404-tolerant path doesn't poison lastEtag.
	payload := []byte(`{"finally":"there"}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	clock.tick()
	waitForFile(t, path, payload, 2*time.Second)
}

func TestDownloaderRetriesOnTransientError(t *testing.T) {
	// S3 hiccups during a cycle must not crash the downloader. cycle()
	// retries within the same tick using backoff; we verify the file
	// eventually lands after two transient Head failures.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	inner := newFakeStore()
	payload := []byte(`{"retry":"works"}`)
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
		Path:     path,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForFile(t, path, payload, 2*time.Second)
	if got := atomic.LoadInt32(&flaky.failed); got != 2 {
		t.Errorf("expected 2 failed Heads before success, got %d", got)
	}
}

func TestDownloaderWritesMode0600(t *testing.T) {
	// acme.json contains private keys. The atomic-replace path must end
	// with mode 0600 even if the tempfile was created with the default
	// umask-influenced mode.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	payload := []byte(`{"secret":"keys"}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForFile(t, path, payload, 2*time.Second)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}
}

func TestDownloaderAtomicReplace(t *testing.T) {
	// Verify the rename-after-tempfile pattern by pre-populating Path
	// with old content; while the new bytes are in flight a concurrent
	// reader must see either the old or the new file, never a partial
	// one. Race-checking is hard; what we *can* verify is that the
	// downloader never opens Path for writing directly (no truncation
	// window), which we approximate by checking no .tmp-* leftovers
	// remain in the directory after success.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newFakeStore()
	payload := []byte(`{"new":"contents"}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Interval: 60 * time.Second,
		Backoff:  fastBackoff,
		After:    clock.After,
	}
	cancel, done := startDownloader(t, d)
	defer func() { cancel(); <-done }()

	waitForFile(t, path, payload, 2*time.Second)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "acme.json" {
			continue
		}
		t.Errorf("unexpected leftover file in dir: %s", e.Name())
	}
}

func TestDownloaderCancellationReturns(t *testing.T) {
	// Context cancellation must stop Run promptly even while waiting on
	// the After channel. Without this property, SIGTERM would hang for
	// up to one interval (60s in production) before the container exits.
	dir := t.TempDir()
	store := newFakeStore()
	clock := newFakeClock()
	d := &Downloader{
		Store:    store,
		Path:     filepath.Join(dir, "acme.json"),
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
		Path:     "/tmp/never-used",
		Key:      "acme.json",
		Interval: 0,
	}
	err := d.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for zero interval, got nil")
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
