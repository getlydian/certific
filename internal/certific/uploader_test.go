package certific

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shortDebounce is small enough that tests aren't slow but large enough
// that a burst of fsnotify events still coalesces into one upload. 50ms
// matches the slowest CI box's wakeup jitter in practice.
const shortDebounce = 50 * time.Millisecond

// fastBackoff makes retry-on-error tests finish in milliseconds. The
// production defaults (1s..60s) would make CI unbearable.
var fastBackoff = BackoffConfig{
	Initial:    5 * time.Millisecond,
	Max:        20 * time.Millisecond,
	Multiplier: 2.0,
	JitterFrac: 0, // deterministic for tests
}

// startUploader runs u.Run in a goroutine and returns a cancel function
// and a done channel. Tests use these to deterministically shut the
// uploader down and wait for it to flush pending work.
func startUploader(t *testing.T, u *Uploader) (cancel context.CancelFunc, done chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		if err := u.Run(ctx); err != nil {
			t.Errorf("Run returned error: %v", err)
		}
		close(done)
	}()
	return cancel, done
}

// waitForObject polls the fake until the named key exists with the
// expected body, or the deadline expires. Direct sleep would race the
// debounce timer; polling is the cheapest reliable signal.
func waitForObject(t *testing.T, store *fakeStore, key string, want []byte, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		store.mu.Lock()
		obj, ok := store.objects[key]
		body := append([]byte(nil), obj.body...)
		store.mu.Unlock()
		if ok && bytes.Equal(body, want) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to equal %q", key, want)
}

func putCount(store *fakeStore) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.putCalls
}

func TestUploaderBootstrapSeedsFromS3(t *testing.T) {
	// Boot path: object already in S3 → uploader writes it to disk before
	// starting the watch loop. This is the "issuer reschedules to a fresh
	// node" case in the design doc.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	seed := []byte(`{"seed":"from-s3"}`)
	if err := store.Put(context.Background(), "acme.json", bytes.NewReader(seed), int64(len(seed))); err != nil {
		t.Fatal(err)
	}
	store.resetCounts()

	u := &Uploader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Debounce: shortDebounce,
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	// Bootstrap is synchronous in Run, so by the time we get here the
	// file must be on disk. Give the initial-upload-after-bootstrap a
	// moment to fire and dedup against the bootstrap hash.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if buf, err := os.ReadFile(path); err == nil && bytes.Equal(buf, seed) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded file: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Errorf("seeded contents = %q, want %q", got, seed)
	}

	// The initial-upload-after-bootstrap should be deduped (file matches
	// what we just downloaded) → zero Puts since resetCounts.
	time.Sleep(3 * shortDebounce)
	if n := putCount(store); n != 0 {
		t.Errorf("expected 0 Puts after bootstrap dedup, got %d", n)
	}
}

func TestUploaderBootstrap404Tolerated(t *testing.T) {
	// First-deploy case: bucket is empty. Uploader must not crash; it
	// also must not create the local file out of nothing.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	u := &Uploader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Debounce: shortDebounce,
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	// Give bootstrap and the initial-upload tick time to run.
	time.Sleep(3 * shortDebounce)

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("local file should not exist after empty-bucket bootstrap, stat err=%v", err)
	}
}

func TestUploaderBootstrapPropagatesNon404Error(t *testing.T) {
	// Anything other than ErrNotFound is fatal: we don't know if S3 has
	// state we'd otherwise clobber on first upload.
	boom := errors.New("connection refused")
	store := &errStore{getErr: boom}

	dir := t.TempDir()
	u := &Uploader{
		Store: store,
		Path:  filepath.Join(dir, "acme.json"),
		Key:   "acme.json",
	}
	err := u.Run(context.Background())
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("Run err = %v, want wrap of %v", err, boom)
	}
}

func TestUploaderUploadsOnWrite(t *testing.T) {
	// Golden path: write the file, watcher fires, debounced upload lands
	// in S3 with the new bytes.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	u := &Uploader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Debounce: shortDebounce,
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	// Wait for bootstrap + initial-upload pass to settle.
	time.Sleep(2 * shortDebounce)
	store.resetCounts()

	payload := []byte(`{"new":"cert"}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	waitForObject(t, store, "acme.json", payload, 2*time.Second)
}

func TestUploaderDebouncesBurst(t *testing.T) {
	// A flurry of writes (Traefik renews several certs at once) must
	// produce one Put, not one per event. The debounce window is the
	// only knob keeping us inside S3 rate limits.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	store := newFakeStore()
	u := &Uploader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Debounce: 100 * time.Millisecond, // larger so burst clearly coalesces
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	time.Sleep(150 * time.Millisecond)
	store.resetCounts()

	for i := 0; i < 5; i++ {
		payload := []byte(`{"n":` + string(rune('0'+i)) + `}`)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Millisecond) // well under debounce
	}

	// Wait long enough for the debounce timer to expire and the upload
	// to land.
	time.Sleep(400 * time.Millisecond)

	if n := putCount(store); n != 1 {
		t.Errorf("burst of 5 writes produced %d Puts, want 1", n)
	}
}

func TestUploaderDedupsUnchangedContent(t *testing.T) {
	// fsnotify fires Write even when bytes don't change (touch, chmod
	// followed by reopen, etc.). The hash check is what prevents us from
	// re-uploading identical content on every spurious event.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	payload := []byte(`{"same":"bytes"}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	store := newFakeStore()
	u := &Uploader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Debounce: shortDebounce,
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	// First upload (initial-after-bootstrap) lands.
	waitForObject(t, store, "acme.json", payload, 2*time.Second)
	store.resetCounts()

	// Re-write the same bytes a few times; nothing should reach S3.
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(3 * shortDebounce)

	if n := putCount(store); n != 0 {
		t.Errorf("dedup failed: %d unnecessary Puts", n)
	}
}

func TestUploaderRetriesOnPutError(t *testing.T) {
	// S3 transient failures must not crash the watch loop. We arrange for
	// the first two Puts to fail and the third to succeed, then assert
	// the file ended up uploaded.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")

	flaky := &flakyStore{
		inner:    newFakeStore(),
		failPuts: 2,
		err:      errors.New("transient s3 error"),
	}

	u := &Uploader{
		Store:    flaky,
		Path:     path,
		Key:      "acme.json",
		Debounce: shortDebounce,
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	time.Sleep(2 * shortDebounce)

	payload := []byte(`{"retry":"me"}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	waitForObject(t, flaky.inner, "acme.json", payload, 2*time.Second)

	if got := atomic.LoadInt32(&flaky.failed); got != 2 {
		t.Errorf("expected 2 failed Puts before success, got %d", got)
	}
}

func TestUploaderFiltersUnrelatedEvents(t *testing.T) {
	// Events on sibling files in the same directory must be ignored — we
	// watch the directory, not the file, so other writes show up here too.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")
	if err := os.WriteFile(path, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newFakeStore()
	u := &Uploader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Debounce: shortDebounce,
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	waitForObject(t, store, "acme.json", []byte("seed"), 2*time.Second)
	store.resetCounts()

	sibling := filepath.Join(dir, "noise.txt")
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(sibling, []byte("noise"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(3 * shortDebounce)

	if n := putCount(store); n != 0 {
		t.Errorf("sibling-file writes triggered %d Puts, want 0", n)
	}
}

func TestUploaderHandlesAtomicRename(t *testing.T) {
	// The atomic-write pattern (write tempfile + rename over target) is
	// what Traefik itself uses. Watching the parent dir is what lets us
	// notice it; this test pins that behaviour.
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newFakeStore()
	u := &Uploader{
		Store:    store,
		Path:     path,
		Key:      "acme.json",
		Debounce: shortDebounce,
		Backoff:  fastBackoff,
	}
	cancel, done := startUploader(t, u)
	defer func() { cancel(); <-done }()

	waitForObject(t, store, "acme.json", []byte("old"), 2*time.Second)

	tmp := filepath.Join(dir, "acme.json.new")
	payload := []byte(`{"renamed":"in"}`)
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	waitForObject(t, store, "acme.json", payload, 2*time.Second)
}

// errStore is a degenerate ObjectStore that only knows how to fail Get.
// Used to test bootstrap's non-404 error propagation without dragging in
// a full mocked SDK.
type errStore struct{ getErr error }

func (e *errStore) Get(context.Context, string) (io.ReadCloser, string, error) {
	return nil, "", e.getErr
}
func (e *errStore) Put(context.Context, string, io.Reader, int64) error {
	return errors.New("errStore: Put not implemented")
}
func (e *errStore) Head(context.Context, string) (string, time.Time, error) {
	return "", time.Time{}, errors.New("errStore: Head not implemented")
}

// flakyStore wraps fakeStore and fails the first N Puts to exercise the
// uploader's retry loop. After the budget is exhausted, calls forward to
// the inner store.
type flakyStore struct {
	inner    *fakeStore
	mu       sync.Mutex
	failPuts int
	failed   int32
	err      error
}

func (f *flakyStore) Get(ctx context.Context, key string) (io.ReadCloser, string, error) {
	return f.inner.Get(ctx, key)
}
func (f *flakyStore) Head(ctx context.Context, key string) (string, time.Time, error) {
	return f.inner.Head(ctx, key)
}
func (f *flakyStore) Put(ctx context.Context, key string, body io.Reader, n int64) error {
	f.mu.Lock()
	if f.failPuts > 0 {
		f.failPuts--
		f.mu.Unlock()
		atomic.AddInt32(&f.failed, 1)
		// Drain the body so the caller's bytes.Reader doesn't surprise
		// the next attempt (it won't — we hand a fresh reader each
		// retry — but draining mirrors real S3 behaviour on error).
		_, _ = io.Copy(io.Discard, body)
		return f.err
	}
	f.mu.Unlock()
	return f.inner.Put(ctx, key, body, n)
}

var _ ObjectStore = (*flakyStore)(nil)
var _ ObjectStore = (*errStore)(nil)
