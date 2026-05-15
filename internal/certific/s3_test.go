package certific

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// fakeStore is the in-memory ObjectStore used to exercise uploader/
// downloader code paths without a live S3. Keeping it next to S3Store
// makes the contract obvious: same interface, no network. Concurrent-safe
// because the uploader's debounce timer can fire from one goroutine while
// tests poke another.
type fakeStore struct {
	mu       sync.Mutex
	objects  map[string]fakeObject
	putCalls int
}

type fakeObject struct {
	body         []byte
	etag         string
	lastModified time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: make(map[string]fakeObject)}
}

func (f *fakeStore) Get(_ context.Context, key string) (io.ReadCloser, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[key]
	if !ok {
		return nil, "", ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(obj.body)), obj.etag, nil
}

func (f *fakeStore) Put(_ context.Context, key string, body io.Reader, contentLength int64) error {
	buf, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(buf)) != contentLength {
		return fmt.Errorf("fake put: contentLength %d != body len %d", contentLength, len(buf))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putCalls++
	f.objects[key] = fakeObject{
		body:         buf,
		etag:         fmt.Sprintf("%q", md5sum(buf)),
		lastModified: time.Now().UTC(),
	}
	return nil
}

// resetCounts clears observable counters but leaves stored objects in
// place. Uploader tests use it to ignore Puts that happen during the
// bootstrap/initial-upload settle window.
func (f *fakeStore) resetCounts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putCalls = 0
}

func (f *fakeStore) Head(_ context.Context, key string) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[key]
	if !ok {
		return "", time.Time{}, ErrNotFound
	}
	return obj.etag, obj.lastModified, nil
}

func md5sum(b []byte) string {
	sum := md5.Sum(b)
	return fmt.Sprintf("%x", sum)
}

// Compile-time check: fakeStore satisfies ObjectStore. Pinned in a test
// rather than the production file so the fake stays a test-only concern.
var _ ObjectStore = (*fakeStore)(nil)
var _ ObjectStore = (*S3Store)(nil)

func TestFakeStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()

	if _, _, err := store.Get(ctx, "acme.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty store: err = %v, want ErrNotFound", err)
	}
	if _, _, err := store.Head(ctx, "acme.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Head on empty store: err = %v, want ErrNotFound", err)
	}

	payload := []byte(`{"hello":"world"}`)
	if err := store.Put(ctx, "acme.json", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rc, etag, err := store.Get(ctx, "acme.json")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("body = %q, want %q", got, payload)
	}
	if etag == "" {
		t.Error("etag should not be empty after Put")
	}

	headEtag, lastMod, err := store.Head(ctx, "acme.json")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if headEtag != etag {
		t.Errorf("Head etag = %q, Get etag = %q", headEtag, etag)
	}
	if lastMod.IsZero() {
		t.Error("Head LastModified should be set")
	}
}

func TestFakeStorePutContentLengthMismatch(t *testing.T) {
	// Locks in the invariant that the contract requires contentLength to
	// match the body — the production S3 client would reject mismatches
	// at signing time; the fake refuses them too so unit tests don't
	// drift away from the production behaviour.
	store := newFakeStore()
	body := []byte("hello")
	if err := store.Put(context.Background(), "k", bytes.NewReader(body), 99); err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
}

// stubS3API drives the real S3Store against pre-canned SDK responses so
// the ErrNotFound mapping can be exercised without a network. The
// uploader/downloader tests use fakeStore; this test exists only to pin
// the S3Store.Get/Head error-translation contract.
type stubS3API struct {
	getErr  error
	headErr error
	getOut  *s3.GetObjectOutput
	headOut *s3.HeadObjectOutput
}

func (s *stubS3API) GetObject(_ context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.getOut, nil
}

func (s *stubS3API) PutObject(_ context.Context, _ *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}

func (s *stubS3API) HeadObject(_ context.Context, _ *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if s.headErr != nil {
		return nil, s.headErr
	}
	return s.headOut, nil
}

func TestS3StoreGetMapsNoSuchKey(t *testing.T) {
	store := &S3Store{client: &stubS3API{getErr: &types.NoSuchKey{}}, bucket: "b"}
	_, _, err := store.Get(context.Background(), "k")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get err = %v, want ErrNotFound", err)
	}
}

func TestS3StoreHeadMapsNotFound(t *testing.T) {
	// HeadObject doesn't return *types.NoSuchKey — the API has no body to
	// shape one from — so the SDK gives us a generic smithy.APIError with
	// ErrorCode "NotFound". Tested separately from Get because the
	// translation code paths diverge.
	store := &S3Store{client: &stubS3API{headErr: &types.NotFound{}}, bucket: "b"}
	_, _, err := store.Head(context.Background(), "k")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Head err = %v, want ErrNotFound", err)
	}
}

// genericNotFound mimics the smithy.APIError shape some S3-compatible
// stores return for missing objects (MinIO, for instance, surfaces a
// generic 404 rather than a typed NoSuchKey on Head). Pinned in a test
// so the isNotFound fallback that handles them doesn't quietly regress.
type genericNotFound struct{}

func (genericNotFound) Error() string                 { return "404 not found" }
func (genericNotFound) ErrorCode() string             { return "NotFound" }
func (genericNotFound) ErrorMessage() string          { return "404 not found" }
func (genericNotFound) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestS3StoreHeadMapsGenericAPIError(t *testing.T) {
	store := &S3Store{client: &stubS3API{headErr: genericNotFound{}}, bucket: "b"}
	_, _, err := store.Head(context.Background(), "k")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Head err = %v, want ErrNotFound", err)
	}
}

func TestS3StoreGetReturnsBodyAndEtag(t *testing.T) {
	body := io.NopCloser(strings.NewReader("hello"))
	stub := &stubS3API{getOut: &s3.GetObjectOutput{
		Body: body,
		ETag: aws.String(`"abc"`),
	}}
	store := &S3Store{client: stub, bucket: "b"}
	rc, etag, err := store.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	if etag != `"abc"` {
		t.Errorf("etag = %q", etag)
	}
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Errorf("body = %q", got)
	}
}

func TestS3StoreHeadReturnsEtagAndLastModified(t *testing.T) {
	when := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	stub := &stubS3API{headOut: &s3.HeadObjectOutput{
		ETag:         aws.String(`"abc"`),
		LastModified: &when,
	}}
	store := &S3Store{client: stub, bucket: "b"}
	etag, lastMod, err := store.Head(context.Background(), "k")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if etag != `"abc"` {
		t.Errorf("etag = %q", etag)
	}
	if !lastMod.Equal(when) {
		t.Errorf("lastMod = %v, want %v", lastMod, when)
	}
}

func TestS3StoreGetWrapsNonNotFoundError(t *testing.T) {
	// Non-404 errors must propagate so callers (uploader bootstrap, in
	// particular) can fail loudly instead of mistaking S3 outages for
	// "no object yet."
	boom := errors.New("connection refused")
	store := &S3Store{client: &stubS3API{getErr: boom}, bucket: "b"}
	_, _, err := store.Get(context.Background(), "k")
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("err should not be ErrNotFound, got %v", err)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}
}
