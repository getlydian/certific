package certific

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// staticSyncer is a LastSyncer backed by a plain time value, used to
// drive the handler through its three states without spinning up a real
// uploader.
type staticSyncer struct{ t time.Time }

func (s staticSyncer) LastSync() time.Time { return s.t }

func TestHealthzReturns200WhenFresh(t *testing.T) {
	// Steady-state: a recent sync is well inside the freshness window,
	// so /healthz should answer 200 with a short status line.
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	syncer := staticSyncer{t: now.Add(-30 * time.Second)}

	h := HealthHandler(syncer, 2*time.Minute, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("body = %q, want it to mention ok", rr.Body.String())
	}
}

func TestHealthzReturns503WhenStale(t *testing.T) {
	// The freshness check is the whole point of the endpoint. Stale ⇒
	// 503 so external alerting can branch on the status code without
	// parsing the body.
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	syncer := staticSyncer{t: now.Add(-5 * time.Minute)}

	h := HealthHandler(syncer, 2*time.Minute, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "unhealthy") {
		t.Errorf("body = %q, want unhealthy", rr.Body.String())
	}
}

func TestHealthzReturns503BeforeFirstSync(t *testing.T) {
	// Zero LastSync means bootstrap hasn't completed yet (or has been
	// running for so long the value wrapped, which we don't expect).
	// Either way, reporting 200 would be a lie. 503 is correct until
	// we've observed at least one successful S3 round-trip.
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	syncer := staticSyncer{t: time.Time{}}

	h := HealthHandler(syncer, time.Hour, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "no successful sync") {
		t.Errorf("body = %q, want explicit no-sync message", rr.Body.String())
	}
}

func TestHealthzBoundaryAtExactFreshness(t *testing.T) {
	// The boundary is inclusive on the OK side: a sync that's exactly
	// `freshness` old is still considered fresh. This matches the
	// 2×interval rule which would otherwise oscillate when a slow
	// cycle lands one nanosecond past the cutoff.
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	syncer := staticSyncer{t: now.Add(-2 * time.Minute)}

	h := HealthHandler(syncer, 2*time.Minute, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("at exact freshness, status = %d, want 200", rr.Code)
	}
}

func TestMetricsExposesLastSync(t *testing.T) {
	// /metrics is a placeholder, but it must at least surface the
	// last-sync timestamp so an operator can curl it during incident
	// response without inspecting the filesystem.
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	last := now.Add(-45 * time.Second)
	syncer := staticSyncer{t: last}

	h := HealthHandler(syncer, time.Minute, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "certific_last_sync_unix") {
		t.Errorf("body missing certific_last_sync_unix: %q", body)
	}
	if !strings.Contains(body, "certific_freshness_seconds") {
		t.Errorf("body missing certific_freshness_seconds: %q", body)
	}
}

func TestRunHealthServerServesAndShutsDown(t *testing.T) {
	// End-to-end on a real loopback socket: bind, GET /healthz, then
	// cancel ctx and confirm RunHealthServer returns nil promptly.
	// Picks an ephemeral port to avoid collisions in parallel CI runs.
	syncer := LastSyncerFunc(func() time.Time { return time.Now() })

	addr, err := freeTCPAddr()
	if err != nil {
		t.Fatalf("freeTCPAddr: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunHealthServer(ctx, addr, syncer, time.Minute, nil) }()

	// Poll until the listener is up — bind is synchronous in
	// RunHealthServer but the goroutine that calls Serve hasn't
	// necessarily scheduled yet by the time the constructor returns.
	url := "http://" + addr + "/healthz"
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get(url) //nolint:gosec // test loopback URL
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("GET %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunHealthServer returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunHealthServer did not return within 2s of cancel")
	}
}

func TestRunHealthServerReportsBindError(t *testing.T) {
	// Two servers on the same addr: the second must fail loudly, not
	// run silently without /healthz. Operators would never notice an
	// unbound health endpoint until an outage was already in progress.
	addr, err := freeTCPAddr()
	if err != nil {
		t.Fatalf("freeTCPAddr: %v", err)
	}

	// Occupy the port with a real listener so the second attempt sees
	// EADDRINUSE deterministically.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("pre-listen: %v", err)
	}
	defer ln.Close()

	syncer := LastSyncerFunc(func() time.Time { return time.Now() })
	err = RunHealthServer(context.Background(), addr, syncer, time.Minute, nil)
	if err == nil {
		t.Fatal("expected bind error, got nil")
	}
}

// freeTCPAddr returns a loopback address with a free port. The kernel
// closes the listener immediately, but bind-then-rebind has been racy
// historically; in practice the window is short enough that tests
// tolerate it.
func freeTCPAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return "", err
	}
	return addr, nil
}

// liveSyncer is a thread-safe LastSyncer used by the integration-style
// test below; the static one would race the goroutine that bumps it.
type liveSyncer struct{ ns atomic.Int64 }

func (l *liveSyncer) LastSync() time.Time {
	n := l.ns.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
func (l *liveSyncer) bump(t time.Time) { l.ns.Store(t.UnixNano()) }

func TestHealthzFlipsWhenSyncerBumps(t *testing.T) {
	// Confirms the handler reads LastSync on every request (not e.g.
	// caching at construction). Without this, a stuck uploader would
	// still report 200 for as long as the handler kept its cached value.
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := now
	syncer := &liveSyncer{}

	h := HealthHandler(syncer, 30*time.Second, func() time.Time { return clock })

	// No sync yet → 503.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("before bump: status = %d, want 503", rr.Code)
	}

	// Bump → 200.
	syncer.bump(clock)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("after bump: status = %d, want 200", rr.Code)
	}

	// Advance clock past freshness → 503.
	clock = clock.Add(2 * time.Minute)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("after time advance: status = %d, want 503", rr.Code)
	}
}

// Compile-time checks: both worker types satisfy LastSyncer, so the
// main.go wiring will compile. Pinned in a test to avoid littering the
// production files with unused interface assertions.
var (
	_ LastSyncer = (*Uploader)(nil)
	_ LastSyncer = (*Downloader)(nil)
	_ LastSyncer = LastSyncerFunc(nil)
)
