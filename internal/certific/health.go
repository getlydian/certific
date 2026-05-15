package certific

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// LastSyncer is the minimal seam between a running uploader/downloader
// and the health endpoint. Both Uploader.LastSync and Downloader.LastSync
// satisfy it. Keeping the interface this narrow means the health server
// has no idea which mode it's serving — that's all in the freshness
// window the caller hands it.
type LastSyncer interface {
	LastSync() time.Time
}

// LastSyncerFunc adapts a plain function into a LastSyncer, useful for
// tests that want to inject a fake clock.
type LastSyncerFunc func() time.Time

func (f LastSyncerFunc) LastSync() time.Time { return f() }

// HealthHandler returns an http.Handler exposing /healthz and /metrics.
//
//   - /healthz: 200 if Now() − LastSync() ≤ freshness; 503 otherwise.
//     A zero LastSync (no successful op yet) reports 503 to avoid a
//     window after startup where the endpoint says "healthy" before
//     bootstrap has run.
//   - /metrics: plain-text key=value output. Intentionally not real
//     Prometheus — step 8 calls it a placeholder "just enough to curl."
//     Operators who want scraping wire it up themselves later.
//
// now is a seam for tests; pass nil to use time.Now.
func HealthHandler(syncer LastSyncer, freshness time.Duration, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		last := syncer.LastSync()
		t := now()
		if last.IsZero() {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "unhealthy: no successful sync yet\n")
			return
		}
		age := t.Sub(last)
		if age > freshness {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "unhealthy: last sync %s ago, freshness window %s\n", age, freshness)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "ok: last sync %s ago\n", age)
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		last := syncer.LastSync()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		var lastUnix int64
		if !last.IsZero() {
			lastUnix = last.Unix()
		}
		_, _ = fmt.Fprintf(w, "certific_last_sync_unix %d\n", lastUnix)
		_, _ = fmt.Fprintf(w, "certific_freshness_seconds %d\n", int64(freshness.Seconds()))
	})

	return mux
}

// RunHealthServer starts an HTTP server bound to addr that serves the
// handler returned by HealthHandler. It blocks until ctx is cancelled
// or the server returns an error, then shuts the server down within a
// short grace window so SIGTERM doesn't get stuck waiting on in-flight
// curl probes.
//
// addr may be ":8080", "127.0.0.1:8080", etc. If listening fails (port
// in use, bad addr) the error is returned synchronously so misconfigured
// deployments fail loudly at startup rather than serving silently
// without /healthz.
func RunHealthServer(ctx context.Context, addr string, syncer LastSyncer, freshness time.Duration, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           HealthHandler(syncer, freshness, nil),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Bind synchronously so we can surface "address in use" before
	// returning to the caller. http.Server.ListenAndServe doesn't tell
	// us the listener succeeded vs. failed without parsing its error.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("health: listen %s: %w", addr, err)
	}
	logger.Info("health server listening", "addr", ln.Addr().String(), "freshness", freshness)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		// Bounded shutdown: 5s is plenty for an internal endpoint that
		// only handles GETs. Anything longer means the kubelet/swarm
		// kill timer is already counting down on us.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("health server shutdown", "err", err)
		}
		// Drain Serve's return so the goroutine doesn't leak.
		<-serveErr
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("health: serve: %w", err)
	}
}
