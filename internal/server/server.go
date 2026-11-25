// Package server hosts the HTTP API, the OpenAPI spec and the metrics.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/ogen-go/ogen/ogenerrors"

	"github.com/ethpandaops/banoor/api"
	"github.com/ethpandaops/banoor/api/rest"
	"github.com/ethpandaops/banoor/internal/publish"
)

const shutdownTimeout = 5 * time.Second

// Config holds what the server needs to start.
type Config struct {
	// Listen is the TCP address to serve on, e.g. 127.0.0.1:8080.
	Listen string
	// Version is reported by the health endpoint.
	Version string
	// FetchUserHeader names the request header that says who fetched the
	// list, such as one an authenticating proxy sets, for the fetch metric.
	FetchUserHeader string
	// FetchAddressHeader names the request header holding the client's
	// address, set by the proxy in front; empty records no addresses.
	FetchAddressHeader string
	// TrustedProxies are the peers whose fetch headers are believed; empty
	// believes every peer.
	TrustedProxies []netip.Prefix
}

// Lists is where the served list comes from.
type Lists interface {
	Current() *publish.Current
	LastSuccess() time.Time
	// Seen is told who fetched the list, and from where.
	Seen(user, address string)
}

// Metrics is the registry the server counts fetches in and serves.
type Metrics interface {
	Counter(name, help string)
	Add(name string, v float64, labels ...string)
	Write(w io.Writer) error
}

// Server serves /api/v1, the OpenAPI spec and /metrics on one listener.
type Server struct {
	log  *slog.Logger
	cfg  Config
	http *http.Server
}

// New builds the route table.
func New(log *slog.Logger, cfg Config, lists Lists, metrics Metrics) (*Server, error) {
	// Every line the server logs inside a request carries that request's ID.
	log = slog.New(requestIDHandler{log.Handler()})
	s := &Server{log: log, cfg: cfg}

	metrics.Counter("banoor_fetches_total", "List requests, by user and result.")
	ops := &operations{log: log, version: cfg.Version, lists: lists, metrics: metrics, users: newUserLabels(maxUserLabels)}

	generated, err := rest.NewServer(
		ops,
		rest.WithErrorHandler(s.handleError),
		rest.WithNotFound(func(w http.ResponseWriter, _ *http.Request) {
			writeProblem(w, problem(http.StatusNotFound, "no such API route"))
		}),
		rest.WithMethodNotAllowed(func(w http.ResponseWriter, _ *http.Request, allowed string) {
			w.Header().Set("Allow", allowed)
			writeProblem(w, problem(http.StatusMethodNotAllowed, ""))
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/v1/", withFetcher(cfg, generated))
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(api.Spec)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		if writeErr := metrics.Write(w); writeErr != nil {
			log.WarnContext(r.Context(), "writing metrics", "error", writeErr)
		}
	})

	s.http = &http.Server{
		Handler:           withRequestID(accessLog(log, mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	return s, nil
}

// Handler returns the served handler (the route table behind the access
// log), for tests.
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.log.InfoContext(ctx, "serving", "addr", "http://"+ln.Addr().String())

	served := make(chan error, 1)
	go func() { served <- s.http.Serve(ln) }()

	select {
	case serveErr := <-served:
		return fmt.Errorf("serve: %w", serveErr)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	if err := s.http.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}

	s.log.InfoContext(ctx, "stopped")

	return nil
}

// handleError answers requests ogen could not decode, as problems.
func (s *Server) handleError(ctx context.Context, w http.ResponseWriter, _ *http.Request, err error) {
	code := ogenerrors.ErrorCode(err)
	if code >= http.StatusInternalServerError {
		s.log.ErrorContext(ctx, "api request failed", "error", err)
		writeProblem(w, problem(code, ""))

		return
	}

	writeProblem(w, problem(code, err.Error()))
}

func writeProblem(w http.ResponseWriter, p *rest.ProblemStatusCode) {
	body, err := p.Response.MarshalJSON()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.StatusCode)
	_, _ = w.Write(body)
}
