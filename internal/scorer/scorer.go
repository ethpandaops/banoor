// Package scorer runs the scoring loop: it reads every input from the
// source and the operator's files, scores, records, and publishes the signed
// list.
package scorer

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/publish"
	"github.com/ethpandaops/banoor/pkg/engine"
	"github.com/ethpandaops/banoor/pkg/manual"
	"github.com/ethpandaops/banoor/pkg/netaddr"
)

// Source runs queries and stores rows. Select calls row with each result
// row as column name to value.
type Source interface {
	Select(ctx context.Context, query string, params map[string]string, row func(map[string]any) error) error
	Insert(ctx context.Context, table string, columns []string, rows [][]any) error
}

// Registry is where the scorer reports metrics.
type Registry interface {
	Counter(name, help string)
	Gauge(name, help string)
	Add(name string, v float64, labels ...string)
	Set(name string, v float64, labels ...string)
}

type allowRow struct {
	address string
	key     string
}

type allowCache struct {
	rows   []allowRow
	loaded time.Time
	// keys is the last good key list, kept when its file breaks.
	keys map[string]bool
}

// Scorer is one scoring loop.
type Scorer struct {
	log      *slog.Logger
	cfg      *config.Config
	src      Source
	signer   publish.Signer
	metrics  Registry
	episodes *episodes
	now      func() time.Time

	engine      *engine.Engine
	pub         atomic.Pointer[publish.Publisher]
	lastSuccess atomic.Int64
	fetchers    *fetchers

	mode       engine.Mode
	haveMode   bool
	static     *netaddr.Set
	dynamic    map[string]*allowCache
	manual     []manual.Entry
	haveManual bool
}

// New returns a scorer. Nothing is published until the first run succeeds.
// now is the clock; nil takes time.Now.
func New(log *slog.Logger, cfg *config.Config, src Source, signer publish.Signer, reg Registry, now func() time.Time) *Scorer {
	if now == nil {
		now = time.Now
	}

	s := &Scorer{
		log:      log,
		cfg:      cfg,
		src:      src,
		signer:   signer,
		metrics:  reg,
		episodes: newEpisodes(),
		now:      now,
		engine:   engine.New(cfg.Engine()),
		dynamic:  map[string]*allowCache{},
	}
	if f := cfg.Allow.Fetchers; f != nil {
		s.fetchers = newFetchers(f.Users, f.Window.Duration)
	}

	s.defineMetrics()

	return s
}

// Current returns the list being served, or nil before the first
// successful run.
func (s *Scorer) Current() *publish.Current {
	if p := s.pub.Load(); p != nil {
		return p.Current()
	}

	return nil
}

// LastSuccess returns when a run last succeeded, or the zero time.
func (s *Scorer) LastSuccess() time.Time {
	if n := s.lastSuccess.Load(); n != 0 {
		return time.Unix(0, n).UTC()
	}

	return time.Time{}
}

// Run scores every interval until ctx ends.
func (s *Scorer) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval.Duration)
	defer t.Stop()

	for {
		runCtx, cancel := context.WithTimeout(ctx, s.cfg.Interval.Duration)

		var b *blockedError
		if err := s.RunOnce(runCtx); errors.As(err, &b) && ctx.Err() == nil {
			s.log.WarnContext(ctx, "run published nothing", "reason", b.reason, "error", b.err)
		}

		cancel()

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// blockedError is why a run published nothing.
type blockedError struct {
	reason string
	err    error
}

func (e *blockedError) Error() string { return e.reason + ": " + e.err.Error() }

func (e *blockedError) Unwrap() error { return e.err }

func (s *Scorer) blocked(reason string, err error) error {
	s.metrics.Add("banoor_run_blocked_total", 1, "reason", reason)

	return &blockedError{reason: reason, err: err}
}

// RunOnce reads every input, scores, records new decisions and publishes.
// A missing input may only keep sources off the list: a signal that cannot
// be read is left out, and decisions that cannot be recorded are not made,
// so the kill switch, lifts and expiries still take effect. A run that
// cannot read the mode, the allowlists or the manual list, or record a new
// generation, publishes nothing, so the served list ages and consumers keep
// what they hold.
func (s *Scorer) RunOnce(ctx context.Context) error {
	start := s.now()
	now := start.UTC()

	if s.pub.Load() == nil {
		if err := s.restore(ctx, now); err != nil {
			return s.blocked("restore", err)
		}
	}

	if err := s.readMode(ctx); err != nil {
		return s.blocked("control", err)
	}

	in, err := s.inputs(ctx, now)
	if err != nil {
		return err
	}

	res := s.engine.Step(in)
	pub := s.pub.Load()

	if err = s.recordDecisions(ctx, res, pub.Next(now)); err != nil {
		s.log.WarnContext(ctx, "could not record new decisions; publishing without them", "error", err)

		in.NoNewDecisions = true
		res = s.engine.Step(in)
	}

	s.engine.Commit(res)

	pr, err := pub.Prepare(now, s.mode, res.Entries)
	if err != nil {
		return s.blocked("sign", err)
	}

	if pr != nil && pr.Change != nil {
		if err = s.recordPublish(ctx, now, pr.Change, res); err != nil {
			return s.blocked("record", err)
		}

		s.engine.Published(res.Entries)
		s.log.InfoContext(ctx, "published", "generation", pr.Change.Generation, "mode", pr.Change.Mode,
			"entries", len(res.Entries), "added", pr.Change.Added, "removed", pr.Change.Removed)
	}

	if pr != nil {
		pub.Commit(pr)
	}

	s.storeFetchers(ctx)
	s.reportSuppressed(ctx, res)
	s.lastSuccess.Store(s.now().UnixNano())
	s.observe(res, start)

	return nil
}

// inputs reads everything a step needs. An empty list needs nothing, so the
// kill switch works whatever else fails. A signal that cannot be read is left
// out; any other read that fails blocks the run.
func (s *Scorer) inputs(ctx context.Context, now time.Time) (engine.Inputs, error) {
	if s.mode == engine.Empty {
		return engine.Inputs{Now: now, Mode: engine.Empty}, nil
	}

	tallies := s.readSignals(ctx)

	if err := s.readStatic(ctx); err != nil {
		return engine.Inputs{}, s.blocked("allowlist", err)
	}

	dynamic, err := s.readAllowQueries(ctx, now)
	if err != nil {
		return engine.Inputs{}, s.blocked("allow_query", err)
	}

	if err = s.readManual(ctx); err != nil {
		return engine.Inputs{}, s.blocked("manual", err)
	}

	allow := netaddr.Union(netaddr.SpecialPurpose(), s.static, dynamic)

	if s.fetchers != nil {
		fetched := s.fetchers.allowed(now)
		s.metrics.Set("banoor_allowlist_prefixes", float64(fetched.Len()), "list", "fetchers")
		allow = netaddr.Union(allow, fetched)
	}

	return engine.Inputs{
		Now:     now,
		Mode:    s.mode,
		Tallies: tallies,
		Allow:   allow,
		Manual:  s.manual,
	}, nil
}
