// Package scorer runs the scoring loop: it reads every input from the
// source and the operator's files, scores, records, and publishes the signed
// list.
package scorer

import (
	"context"
	"fmt"
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
		if err := s.RunOnce(runCtx); err != nil && ctx.Err() == nil {
			s.log.WarnContext(ctx, "run published nothing", "error", err)
		}

		cancel()

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Scorer) blocked(reason string, err error) error {
	s.metrics.Add("banoor_run_blocked_total", 1, "reason", reason)

	return fmt.Errorf("%s: %w", reason, err)
}

// RunOnce reads every input, scores, records new decisions and publishes.
// A run that cannot read an input or record what it decided publishes
// nothing, so the served list ages and consumers keep what they hold.
func (s *Scorer) RunOnce(ctx context.Context) error {
	start := s.now()
	now := start.UTC()

	if s.pub.Load() == nil {
		if err := s.restore(ctx, now); err != nil {
			return s.blocked("restore", err)
		}
	}

	in, err := s.inputs(ctx, now)
	if err != nil {
		return err
	}

	res := s.engine.Step(in)
	pub := s.pub.Load()

	if err = s.recordDecisions(ctx, res, pub.Next(now)); err != nil {
		return s.blocked("record", err)
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
	s.lastSuccess.Store(s.now().UnixNano())
	s.observe(res, start)

	return nil
}

// inputs reads everything a step needs. Each read that fails blocks the run.
func (s *Scorer) inputs(ctx context.Context, now time.Time) (engine.Inputs, error) {
	if err := s.readMode(ctx); err != nil {
		return engine.Inputs{}, s.blocked("control", err)
	}

	rows, err := s.readSignals(ctx)
	if err != nil {
		return engine.Inputs{}, s.blocked("signals", err)
	}

	if err = s.readStatic(ctx); err != nil {
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
		Now:    now,
		Mode:   s.mode,
		Rows:   rows,
		Allow:  allow,
		Manual: s.manual,
	}, nil
}
