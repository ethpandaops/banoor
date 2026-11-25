// Package service runs the scoring loop against a source and serves the
// signed list.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/engine"
	"github.com/ethpandaops/banoor/internal/lists"
	"github.com/ethpandaops/banoor/internal/metrics"
	"github.com/ethpandaops/banoor/internal/netaddr"
	"github.com/ethpandaops/banoor/internal/publish"
	"github.com/ethpandaops/banoor/internal/sshlog"
)

// Source runs queries and stores rows. Select calls row with each result row
// as a JSON object; Insert takes rows as JSON objects.
type Source interface {
	Select(ctx context.Context, query string, params map[string]string, row func([]byte) error) error
	Insert(ctx context.Context, table string, rows [][]byte) error
}

type allowCache struct {
	set    *netaddr.Set
	loaded time.Time
}

// Service is one scorer.
type Service struct {
	cfg      *config.Config
	src      Source
	signer   publish.Signer
	log      *slog.Logger
	metrics  *metrics.Registry
	episodes *metrics.Episodes
	now      func() time.Time

	engine *engine.Engine
	pub    atomic.Pointer[publish.Publisher]

	mode     engine.Mode
	haveMode bool
	static   *netaddr.Set
	dynamic  map[string]*allowCache
	manual   []lists.Manual
	haveMan  bool
}

// New returns a service. Nothing is served until the first run succeeds.
func New(cfg *config.Config, src Source, signer publish.Signer, log *slog.Logger, version string) *Service {
	s := &Service{
		cfg:      cfg,
		src:      src,
		signer:   signer,
		log:      log,
		metrics:  metrics.New(),
		episodes: metrics.NewEpisodes(),
		now:      time.Now,
		engine:   engine.New(cfg.Engine()),
		dynamic:  map[string]*allowCache{},
	}
	s.defineMetrics()
	s.metrics.Set("banoor_build_info", 1, "version", version)
	return s
}

// Run scores every interval until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval.Duration)
	defer t.Stop()
	for {
		runCtx, cancel := context.WithTimeout(ctx, s.cfg.Interval.Duration)
		if err := s.RunOnce(runCtx); err != nil && ctx.Err() == nil {
			s.log.Warn("run did not publish", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) blocked(reason string, err error) error {
	s.metrics.Add("banoor_run_blocked_total", 1, "reason", reason)
	return fmt.Errorf("%s: %w", reason, err)
}

// RunOnce reads every input, scores, records new bans and publishes. A run
// that cannot read an input publishes nothing, so the served list ages and
// consumers keep what they hold.
func (s *Service) RunOnce(ctx context.Context) error {
	start := s.now()
	now := start.UTC()

	if s.pub.Load() == nil {
		if err := s.restore(ctx); err != nil {
			return s.blocked("restore", err)
		}
	}
	if err := s.readMode(ctx); err != nil {
		return s.blocked("control", err)
	}
	rows, err := s.readSignals(ctx)
	if err != nil {
		return s.blocked("signals", err)
	}
	if err := s.readStatic(); err != nil {
		return s.blocked("allowlist", err)
	}
	if err := s.readAllowQueries(ctx, now); err != nil {
		return s.blocked("allow_query", err)
	}
	if err := s.readManual(); err != nil {
		return s.blocked("manual", err)
	}

	sets := []*netaddr.Set{netaddr.SpecialPurpose(), s.static}
	for _, c := range s.dynamic {
		sets = append(sets, c.set)
	}
	res := s.engine.Step(engine.Inputs{
		Now:    now,
		Mode:   s.mode,
		Rows:   rows,
		Allow:  netaddr.Union(sets...),
		Manual: s.manual,
	})

	pub := s.pub.Load()
	if err := s.record(ctx, res, pub.Next(now)); err != nil {
		return s.blocked("record", err)
	}
	s.engine.Commit(res)

	change, err := pub.Update(now, s.mode, res.Entries)
	if err != nil {
		return s.blocked("sign", err)
	}
	if change != nil {
		s.engine.Published(res.Entries)
		s.log.Info("published", "generation", change.Generation, "mode", change.Mode,
			"entries", change.Entries, "added", change.Added, "removed", change.Removed)
		if err := s.recordPublish(ctx, now, change, res); err != nil {
			s.metrics.Add("banoor_source_errors_total", 1, "query", "publishes")
			s.log.Warn("could not record the publish", "err", err)
		}
	}
	s.observe(res, start)
	return nil
}

func selectRows[T any](ctx context.Context, src Source, query string, params map[string]string) ([]T, error) {
	var out []T
	err := src.Select(ctx, query, params, func(b []byte) error {
		var v T
		if err := json.Unmarshal(b, &v); err != nil {
			return fmt.Errorf("decode row %s: %w", truncate(b), err)
		}
		out = append(out, v)
		return nil
	})
	return out, err
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

func seconds(d time.Duration) string { return strconv.FormatInt(int64(d/time.Second), 10) }

func (s *Service) restore(ctx context.Context) error {
	lookback := max(s.cfg.Ban.RepeatWindow.Duration, s.cfg.Ban.Max.Duration)
	type row struct {
		TimeMs  int64    `json:"time_ms"`
		Action  string   `json:"action"`
		CIDR    string   `json:"cidr"`
		Points  float64  `json:"points"`
		Expires int64    `json:"expires"`
		Number  int      `json:"ban_number"`
		Reason  string   `json:"reason"`
		Feeders []string `json:"feeders"`
	}
	q := fmt.Sprintf(`SELECT toUnixTimestamp64Milli(Time) AS time_ms, Action AS action, Cidr AS cidr, Points AS points,
	toUnixTimestamp(Expires) AS expires, BanNumber AS ban_number, Reason AS reason, Feeders AS feeders
FROM %s WHERE Time >= now() - toIntervalSecond({lookback:UInt32}) ORDER BY Time`, s.cfg.Tables.Decisions)
	rows, err := selectRows[row](ctx, s.src, q, map[string]string{"lookback": seconds(lookback)})
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "decisions")
		return err
	}
	var bans []engine.Ban
	var manual []string
	for _, r := range rows {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			s.log.Warn("skipping a recorded decision", "cidr", r.CIDR, "err", err)
			continue
		}
		expires := time.Unix(r.Expires, 0).UTC()
		switch r.Action {
		case actionBan:
			bans = append(bans, engine.Ban{
				Unit: p, Issued: time.UnixMilli(r.TimeMs).UTC(), Expires: expires,
				Points: r.Points, Number: r.Number, Reason: r.Reason, Feeders: r.Feeders,
			})
		case actionManualBan, actionManualLift:
			m := lists.Manual{Action: r.Action[len("manual_"):], Prefix: p, Expires: expires}
			manual = append(manual, m.Key())
		}
	}
	type genRow struct {
		Generation uint64 `json:"generation"`
	}
	gens, err := selectRows[genRow](ctx, s.src, fmt.Sprintf("SELECT max(Generation) AS generation FROM %s", s.cfg.Tables.Publishes), nil)
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "publishes")
		return err
	}
	var last uint64
	if len(gens) > 0 {
		last = gens[0].Generation
	}
	s.engine.Restore(bans, manual)
	s.pub.Store(publish.New(s.signer, s.cfg.Refresh.Duration, last))
	s.log.Info("restored", "bans", len(bans), "manual", len(manual), "last_generation", last)
	return nil
}

func (s *Service) readMode(ctx context.Context) error {
	type row struct {
		Mode string `json:"mode"`
	}
	rows, err := selectRows[row](ctx, s.src, fmt.Sprintf("SELECT toString(Mode) AS mode FROM %s ORDER BY Time DESC LIMIT 1", s.cfg.Tables.Control), nil)
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "control")
		return err
	}
	raw := s.cfg.DefaultMode
	if len(rows) > 0 {
		raw = rows[0].Mode
	}
	m, err := engine.ParseMode(raw)
	if err != nil {
		return err
	}
	if s.haveMode && m != s.mode {
		s.log.Info("mode changed", "from", s.mode, "to", m)
	}
	s.mode, s.haveMode = m, true
	return nil
}

type signalRow struct {
	Address  string  `json:"address"`
	Line     string  `json:"line"`
	Feeder   string  `json:"feeder"`
	Attempts float64 `json:"attempts"`
}

func (s *Service) readSignals(ctx context.Context) (map[string][]engine.Row, error) {
	out := map[string][]engine.Row{}
	params := map[string]string{"window": seconds(s.cfg.Window.Duration)}
	for _, sig := range s.cfg.Signals {
		rows, err := selectRows[signalRow](ctx, s.src, sig.Query, params)
		if err != nil {
			s.metrics.Add("banoor_source_errors_total", 1, "query", "signal:"+sig.Name)
			return nil, fmt.Errorf("signal %s: %w", sig.Name, err)
		}
		for _, r := range rows {
			addr := r.Address
			if sig.Parser == "openssh" {
				ev, ok := sshlog.Parse(r.Line)
				if !ok || !slices.Contains(sig.Kinds, string(ev.Kind)) {
					continue
				}
				addr = ev.Address.String()
			}
			out[sig.Name] = append(out[sig.Name], engine.Row{Address: addr, Feeder: r.Feeder, Attempts: r.Attempts})
		}
	}
	return out, nil
}

// readStatic rereads the allowlist files. A broken file keeps the last good
// allowlist; with none yet, the run stops.
func (s *Service) readStatic() error {
	set, err := lists.LoadAllowDir(s.cfg.Allow.Dir)
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "allowlist")
		if s.static == nil {
			return err
		}
		s.log.Warn("keeping the last good allowlist", "err", err)
		return nil
	}
	s.static = set
	s.metrics.Set("banoor_allowlist_prefixes", float64(set.Len()), "list", "files")
	return nil
}

func (s *Service) readAllowQueries(ctx context.Context, now time.Time) error {
	type row struct {
		Address string `json:"address"`
		Key     string `json:"key"`
	}
	var errs []error
	for _, q := range s.cfg.Allow.Queries {
		c := s.dynamic[q.Name]
		if c != nil && now.Sub(c.loaded) < q.Refresh.Duration {
			continue
		}
		set, err := func() (*netaddr.Set, error) {
			var keys map[string]bool
			if q.KeysFile != "" {
				k, err := lists.LoadKeys(q.KeysFile)
				if err != nil {
					return nil, err
				}
				keys = k
			}
			rows, err := selectRows[row](ctx, s.src, q.Query, map[string]string{"window": seconds(q.Window.Duration)})
			if err != nil {
				return nil, err
			}
			set := netaddr.NewSet()
			for _, r := range rows {
				if keys != nil && !keys[r.Key] {
					continue
				}
				p, err := netaddr.ParseAllow(r.Address)
				if err != nil {
					continue
				}
				set.Add(p)
			}
			return set, nil
		}()
		if err != nil {
			s.metrics.Add("banoor_source_errors_total", 1, "query", "allow:"+q.Name)
			if c == nil {
				errs = append(errs, fmt.Errorf("allow query %s: %w", q.Name, err))
			} else {
				s.log.Warn("keeping the last allow query result", "query", q.Name, "err", err)
			}
			continue
		}
		s.dynamic[q.Name] = &allowCache{set: set, loaded: now}
		s.metrics.Set("banoor_allowlist_prefixes", float64(set.Len()), "list", q.Name)
	}
	return errors.Join(errs...)
}

// readManual rereads the manual list. Invalid entries are skipped and
// counted; an unreadable file keeps the last good list.
func (s *Service) readManual() error {
	if s.cfg.ManualFile == "" {
		s.haveMan = true
		return nil
	}
	data, err := os.ReadFile(s.cfg.ManualFile)
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "manual")
		if !s.haveMan {
			return err
		}
		s.log.Warn("keeping the last manual list", "err", err)
		return nil
	}
	entries, errs := lists.ParseManual(data, s.cfg.Limits)
	for _, err := range errs {
		s.log.Warn("skipping a manual entry", "err", err)
	}
	s.metrics.Set("banoor_manual_invalid", float64(len(errs)))
	s.manual, s.haveMan = entries, true
	return nil
}

const (
	actionBan        = "ban"
	actionManualBan  = "manual_ban"
	actionManualLift = "manual_lift"
)

type decisionRow struct {
	Time       string             `json:"Time"`
	Generation uint64             `json:"Generation"`
	Action     string             `json:"Action"`
	Cidr       string             `json:"Cidr"`
	Points     float64            `json:"Points"`
	Feeders    []string           `json:"Feeders"`
	Signals    map[string]float64 `json:"Signals"`
	BanNumber  int                `json:"BanNumber"`
	Expires    string             `json:"Expires"`
	Mode       string             `json:"Mode"`
	Reason     string             `json:"Reason"`
}

func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func (s *Service) record(ctx context.Context, res engine.Result, generation uint64) error {
	var rows [][]byte
	add := func(r decisionRow) error {
		if r.Feeders == nil {
			r.Feeders = []string{}
		}
		if r.Signals == nil {
			r.Signals = map[string]float64{}
		}
		b, err := json.Marshal(r)
		rows = append(rows, b)
		return err
	}
	for _, b := range res.NewBans {
		if err := add(decisionRow{
			Time: timestamp(res.Now), Generation: generation, Action: actionBan, Cidr: b.Unit.String(),
			Points: b.Points, Feeders: b.Feeders, Signals: b.Signals, BanNumber: b.Number,
			Expires: timestamp(b.Expires), Mode: string(s.mode), Reason: b.Reason,
		}); err != nil {
			return err
		}
	}
	for _, m := range res.NewManual {
		var by []string
		if m.By != "" {
			by = []string{m.By}
		}
		if err := add(decisionRow{
			Time: timestamp(res.Now), Generation: generation, Action: "manual_" + m.Action, Cidr: m.Prefix.String(),
			Feeders: by, Expires: timestamp(m.Expires), Mode: string(s.mode), Reason: m.Reason,
		}); err != nil {
			return err
		}
	}
	if err := s.src.Insert(ctx, s.cfg.Tables.Decisions, rows); err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "decisions")
		return err
	}
	return nil
}

func (s *Service) recordPublish(ctx context.Context, now time.Time, c *publish.Change, res engine.Result) error {
	deferred := 0
	for _, ps := range res.Deferred {
		deferred += len(ps)
	}
	b, err := json.Marshal(map[string]any{
		"Time": timestamp(now), "Generation": c.Generation, "PreviousGeneration": c.PreviousGeneration,
		"Mode": string(c.Mode), "Entries": c.Entries, "Added": c.Added, "Removed": c.Removed,
		"Deferred": deferred, "PayloadSha256": c.PayloadSHA256,
	})
	if err != nil {
		return err
	}
	return s.src.Insert(ctx, s.cfg.Tables.Publishes, [][]byte{b})
}
