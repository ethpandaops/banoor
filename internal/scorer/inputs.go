package scorer

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/lists"
	"github.com/ethpandaops/banoor/pkg/engine"
	"github.com/ethpandaops/banoor/pkg/manual"
	"github.com/ethpandaops/banoor/pkg/netaddr"
	"github.com/ethpandaops/banoor/pkg/sshlog"
)

func seconds(d time.Duration) string { return strconv.FormatInt(int64(d/time.Second), 10) }

// readMode reads the kill switch: the newest row of the control table that
// is not dated in the future, where it would pin the mode.
func (s *Scorer) readMode(ctx context.Context) error {
	raw := s.cfg.DefaultMode
	q := fmt.Sprintf("SELECT toString(Mode) AS mode FROM %s WHERE Time <= now64(3) ORDER BY Time DESC LIMIT 1", s.cfg.Tables.Control)

	err := s.src.Select(ctx, q, nil, func(row map[string]any) error {
		raw = str(row["mode"])

		return nil
	})
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "control")

		return err
	}

	m, err := engine.ParseMode(raw)
	if err != nil {
		return err
	}

	if s.haveMode && m != s.mode {
		s.log.InfoContext(ctx, "mode changed", "from", s.mode, "to", m)
	}

	s.mode, s.haveMode = m, true

	for _, mode := range modes {
		v := 0.0
		if mode == m {
			v = 1
		}

		s.metrics.Set("banoor_mode", v, "mode", string(mode))
	}

	return nil
}

// readSignals tallies every signal's rows. A signal whose query fails is
// left out of the run, which can only mean fewer new bans.
func (s *Scorer) readSignals(ctx context.Context) map[string]*engine.Tally {
	out := map[string]*engine.Tally{}

	for _, sig := range s.cfg.Signals {
		t, err := s.readSignal(ctx, sig)
		if err != nil {
			s.metrics.Add("banoor_source_errors_total", 1, "query", "signal:"+sig.Name)
			s.log.WarnContext(ctx, "scoring without a signal", "signal", sig.Name, "error", err)

			continue
		}

		out[sig.Name] = t
	}

	return out
}

func (s *Scorer) readSignal(ctx context.Context, sig config.Signal) (*engine.Tally, error) {
	t := s.engine.NewTally()
	params := map[string]string{"window": seconds(s.cfg.Window.Duration)}

	addressColumn := "address"
	if sig.Parser == "openssh" {
		addressColumn = "line"
	}

	err := s.src.Select(ctx, sig.Query, params, func(row map[string]any) error {
		for _, c := range []string{addressColumn, "feeder", "attempts"} {
			if _, ok := row[c]; !ok {
				return fmt.Errorf("no %s column", c)
			}
		}

		attempts, ok := num(row["attempts"])
		switch {
		case row["attempts"] == nil:
			attempts = math.NaN() // NULL: the tally counts the row as invalid
		case !ok:
			return fmt.Errorf("attempts is %T, want an integer or a float", row["attempts"])
		}

		addr := str(row[addressColumn])

		if sig.Parser == "openssh" {
			ev, parsed := sshlog.Parse(addr)
			if !parsed || !slices.Contains(sig.Kinds, string(ev.Kind)) {
				return nil
			}

			addr = ev.Address.String()
		}

		t.Add(engine.Row{Address: addr, Feeder: str(row["feeder"]), Attempts: attempts})

		return nil
	})
	if err != nil {
		return nil, err
	}

	return t, nil
}

// readStatic rereads the allowlist files. A broken or missing file keeps the
// last good allowlist; with none yet, the run stops.
func (s *Scorer) readStatic(ctx context.Context) error {
	set, err := lists.ReadAllowDir(s.cfg.Allow.Dir)
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "allowlist")

		if s.static == nil {
			return err
		}

		s.log.WarnContext(ctx, "keeping the last good allowlist", "error", err)

		return nil
	}

	s.static = set
	s.metrics.Set("banoor_allowlist_prefixes", float64(set.Len()), "list", "files")

	return nil
}

// readAllowQueries refreshes the allow queries that are due and filters
// every cached result by its key list, reread each run so a removed key
// stops counting at once. A key list that cannot be read, or lists nothing,
// keeps the last good one.
func (s *Scorer) readAllowQueries(ctx context.Context, now time.Time) (*netaddr.Set, error) {
	var errs []error

	out := netaddr.NewSet()

	for _, q := range s.cfg.Allow.Queries {
		c := s.dynamic[q.Name]

		if c == nil || now.Sub(c.loaded) >= q.Refresh.Duration {
			rows, err := s.queryAllow(ctx, q.Query, q.Window.Duration)
			switch {
			case err == nil && c == nil:
				c = &allowCache{rows: rows, loaded: now}
				s.dynamic[q.Name] = c
			case err == nil:
				c.rows, c.loaded = rows, now
			case c == nil:
				errs = append(errs, fmt.Errorf("allow query %s: %w", q.Name, err))

				continue
			default:
				s.log.WarnContext(ctx, "keeping the last allow query result", "query", q.Name, "error", err)
			}
		}

		if q.KeysFile != "" {
			keys, err := readKeys(q.KeysFile)
			switch {
			case err == nil:
				c.keys = keys
			case c.keys == nil:
				errs = append(errs, fmt.Errorf("allow query %s: %w", q.Name, err))

				continue
			default:
				s.metrics.Add("banoor_source_errors_total", 1, "query", "keys:"+q.Name)
				s.log.WarnContext(ctx, "keeping the last good key list", "query", q.Name, "error", err)
			}
		}

		set := filterAllow(c.rows, c.keys)
		s.metrics.Set("banoor_allowlist_prefixes", float64(set.Len()), "list", q.Name)
		out = netaddr.Union(out, set)
	}

	return out, errors.Join(errs...)
}

// readKeys reads a key list. One that lists no key is an error: it is more
// likely truncated than meant to allow nobody.
func readKeys(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	keys, err := manual.ParseKeys(data)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%s lists no keys", path)
	}

	return keys, nil
}

func (s *Scorer) queryAllow(ctx context.Context, query string, window time.Duration) ([]allowRow, error) {
	var rows []allowRow

	err := s.src.Select(ctx, query, map[string]string{"window": seconds(window)}, func(row map[string]any) error {
		rows = append(rows, allowRow{address: str(row["address"]), key: str(row["key"])})

		return nil
	})
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "allow")

		return nil, err
	}

	return rows, nil
}

// filterAllow allows each row's address whose key is listed; with no key
// list, every row's. A row allows one address, never a prefix.
func filterAllow(rows []allowRow, keys map[string]bool) *netaddr.Set {
	set := netaddr.NewSet()

	for _, r := range rows {
		if keys != nil && !keys[r.key] {
			continue
		}

		if p, err := netaddr.Host(r.address); err == nil {
			set.Add(p)
		}
	}

	return set
}

// readManual rereads the manual list. Invalid entries are skipped and
// counted; a file that cannot be read or parsed as a whole keeps the last
// good list, and with none yet the run stops.
func (s *Scorer) readManual(ctx context.Context) error {
	if s.cfg.ManualFile == "" {
		s.haveManual = true

		return nil
	}

	entries, errs, err := func() ([]manual.Entry, []error, error) {
		data, readErr := os.ReadFile(s.cfg.ManualFile)
		if readErr != nil {
			return nil, nil, readErr
		}

		return manual.Parse(data, s.cfg.Limits)
	}()
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "manual")

		if !s.haveManual {
			return err
		}

		s.log.WarnContext(ctx, "keeping the last good manual list", "error", err)

		return nil
	}

	for _, e := range errs {
		s.log.WarnContext(ctx, "skipping a manual entry", "error", e)
	}

	s.metrics.Set("banoor_manual_invalid", float64(len(errs)))
	s.manual, s.haveManual = entries, true

	return nil
}
