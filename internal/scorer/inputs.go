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

	"github.com/ethpandaops/banoor/internal/lists"

	"github.com/ethpandaops/banoor/pkg/engine"
	"github.com/ethpandaops/banoor/pkg/manual"
	"github.com/ethpandaops/banoor/pkg/netaddr"
	"github.com/ethpandaops/banoor/pkg/sshlog"
)

func seconds(d time.Duration) string { return strconv.FormatInt(int64(d/time.Second), 10) }

func (s *Scorer) readMode(ctx context.Context) error {
	raw := s.cfg.DefaultMode
	q := fmt.Sprintf("SELECT toString(Mode) AS mode FROM %s ORDER BY Time DESC LIMIT 1", s.cfg.Tables.Control)

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

	return nil
}

func (s *Scorer) readSignals(ctx context.Context) (map[string][]engine.Row, error) {
	out := map[string][]engine.Row{}
	params := map[string]string{"window": seconds(s.cfg.Window.Duration)}

	for _, sig := range s.cfg.Signals {
		err := s.src.Select(ctx, sig.Query, params, func(row map[string]any) error {
			attempts, ok := num(row["attempts"])
			switch {
			case row["attempts"] == nil:
				attempts = math.NaN() // NULL: the engine counts the row as invalid
			case !ok:
				return fmt.Errorf("attempts is %T, want a number", row["attempts"])
			}

			addr := str(row["address"])

			if sig.Parser == "openssh" {
				ev, parsed := sshlog.Parse(str(row["line"]))
				if !parsed || !slices.Contains(sig.Kinds, string(ev.Kind)) {
					return nil
				}

				addr = ev.Address.String()
			}

			out[sig.Name] = append(out[sig.Name], engine.Row{Address: addr, Feeder: str(row["feeder"]), Attempts: attempts})

			return nil
		})
		if err != nil {
			s.metrics.Add("banoor_source_errors_total", 1, "query", "signal:"+sig.Name)

			return nil, fmt.Errorf("signal %s: %w", sig.Name, err)
		}
	}

	return out, nil
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
// stops counting at once.
func (s *Scorer) readAllowQueries(ctx context.Context, now time.Time) (*netaddr.Set, error) {
	var errs []error

	out := netaddr.NewSet()

	for _, q := range s.cfg.Allow.Queries {
		c := s.dynamic[q.Name]

		if c == nil || now.Sub(c.loaded) >= q.Refresh.Duration {
			rows, err := s.queryAllow(ctx, q.Query, q.Window.Duration)
			switch {
			case err == nil:
				c = &allowCache{rows: rows, loaded: now}
				s.dynamic[q.Name] = c
			case c == nil:
				errs = append(errs, fmt.Errorf("allow query %s: %w", q.Name, err))

				continue
			default:
				s.log.WarnContext(ctx, "keeping the last allow query result", "query", q.Name, "error", err)
			}
		}

		set, err := filterAllow(c.rows, q.KeysFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("allow query %s: %w", q.Name, err))

			continue
		}

		s.metrics.Set("banoor_allowlist_prefixes", float64(set.Len()), "list", q.Name)
		out = netaddr.Union(out, set)
	}

	return out, errors.Join(errs...)
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

func filterAllow(rows []allowRow, keysFile string) (*netaddr.Set, error) {
	var keys map[string]bool

	if keysFile != "" {
		data, err := os.ReadFile(keysFile)
		if err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}

		if keys, err = manual.ParseKeys(data); err != nil {
			return nil, err
		}
	}

	set := netaddr.NewSet()

	for _, r := range rows {
		if keys != nil && !keys[r.key] {
			continue
		}

		if p, err := netaddr.ParseAllow(r.address); err == nil {
			set.Add(p)
		}
	}

	return set, nil
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
			return nil, nil, fmt.Errorf("manual list: %w", readErr)
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
