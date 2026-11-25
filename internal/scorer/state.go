package scorer

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ethpandaops/banoor/internal/publish"
	"github.com/ethpandaops/banoor/pkg/engine"
	"github.com/ethpandaops/banoor/pkg/manual"
)

const (
	actionBan        = "ban"
	actionManualBan  = "manual_ban"
	actionManualLift = "manual_lift"
)

var decisionColumns = []string{"Time", "Generation", "Action", "Cidr", "Points", "Feeders", "Signals", "BanNumber", "Expires", "Mode", "Reason"}

var publishColumns = []string{"Time", "Generation", "PreviousGeneration", "Mode", "Entries", "Added", "Removed", "Deferred", "PayloadSha256", "Cidrs"}

// restore rebuilds the engine and the generation sequence from the state
// tables: the bans within the longest window that matters, every manual
// entry still in force, and the last published list.
func (s *Scorer) restore(ctx context.Context, now time.Time) error {
	lookback := max(s.cfg.Ban.RepeatWindow.Duration, s.cfg.Ban.Max.Duration)
	q := fmt.Sprintf(`SELECT toUnixTimestamp64Milli(Time) AS time_ms, Action AS action, Cidr AS cidr, Points AS points,
	toUnixTimestamp(Expires) AS expires, BanNumber AS ban_number, Reason AS reason, Feeders AS feeders
FROM %s
WHERE (Action = '%s' AND Time >= now() - toIntervalSecond({lookback:UInt32}))
	OR (Action IN ('%s', '%s') AND Expires > now())
ORDER BY Time`, s.cfg.Tables.Decisions, actionBan, actionManualBan, actionManualLift)

	var (
		bans       []engine.Ban
		manualKeys []string
	)

	err := s.src.Select(ctx, q, map[string]string{"lookback": seconds(lookback)}, func(row map[string]any) error {
		p, err := netip.ParsePrefix(str(row["cidr"]))
		if err != nil {
			s.log.WarnContext(ctx, "skipping a recorded decision", "cidr", row["cidr"], "error", err)

			return nil
		}

		expires := time.Unix(integer(row["expires"]), 0).UTC()

		switch action := str(row["action"]); action {
		case actionBan:
			bans = append(bans, engine.Ban{
				Unit: p, Issued: time.UnixMilli(integer(row["time_ms"])).UTC(), Expires: expires,
				Points: float(row["points"]), Number: int(integer(row["ban_number"])), Reason: str(row["reason"]),
				Feeders: strList(row["feeders"]),
			})
		case actionManualBan, actionManualLift:
			e := manual.Entry{Action: strings.TrimPrefix(action, "manual_"), Prefix: p, Expires: expires}
			manualKeys = append(manualKeys, e.Key())
		}

		return nil
	})
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "decisions")

		return err
	}

	var (
		last      uint64
		published []string
	)

	q = fmt.Sprintf("SELECT Generation AS generation, Cidrs AS cidrs FROM %s ORDER BY Generation DESC LIMIT 1", s.cfg.Tables.Publishes)

	err = s.src.Select(ctx, q, nil, func(row map[string]any) error {
		last, published = uint64(max(integer(row["generation"]), 0)), strList(row["cidrs"])

		return nil
	})
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "publishes")

		return err
	}

	if err = s.restoreFetchers(ctx); err != nil {
		return err
	}

	s.engine.Restore(bans, manualKeys, published)
	s.pub.Store(publish.New(s.signer, s.cfg.Refresh.Duration, last, published))
	s.log.InfoContext(ctx, "restored", "bans", len(bans), "manual", len(manualKeys), "last_generation", last, "at", now)

	return nil
}

// recordDecisions stores new bans and newly seen manual entries before the
// list that includes them is published.
func (s *Scorer) recordDecisions(ctx context.Context, res engine.Result, generation uint64) error {
	rows := make([][]any, 0, len(res.NewBans)+len(res.NewManual))
	mode := string(s.mode)

	for _, b := range res.NewBans {
		rows = append(rows, []any{
			res.Now, generation, actionBan, b.Unit.String(), b.Points, nonNil(b.Feeders), b.Signals,
			uint8(min(b.Number, 255)), b.Expires, mode, b.Reason, //nolint:gosec // clamped to 255
		})
	}

	for _, m := range res.NewManual {
		by := []string{}
		if m.By != "" {
			by = []string{m.By}
		}

		rows = append(rows, []any{
			res.Now, generation, "manual_" + m.Action, m.Prefix.String(), 0.0, by,
			map[string]float64{},
			uint8(0), m.Expires.UTC(), mode, m.Reason,
		})
	}

	if err := s.src.Insert(ctx, s.cfg.Tables.Decisions, decisionColumns, rows); err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "decisions")

		return err
	}

	return nil
}

// recordPublish stores a new generation, with its prefixes, before it is
// served, so a restart never lowers the generation.
func (s *Scorer) recordPublish(ctx context.Context, now time.Time, c *publish.Change, res engine.Result) error {
	deferred := 0
	for _, ps := range res.Deferred {
		deferred += len(ps)
	}

	row := []any{
		now, c.Generation, c.PreviousGeneration, string(c.Mode), uint32(len(c.CIDRs)), //nolint:gosec // at most caps.maxEntries
		uint32(c.Added), uint32(c.Removed), uint32(deferred), c.PayloadSHA256, nonNil(c.CIDRs), //nolint:gosec // bounded by the list sizes
	}

	if err := s.src.Insert(ctx, s.cfg.Tables.Publishes, publishColumns, [][]any{row}); err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "publishes")

		return err
	}

	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}

	return s
}
