package scorer

import (
	"net/netip"
	"sync"
	"time"

	"github.com/ethpandaops/banoor/pkg/engine"
	"github.com/ethpandaops/banoor/pkg/netaddr"
)

func (s *Scorer) defineMetrics() {
	m := s.metrics
	m.Gauge("banoor_mode", "1 for the kill switch's current mode.")
	m.Gauge("banoor_generation", "Generation of the served list.")
	m.Gauge("banoor_list_generated_timestamp_seconds", "When the served list was signed.")
	m.Gauge("banoor_entries", "Entries in the served list, by kind (ipv4, ipv6, range) and source.")
	m.Counter("banoor_new_bans_total", "Bans issued by the scorer, by kind.")
	m.Gauge("banoor_suppressed", "Sources over the threshold, and manual bans, kept off the list by the allowlist or a lift.")
	m.Counter("banoor_suppressed_total", "Times a source was first kept off the list by the allowlist or a lift.")
	m.Gauge("banoor_deferred", "Entries held back by a cap, by reason.")
	m.Counter("banoor_deferred_total", "Times an entry was first held back by a cap, by reason.")
	m.Counter("banoor_signal_would_ban_total", "Times a shadow signal would first have banned a source, by signal.")
	m.Gauge("banoor_scored_sources", "Sources with any points in the window.")
	m.Counter("banoor_invalid_addresses_total", "Signal rows whose address did not parse.")
	m.Gauge("banoor_manual_entries", "Manual entries in force, by action.")
	m.Gauge("banoor_manual_invalid", "Manual entries skipped as invalid.")
	m.Gauge("banoor_allowlist_prefixes", "Allowlisted prefixes, by list.")
	m.Counter("banoor_run_blocked_total", "Runs that published nothing, by reason.")
	m.Counter("banoor_source_errors_total", "Failed queries and inserts, by query.")
	m.Gauge("banoor_last_success_timestamp_seconds", "When a run last succeeded.")
	m.Gauge("banoor_run_duration_seconds", "How long the last successful run took.")
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}

	return out
}

var (
	modes   = []engine.Mode{engine.Enforce, engine.Shadow, engine.Empty}
	kinds   = []string{"ipv4", "ipv6", "range"}
	sources = []string{engine.SourceScorer, engine.SourceManual}
)

func (s *Scorer) observe(res engine.Result, start time.Time) {
	m := s.metrics

	for _, mode := range modes {
		v := 0.0
		if mode == s.mode {
			v = 1
		}

		m.Set("banoor_mode", v, "mode", string(mode))
	}

	if cur := s.Current(); cur != nil {
		m.Set("banoor_generation", float64(cur.Generation))
		m.Set("banoor_list_generated_timestamp_seconds", float64(cur.GeneratedAt.Unix()))
	}

	counts := map[[2]string]int{}

	for _, e := range res.Entries {
		if p, err := netip.ParsePrefix(e.CIDR); err == nil {
			counts[[2]string{netaddr.Kind(p, s.cfg.IPv6Prefix), e.Source}]++
		}
	}

	for _, kind := range kinds {
		for _, src := range sources {
			m.Set("banoor_entries", float64(counts[[2]string{kind, src}]), "kind", kind, "source", src)
		}
	}

	for _, b := range res.NewBans {
		m.Add("banoor_new_bans_total", 1, "kind", netaddr.Kind(b.Unit, s.cfg.IPv6Prefix))
	}

	m.Set("banoor_suppressed", float64(len(res.Suppressed)))
	m.Add("banoor_suppressed_total", float64(s.episodes.observe("suppressed", strs(res.Suppressed))))

	for _, reason := range engine.DeferReasons {
		units := res.Deferred[reason]
		m.Set("banoor_deferred", float64(len(units)), "reason", reason)
		m.Add("banoor_deferred_total", float64(s.episodes.observe("deferred:"+reason, strs(units))), "reason", reason)
	}

	for _, sig := range s.cfg.Signals {
		if sig.Mode == "shadow" {
			units := res.WouldBan[sig.Name]
			m.Add("banoor_signal_would_ban_total", float64(s.episodes.observe("would:"+sig.Name, strs(units))), "signal", sig.Name)
		}
	}

	m.Set("banoor_scored_sources", float64(res.Scored))
	m.Add("banoor_invalid_addresses_total", float64(res.Invalid))

	for _, a := range []string{"ban", "lift"} {
		m.Set("banoor_manual_entries", float64(res.ActiveManual[a]), "action", a)
	}

	now := s.now()
	m.Set("banoor_last_success_timestamp_seconds", float64(now.Unix()))
	m.Set("banoor_run_duration_seconds", now.Sub(start).Seconds())
}

// episodes counts how often keys newly appear in a set, so a source that
// stays over a cap for many runs counts once, not once per run.
type episodes struct {
	mu   sync.Mutex
	seen map[string]map[string]bool
}

func newEpisodes() *episodes { return &episodes{seen: map[string]map[string]bool{}} }

// observe replaces the set for group with keys and returns how many keys
// were not in it before.
func (e *episodes) observe(group string, keys []string) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	prev := e.seen[group]
	next := make(map[string]bool, len(keys))
	n := 0

	for _, k := range keys {
		if !prev[k] && !next[k] {
			n++
		}

		next[k] = true
	}

	e.seen[group] = next

	return n
}
