package service

import (
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ethpandaops/banoor/internal/engine"
	"github.com/ethpandaops/banoor/internal/netaddr"
	"github.com/ethpandaops/banoor/internal/publish"
)

func (s *Service) defineMetrics() {
	m := s.metrics
	m.Gauge("banoor_build_info", "The running version.")
	m.Gauge("banoor_mode", "1 for the kill switch's current mode.")
	m.Gauge("banoor_generation", "Generation of the served list.")
	m.Gauge("banoor_list_generated_timestamp_seconds", "When the served list was signed.")
	m.Gauge("banoor_entries", "Entries in the served list, by kind (ipv4, ipv6, range) and source.")
	m.Counter("banoor_new_bans_total", "Bans issued by the scorer, by kind.")
	m.Gauge("banoor_suppressed", "Sources over the threshold that the allowlist or a lift keeps off the list.")
	m.Counter("banoor_suppressed_total", "Times a source went over the threshold while allowlisted or lifted.")
	m.Gauge("banoor_deferred", "Sources held back by a cap, by reason.")
	m.Counter("banoor_deferred_total", "Times a source was first held back by a cap, by reason.")
	m.Counter("banoor_signal_would_ban_total", "Times a shadow signal would first have put a source over the threshold, by signal.")
	m.Gauge("banoor_scored_sources", "Sources with any points in the window.")
	m.Counter("banoor_invalid_addresses_total", "Signal rows whose address did not parse.")
	m.Gauge("banoor_manual_entries", "Manual entries in force, by action.")
	m.Gauge("banoor_manual_invalid", "Manual entries skipped as invalid.")
	m.Gauge("banoor_allowlist_prefixes", "Allowlisted prefixes, by list.")
	m.Counter("banoor_run_blocked_total", "Runs that published nothing, by reason.")
	m.Counter("banoor_source_errors_total", "Failed queries and inserts, by query.")
	m.Gauge("banoor_last_success_timestamp_seconds", "When a run last succeeded.")
	m.Gauge("banoor_run_duration_seconds", "How long the last successful run took.")
	m.Counter("banoor_fetches_total", "List requests, by user and result.")
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func (s *Service) observe(res engine.Result, start time.Time) {
	m := s.metrics
	m.Reset("banoor_mode")
	for _, mode := range []engine.Mode{engine.Enforce, engine.Shadow, engine.Empty} {
		v := 0.0
		if mode == s.mode {
			v = 1
		}
		m.Set("banoor_mode", v, "mode", string(mode))
	}
	if cur := s.pub.Load().Current(); cur != nil {
		m.Set("banoor_generation", float64(cur.Generation))
		m.Set("banoor_list_generated_timestamp_seconds", float64(cur.GeneratedAt.Unix()))
	}
	m.Reset("banoor_entries")
	for _, kind := range []string{"ipv4", "ipv6", "range"} {
		for _, src := range []string{engine.SourceScorer, engine.SourceManual} {
			m.Set("banoor_entries", 0, "kind", kind, "source", src)
		}
	}
	counts := map[[2]string]int{}
	for _, e := range res.Entries {
		p := netip.MustParsePrefix(e.CIDR)
		counts[[2]string{netaddr.Kind(p, s.cfg.IPv6Prefix), e.Source}]++
	}
	for k, n := range counts {
		m.Set("banoor_entries", float64(n), "kind", k[0], "source", k[1])
	}
	for _, b := range res.NewBans {
		m.Add("banoor_new_bans_total", 1, "kind", netaddr.Kind(b.Unit, s.cfg.IPv6Prefix))
	}
	m.Set("banoor_suppressed", float64(len(res.Suppressed)))
	m.Add("banoor_suppressed_total", float64(s.episodes.Observe("suppressed", strs(res.Suppressed))))
	for _, reason := range []string{engine.DeferHourCap, engine.DeferFeederCap, engine.DeferMaxEntries, engine.DeferCoverage, engine.DeferGenerationCap} {
		units := res.Deferred[reason]
		m.Set("banoor_deferred", float64(len(units)), "reason", reason)
		m.Add("banoor_deferred_total", float64(s.episodes.Observe("deferred:"+reason, strs(units))), "reason", reason)
	}
	for _, sig := range s.cfg.Signals {
		if sig.Mode == "shadow" {
			units := res.WouldBan[sig.Name]
			m.Add("banoor_signal_would_ban_total", float64(s.episodes.Observe("would:"+sig.Name, strs(units))), "signal", sig.Name)
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

var userLabel = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *Service) fetchUser(r *http.Request) string {
	if s.cfg.Server.FetchUserHeader == "" {
		return "unknown"
	}
	u := r.Header.Get(s.cfg.Server.FetchUserHeader)
	switch {
	case u == "":
		return "unknown"
	case !userLabel.MatchString(u):
		return "invalid"
	}
	return u
}

// Handler serves the list at the configured path, /metrics and /healthz.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+s.cfg.Server.Path, s.serveList)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = s.metrics.Write(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func (s *Service) serveList(w http.ResponseWriter, r *http.Request) {
	user := s.fetchUser(r)
	pub := s.pub.Load()
	var c *publish.Current
	if pub != nil {
		c = pub.Current()
	}
	if c == nil {
		s.metrics.Add("banoor_fetches_total", 1, "user", user, "result", "unavailable")
		http.Error(w, "no list has been published yet", http.StatusServiceUnavailable)
		return
	}
	h := w.Header()
	h.Set("ETag", c.ETag)
	h.Set("Cache-Control", "no-cache")
	if matches(r.Header.Get("If-None-Match"), c.ETag) {
		s.metrics.Add("banoor_fetches_total", 1, "user", user, "result", "not_modified")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", "application/json")
	s.metrics.Add("banoor_fetches_total", 1, "user", user, "result", "ok")
	_, _ = w.Write(c.Body)
}

// matches reports whether an If-None-Match header names etag, using the weak
// comparison RFC 9110 specifies for it.
func matches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == "*" || t == etag {
			return true
		}
	}
	return false
}
