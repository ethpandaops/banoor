// Package engine turns per-source signal counts into a ban list. It is pure:
// it reads its inputs, returns what it would do, and changes its own state
// only when Commit is called after the caller has recorded the new bans.
package engine

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ethpandaops/banoor/internal/lists"
	"github.com/ethpandaops/banoor/internal/netaddr"
)

// Mode is the kill switch's position.
type Mode string

const (
	// Enforce publishes the list; consumers apply it in their own mode.
	Enforce Mode = "enforce"
	// Shadow publishes the list and tells consumers to drop nothing.
	Shadow Mode = "shadow"
	// Empty publishes an empty list.
	Empty Mode = "empty"
)

// ParseMode accepts enforce, shadow or empty.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case Enforce, Shadow, Empty:
		return m, nil
	}
	return "", fmt.Errorf("mode %q: want enforce, shadow or empty", s)
}

// Signal weighs one kind of evidence. Points from a signal are Weight per
// attempt, at most Cap per source over the window (0 means no cap). A shadow
// signal is scored and reported but never counts toward a ban.
type Signal struct {
	Name   string
	Weight float64
	Cap    float64
	Shadow bool
}

// Caps bound what one step may publish and ban.
type Caps struct {
	MaxEntries             int
	MaxAddedPerGeneration  int
	MaxNewPerHour          int
	MaxNewPerFeederPerHour int
	MaxIPv4Addresses       uint64
	MaxIPv6Networks        uint64
}

// Config is the engine's scoring policy.
type Config struct {
	Threshold    float64
	Window       time.Duration
	IPv6Prefix   int
	BanBase      time.Duration
	BanMax       time.Duration
	RepeatWindow time.Duration
	Caps         Caps
	Signals      []Signal
}

// Row is one signal's count for one source and feeder over the window. The
// feeder is whoever reported the attempts, such as a host; caps on new bans
// are kept per feeder.
type Row struct {
	Address  string
	Feeder   string
	Attempts float64
}

// Inputs is everything one step reads.
type Inputs struct {
	Now    time.Time
	Mode   Mode
	Rows   map[string][]Row
	Allow  *netaddr.Set
	Manual []lists.Manual
}

// Ban is one scored ban.
type Ban struct {
	Unit    netip.Prefix
	Issued  time.Time
	Expires time.Time
	Points  float64
	Number  int // 1 for a first ban, 2 for the next within the repeat window, ...
	Feeders []string
	Signals map[string]float64 // attempts per signal
	Reason  string
}

// Entry is one published prefix.
type Entry struct {
	CIDR    string `json:"cidr"`
	Expires int64  `json:"expires"`
	Source  string `json:"source"`
	Reason  string `json:"reason,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

// Entry sources.
const (
	SourceScorer = "scorer"
	SourceManual = "manual"
)

// Deferral reasons.
const (
	DeferHourCap       = "hour_cap"
	DeferFeederCap     = "feeder_cap"
	DeferMaxEntries    = "max_entries"
	DeferCoverage      = "coverage"
	DeferGenerationCap = "generation_cap"
)

// Result is what one step would do.
type Result struct {
	Now       time.Time
	NewBans   []Ban
	NewManual []lists.Manual
	Entries   []Entry
	// Suppressed are sources over the threshold that the allowlist or a
	// manual lift kept off the list.
	Suppressed []netip.Prefix
	// Deferred are sources held back by a cap, by reason. They are
	// considered again at the next step.
	Deferred map[string][]netip.Prefix
	// WouldBan are sources a shadow signal would have put over the
	// threshold, by signal.
	WouldBan map[string][]netip.Prefix
	// Scored counts sources with any points from counting signals.
	Scored int
	// Invalid counts rows whose address did not parse.
	Invalid int
	// ActiveManual counts manual entries in force, by action.
	ActiveManual map[string]int
}

type issued struct {
	at     time.Time
	feeder string
}

// Engine holds the bans issued so far.
type Engine struct {
	cfg        Config
	bans       map[netip.Prefix]Ban
	history    map[netip.Prefix][]time.Time
	recent     []issued
	seenManual map[string]bool
	published  map[string]bool // nil until something is published
}

// New returns an engine with no history.
func New(cfg Config) *Engine {
	return &Engine{
		cfg:        cfg,
		bans:       map[netip.Prefix]Ban{},
		history:    map[netip.Prefix][]time.Time{},
		seenManual: map[string]bool{},
	}
}

// Restore loads bans and manual entries recorded before a restart. Until the
// first list is published after it, the generation cap does not apply: the
// restored list is what consumers already hold.
func (e *Engine) Restore(bans []Ban, manualKeys []string) {
	sort.Slice(bans, func(i, j int) bool { return bans[i].Issued.Before(bans[j].Issued) })
	for _, b := range bans {
		e.record(b)
	}
	for _, k := range manualKeys {
		e.seenManual[k] = true
	}
}

func (e *Engine) record(b Ban) {
	e.bans[b.Unit] = b
	e.history[b.Unit] = append(e.history[b.Unit], b.Issued)
	feeder := ""
	if len(b.Feeders) > 0 {
		feeder = b.Feeders[0]
	}
	e.recent = append(e.recent, issued{at: b.Issued, feeder: feeder})
}

type candidate struct {
	unit    netip.Prefix
	points  float64
	signals map[string]float64
	feeders map[string]float64
}

func (c *candidate) topFeeders() []string {
	out := make([]string, 0, len(c.feeders))
	for f, p := range c.feeders {
		if p > 0 {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c.feeders[out[i]] != c.feeders[out[j]] {
			return c.feeders[out[i]] > c.feeders[out[j]]
		}
		return out[i] < out[j]
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// Step computes the next list from in without changing the engine.
func (e *Engine) Step(in Inputs) Result {
	now := in.Now
	res := Result{
		Now:          now,
		Deferred:     map[string][]netip.Prefix{},
		WouldBan:     map[string][]netip.Prefix{},
		ActiveManual: map[string]int{},
	}

	scores, shadow := e.score(in, &res)

	var manualBans []lists.Manual
	banned, lifts := netaddr.NewSet(), netaddr.NewSet()
	for _, m := range in.Manual {
		if !m.Expires.After(now) {
			continue
		}
		res.ActiveManual[m.Action]++
		if !e.seenManual[m.Key()] {
			res.NewManual = append(res.NewManual, m)
		}
		if m.Action == lists.Lift {
			lifts.Add(m.Prefix)
		} else {
			manualBans = append(manualBans, m)
			banned.Add(m.Prefix)
		}
	}
	blocked := func(p netip.Prefix) bool { return in.Allow.Overlaps(p) || lifts.Overlaps(p) }

	active := func(u netip.Prefix) bool {
		b, ok := e.bans[u]
		return ok && b.Expires.After(now)
	}

	var cands []*candidate
	for _, c := range scores {
		if c.points < e.cfg.Threshold || active(c.unit) || banned.Covers(c.unit) {
			continue
		}
		if blocked(c.unit) {
			res.Suppressed = append(res.Suppressed, c.unit)
			continue
		}
		cands = append(cands, c)
	}
	for name, pts := range shadow {
		for u, p := range pts {
			base := 0.0
			if c := scores[u]; c != nil {
				base = c.points
			}
			if base < e.cfg.Threshold && base+p >= e.cfg.Threshold {
				res.WouldBan[name] = append(res.WouldBan[name], u)
			}
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].points != cands[j].points {
			return cands[i].points > cands[j].points
		}
		return cands[i].unit.String() < cands[j].unit.String()
	})

	hourAgo := now.Add(-time.Hour)
	newThisHour := 0
	perFeeder := map[string]int{}
	for _, r := range e.recent {
		if r.at.After(hourAgo) {
			newThisHour++
			perFeeder[r.feeder]++
		}
	}
	activeCount := len(manualBans)
	for u := range e.bans {
		if active(u) {
			activeCount++
		}
	}

	caps := e.cfg.Caps
	for _, c := range cands {
		feeders := c.topFeeders()
		top := ""
		if len(feeders) > 0 {
			top = feeders[0]
		}
		switch {
		case newThisHour >= caps.MaxNewPerHour:
			res.Deferred[DeferHourCap] = append(res.Deferred[DeferHourCap], c.unit)
		case perFeeder[top] >= caps.MaxNewPerFeederPerHour:
			res.Deferred[DeferFeederCap] = append(res.Deferred[DeferFeederCap], c.unit)
		case activeCount >= caps.MaxEntries:
			res.Deferred[DeferMaxEntries] = append(res.Deferred[DeferMaxEntries], c.unit)
		default:
			newThisHour++
			perFeeder[top]++
			activeCount++
			res.NewBans = append(res.NewBans, e.newBan(c, feeders, now))
		}
	}

	res.Entries = e.entries(in.Mode, now, manualBans, res.NewBans, blocked, &res)
	return res
}

func (e *Engine) score(in Inputs, res *Result) (map[netip.Prefix]*candidate, map[string]map[netip.Prefix]float64) {
	scores := map[netip.Prefix]*candidate{}
	shadow := map[string]map[netip.Prefix]float64{}
	for _, sig := range e.cfg.Signals {
		points := map[netip.Prefix]float64{}
		for _, r := range in.Rows[sig.Name] {
			u, err := netaddr.Unit(r.Address, e.cfg.IPv6Prefix)
			if err != nil {
				res.Invalid++
				continue
			}
			p := sig.Weight * r.Attempts
			points[u] += p
			if sig.Shadow {
				continue
			}
			c := scores[u]
			if c == nil {
				c = &candidate{unit: u, signals: map[string]float64{}, feeders: map[string]float64{}}
				scores[u] = c
			}
			c.signals[sig.Name] += r.Attempts
			c.feeders[r.Feeder] += p
		}
		for u, p := range points {
			if sig.Cap > 0 {
				p = math.Min(p, sig.Cap)
			}
			if sig.Shadow {
				if shadow[sig.Name] == nil {
					shadow[sig.Name] = map[netip.Prefix]float64{}
				}
				shadow[sig.Name][u] = p
			} else {
				scores[u].points += p
			}
		}
	}
	for _, c := range scores {
		if c.points > 0 {
			res.Scored++
		}
	}
	return scores, shadow
}

func (e *Engine) newBan(c *candidate, feeders []string, now time.Time) Ban {
	earlier := 0
	for _, t := range e.history[c.unit] {
		if now.Sub(t) < e.cfg.RepeatWindow {
			earlier++
		}
	}
	d := e.cfg.BanBase
	for i := 0; i < earlier && d < e.cfg.BanMax; i++ {
		d *= 2
	}
	d = min(d, e.cfg.BanMax)

	names := make([]string, 0, len(c.signals))
	for n := range c.signals {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%g", n, c.signals[n]))
	}
	return Ban{
		Unit:    c.unit,
		Issued:  now,
		Expires: now.Add(d),
		Points:  c.points,
		Number:  earlier + 1,
		Feeders: feeders,
		Signals: c.signals,
		Reason:  fmt.Sprintf("%s in %s, ban %d", strings.Join(parts, " "), shortDuration(e.cfg.Window), earlier+1),
	}
}

func shortDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return d.String()
}

type item struct {
	prefix netip.Prefix
	entry  Entry
	points float64
	manual bool
}

// entries builds the published list in priority order (manual bans, then
// scored bans by points) and applies the size, coverage and per-generation
// caps, so that past any cap the highest-priority entries are published and
// the rest wait.
func (e *Engine) entries(mode Mode, now time.Time, manual []lists.Manual, newBans []Ban, blocked func(netip.Prefix) bool, res *Result) []Entry {
	out := []Entry{}
	if mode == Empty {
		return out
	}
	var items []item
	for _, m := range manual {
		if blocked(m.Prefix) {
			res.Suppressed = append(res.Suppressed, m.Prefix)
			continue
		}
		items = append(items, item{prefix: m.Prefix, manual: true, entry: Entry{
			CIDR: m.Prefix.String(), Expires: m.Expires.Unix(), Source: SourceManual, Reason: m.Reason, Commit: m.Commit,
		}})
	}
	bans := make([]Ban, 0, len(e.bans)+len(newBans))
	for _, b := range e.bans {
		bans = append(bans, b)
	}
	bans = append(bans, newBans...)
	for _, b := range bans {
		if !b.Expires.After(now) || blocked(b.Unit) {
			continue
		}
		items = append(items, item{prefix: b.Unit, points: b.Points, entry: Entry{
			CIDR: b.Unit.String(), Expires: b.Expires.Unix(), Source: SourceScorer, Reason: b.Reason,
		}})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.manual != b.manual {
			return a.manual
		}
		if a.points != b.points {
			return a.points > b.points
		}
		return a.entry.CIDR < b.entry.CIDR
	})

	caps := e.cfg.Caps
	var v4, v6 uint64
	added := 0
	listed := map[string]bool{}
	for _, it := range items {
		if listed[it.entry.CIDR] {
			continue // a manual ban already lists this prefix
		}
		if len(out) >= caps.MaxEntries {
			res.Deferred[DeferMaxEntries] = append(res.Deferred[DeferMaxEntries], it.prefix)
			continue
		}
		a, b := netaddr.Coverage(it.prefix)
		if v4+a > caps.MaxIPv4Addresses || v6+b > caps.MaxIPv6Networks {
			res.Deferred[DeferCoverage] = append(res.Deferred[DeferCoverage], it.prefix)
			continue
		}
		isNew := e.published != nil && !e.published[it.entry.CIDR]
		if isNew && added >= caps.MaxAddedPerGeneration {
			res.Deferred[DeferGenerationCap] = append(res.Deferred[DeferGenerationCap], it.prefix)
			continue
		}
		if isNew {
			added++
		}
		v4, v6 = v4+a, v6+b
		listed[it.entry.CIDR] = true
		out = append(out, it.entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}

// Commit applies a step's new bans and manual entries after the caller has
// recorded them, and forgets what has aged out.
func (e *Engine) Commit(r Result) {
	for _, b := range r.NewBans {
		e.record(b)
	}
	for _, m := range r.NewManual {
		e.seenManual[m.Key()] = true
	}
	horizon := r.Now.Add(-e.cfg.RepeatWindow)
	for u, ts := range e.history {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(horizon) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(e.history, u)
		} else {
			e.history[u] = kept
		}
	}
	for u, b := range e.bans {
		if !b.Expires.After(r.Now) && e.history[u] == nil {
			delete(e.bans, u)
		}
	}
	hourAgo := r.Now.Add(-time.Hour)
	recent := e.recent[:0]
	for _, x := range e.recent {
		if x.at.After(hourAgo) {
			recent = append(recent, x)
		}
	}
	e.recent = recent
}

// Published tells the engine what consumers now hold, for the next step's
// generation cap.
func (e *Engine) Published(entries []Entry) {
	e.published = make(map[string]bool, len(entries))
	for _, en := range entries {
		e.published[en.CIDR] = true
	}
}
