// Package engine turns per-source signal counts into a ban list. It is a
// pure decision package: Step reads its inputs and returns what it would do,
// and the engine changes only when Commit is called after the caller has
// recorded the new bans.
package engine

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ethpandaops/banoor/pkg/manual"
	"github.com/ethpandaops/banoor/pkg/netaddr"
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

// Config is the scoring policy.
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
	Manual []manual.Entry
}

// Ban is one scored ban.
type Ban struct {
	Unit    netip.Prefix
	Issued  time.Time
	Expires time.Time
	Points  float64
	// Number is 1 for a first ban, 2 for the next within the repeat
	// window, and so on.
	Number  int
	Feeders []string
	Signals map[string]float64
	Reason  string
}

// Entry is one published prefix.
type Entry struct {
	CIDR    string `json:"cidr"`
	Expires int64  `json:"expires"`
	Source  string `json:"source"`
	Reason  string `json:"reason"`
	Commit  string `json:"commit"`
}

// Entry sources.
const (
	SourceScorer = "scorer"
	SourceManual = "manual"
)

// Suppression is a source or manual ban kept off the list.
type Suppression struct {
	Prefix netip.Prefix
	Points float64
	// By is SuppressedByAllowlist or SuppressedByLift.
	By     string
	Manual bool
}

// What suppressed an entry.
const (
	SuppressedByAllowlist = "allowlist"
	SuppressedByLift      = "lift"
)

// Deferral reasons.
const (
	DeferHourCap       = "hour_cap"
	DeferFeederCap     = "feeder_cap"
	DeferMaxEntries    = "max_entries"
	DeferCoverage      = "coverage"
	DeferGenerationCap = "generation_cap"
)

// DeferReasons lists every deferral reason.
var DeferReasons = []string{DeferHourCap, DeferFeederCap, DeferMaxEntries, DeferCoverage, DeferGenerationCap}

// Result is what one step would do.
type Result struct {
	Now       time.Time
	NewBans   []Ban
	NewManual []manual.Entry
	Entries   []Entry
	// Suppressed are sources over the threshold, and manual bans, that the
	// allowlist or a lift keeps off the list.
	Suppressed []Suppression
	// Deferred are entries a cap holds back, by reason. They are considered
	// again at the next step.
	Deferred map[string][]netip.Prefix
	// WouldBan are sources a shadow signal would have banned, by signal.
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
	published  map[string]bool
}

// New returns an engine with no history.
func New(cfg Config) *Engine {
	return &Engine{
		cfg:        cfg,
		bans:       map[netip.Prefix]Ban{},
		history:    map[netip.Prefix][]time.Time{},
		seenManual: map[string]bool{},
		published:  map[string]bool{},
	}
}

// Restore loads what was recorded before a restart: the bans, the manual
// entries already recorded, and the prefixes of the last published list,
// which the next step's additions are counted against.
func (e *Engine) Restore(bans []Ban, manualKeys, published []string) {
	sorted := slices.Clone(bans)
	slices.SortFunc(sorted, func(a, b Ban) int { return a.Issued.Compare(b.Issued) })

	for _, b := range sorted {
		e.record(b)
	}

	for _, k := range manualKeys {
		e.seenManual[k] = true
	}

	e.setPublished(published)
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

func (e *Engine) setPublished(cidrs []string) {
	e.published = make(map[string]bool, len(cidrs))
	for _, c := range cidrs {
		e.published[c] = true
	}
}

// Published tells the engine what consumers now hold, for the next step's
// generation cap.
func (e *Engine) Published(entries []Entry) {
	cidrs := make([]string, len(entries))
	for i, en := range entries {
		cidrs[i] = en.CIDR
	}

	e.setPublished(cidrs)
}

func (e *Engine) active(u netip.Prefix, now time.Time) bool {
	b, ok := e.bans[u]

	return ok && b.Expires.After(now)
}

// Step computes the next list from in without changing the engine.
func (e *Engine) Step(in Inputs) Result {
	res := Result{
		Now:          in.Now,
		Deferred:     map[string][]netip.Prefix{},
		WouldBan:     map[string][]netip.Prefix{},
		ActiveManual: map[string]int{},
	}

	scores, shadow := e.score(in, &res)
	v := e.manualView(in, &res)
	cands := e.candidates(in.Now, scores, v, &res)

	var listed *netaddr.Set

	res.Entries, listed = e.admit(in.Mode, in.Now, e.items(in.Now, v, cands), &res)
	e.wouldBan(in.Now, scores, shadow, v, listed, &res)

	slices.SortFunc(res.Suppressed, func(a, b Suppression) int {
		if d := a.Prefix.Compare(b.Prefix); d != 0 {
			return d
		}

		return strings.Compare(a.By, b.By)
	})

	return res
}

type candidate struct {
	unit    netip.Prefix
	points  float64
	signals map[string]float64
	feeders map[string]float64
}

func (c *candidate) rankedFeeders() []string {
	out := make([]string, 0, len(c.feeders))
	for f, p := range c.feeders {
		if p > 0 {
			out = append(out, f)
		}
	}

	slices.SortFunc(out, func(a, b string) int {
		if d := cmp.Compare(c.feeders[b], c.feeders[a]); d != 0 {
			return d
		}

		return strings.Compare(a, b)
	})

	return out[:min(len(out), 10)]
}

func (e *Engine) score(in Inputs, res *Result) (map[netip.Prefix]*candidate, map[string]map[netip.Prefix]float64) {
	scores := map[netip.Prefix]*candidate{}
	shadow := map[string]map[netip.Prefix]float64{}

	for _, sig := range e.cfg.Signals {
		points := e.scoreSignal(sig, in.Rows[sig.Name], scores, res)

		if sig.Shadow {
			shadow[sig.Name] = points

			continue
		}

		for u, p := range points {
			scores[u].points += p
		}
	}

	for _, c := range scores {
		if c.points > 0 {
			res.Scored++
		}
	}

	return scores, shadow
}

// scoreSignal returns one signal's points per source, capped, and adds a
// counting signal's attempts and feeders to the candidates.
func (e *Engine) scoreSignal(sig Signal, rows []Row, scores map[netip.Prefix]*candidate, res *Result) map[netip.Prefix]float64 {
	points := map[netip.Prefix]float64{}

	for _, r := range rows {
		u, err := netaddr.Unit(r.Address, e.cfg.IPv6Prefix)
		if err != nil || math.IsNaN(r.Attempts) || math.IsInf(r.Attempts, 0) || r.Attempts < 0 {
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

	if sig.Cap > 0 {
		for u, p := range points {
			points[u] = math.Min(p, sig.Cap)
		}
	}

	return points
}

// view is the step's allowlist and manual entries.
type view struct {
	allow *netaddr.Set
	lifts *netaddr.Set
	bans  []manual.Entry
}

func (v view) blocked(p netip.Prefix) bool { return v.allow.Overlaps(p) || v.lifts.Overlaps(p) }

// by names what blocks p: the allowlist wins over a lift.
func (v view) by(p netip.Prefix) string {
	if v.allow.Overlaps(p) {
		return SuppressedByAllowlist
	}

	return SuppressedByLift
}

// manualView sorts the manual entries in force into lifts and the bans that
// no lift or allowlist entry overlaps.
func (e *Engine) manualView(in Inputs, res *Result) view {
	v := view{allow: in.Allow, lifts: netaddr.NewSet()}

	var active []manual.Entry

	for _, m := range in.Manual {
		if !m.Expires.After(in.Now) {
			continue
		}

		active = append(active, m)
		res.ActiveManual[m.Action]++

		if !e.seenManual[m.Key()] {
			res.NewManual = append(res.NewManual, m)
		}

		if m.Action == manual.Lift {
			v.lifts.Add(m.Prefix)
		}
	}

	for _, m := range active {
		if m.Action != manual.Ban {
			continue
		}

		if v.blocked(m.Prefix) {
			res.Suppressed = append(res.Suppressed, Suppression{Prefix: m.Prefix, By: v.by(m.Prefix), Manual: true})

			continue
		}

		v.bans = append(v.bans, m)
	}

	return v
}

// candidates are the sources at the threshold that are not banned yet;
// allowlisted or lifted ones are suppressed.
func (e *Engine) candidates(now time.Time, scores map[netip.Prefix]*candidate, v view, res *Result) []*candidate {
	var out []*candidate

	for _, c := range scores {
		if c.points < e.cfg.Threshold || e.active(c.unit, now) {
			continue
		}

		if v.blocked(c.unit) {
			res.Suppressed = append(res.Suppressed, Suppression{Prefix: c.unit, Points: c.points, By: v.by(c.unit)})

			continue
		}

		out = append(out, c)
	}

	return out
}

// wouldBan reports the sources a shadow signal alone would have put over
// the threshold, among those that could be banned at all: not blocked, not
// banned and not inside a listed manual ban.
func (e *Engine) wouldBan(now time.Time, scores map[netip.Prefix]*candidate, shadow map[string]map[netip.Prefix]float64, v view, listed *netaddr.Set, res *Result) {
	for name, pts := range shadow {
		for u, p := range pts {
			base := 0.0
			if c := scores[u]; c != nil {
				base = c.points
			}

			if base >= e.cfg.Threshold || base+p < e.cfg.Threshold {
				continue
			}

			if v.blocked(u) || e.active(u, now) || listed.Covers(u) {
				continue
			}

			res.WouldBan[name] = append(res.WouldBan[name], u)
		}

		slices.SortFunc(res.WouldBan[name], netip.Prefix.Compare)
	}
}

type item struct {
	prefix netip.Prefix
	entry  Entry
	points float64
	manual bool
	cand   *candidate
}

// items is everything that could be published, in priority order: manual
// bans, then scored bans and candidates by points.
func (e *Engine) items(now time.Time, v view, cands []*candidate) []item {
	out := make([]item, 0, len(v.bans)+len(e.bans)+len(cands))

	for _, m := range v.bans {
		out = append(out, item{prefix: m.Prefix, manual: true, entry: Entry{
			CIDR: m.Prefix.String(), Expires: m.Expires.Unix(), Source: SourceManual, Reason: m.Reason, Commit: m.Commit,
		}})
	}

	for _, b := range e.bans {
		if !b.Expires.After(now) || v.blocked(b.Unit) {
			continue
		}

		out = append(out, item{prefix: b.Unit, points: b.Points, entry: banEntry(b)})
	}

	for _, c := range cands {
		out = append(out, item{prefix: c.unit, points: c.points, cand: c})
	}

	slices.SortFunc(out, func(a, b item) int {
		if a.manual != b.manual {
			if a.manual {
				return -1
			}

			return 1
		}

		if d := cmp.Compare(b.points, a.points); d != 0 {
			return d
		}

		return strings.Compare(a.prefix.String(), b.prefix.String())
	})

	return out
}

func banEntry(b Ban) Entry {
	return Entry{CIDR: b.Unit.String(), Expires: b.Expires.Unix(), Source: SourceScorer, Reason: b.Reason}
}

// budget is what the caps leave as items are admitted.
type budget struct {
	entries     int
	v4, v6      uint64
	added       int
	newThisHour int
	perFeeder   map[string]int
	listed      map[string]bool
}

func (e *Engine) newBudget(now time.Time) *budget {
	b := &budget{perFeeder: map[string]int{}, listed: map[string]bool{}}

	hourAgo := now.Add(-time.Hour)
	for _, r := range e.recent {
		if r.at.After(hourAgo) {
			b.newThisHour++
			b.perFeeder[r.feeder]++
		}
	}

	return b
}

// admit walks the items in priority order and keeps each one the caps
// allow. A candidate is banned only if it is published, so a ban that could
// not be published is never issued, recorded or counted as a repeat. A
// scored ban or candidate inside a manual ban that was admitted is left
// out: the manual ban covers it. It returns the entries and the admitted
// manual prefixes.
func (e *Engine) admit(mode Mode, now time.Time, items []item, res *Result) ([]Entry, *netaddr.Set) {
	b := e.newBudget(now)
	kept := []Entry{}
	listed := netaddr.NewSet()

	for _, it := range items {
		if !it.manual && listed.Covers(it.prefix) {
			continue
		}

		var feeders []string
		if it.cand != nil {
			feeders = it.cand.rankedFeeders()
		}

		reason, skip := e.check(mode, it, feeders, b)
		if skip {
			continue
		}

		if reason != "" {
			res.Deferred[reason] = append(res.Deferred[reason], it.prefix)

			continue
		}

		v4, v6 := netaddr.Coverage(it.prefix)
		b.entries++
		b.v4 += v4
		b.v6 += v6
		b.listed[it.prefix.String()] = true

		if it.manual {
			listed.Add(it.prefix)
		}

		if !e.published[it.prefix.String()] {
			b.added++
		}

		if it.cand != nil {
			ban := e.newBan(it.cand, feeders, now)
			res.NewBans = append(res.NewBans, ban)
			it.entry = banEntry(ban)
			b.newThisHour++

			if len(feeders) > 0 {
				b.perFeeder[feeders[0]]++
			}
		}

		kept = append(kept, it.entry)
	}

	if mode == Empty {
		return []Entry{}, listed
	}

	slices.SortFunc(kept, func(a, b Entry) int { return strings.Compare(a.CIDR, b.CIDR) })

	return kept, listed
}

// check returns why an item must wait, or skip for a prefix already listed.
func (e *Engine) check(mode Mode, it item, feeders []string, b *budget) (reason string, skip bool) {
	caps := e.cfg.Caps
	key := it.prefix.String()

	if it.cand != nil {
		top := ""
		if len(feeders) > 0 {
			top = feeders[0]
		}

		switch {
		case b.newThisHour >= caps.MaxNewPerHour:
			return DeferHourCap, false
		case b.perFeeder[top] >= caps.MaxNewPerFeederPerHour:
			return DeferFeederCap, false
		}
	}

	if b.listed[key] {
		return "", true
	}

	if b.entries >= caps.MaxEntries {
		return DeferMaxEntries, false
	}

	v4, v6 := netaddr.Coverage(it.prefix)
	if v4 > caps.MaxIPv4Addresses-b.v4 || v6 > caps.MaxIPv6Networks-b.v6 {
		return DeferCoverage, false
	}

	// While the list is empty nothing reaches consumers, so additions are
	// counted from the list they hold once it is not.
	if mode != Empty && !e.published[key] && b.added >= caps.MaxAddedPerGeneration {
		return DeferGenerationCap, false
	}

	return "", false
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

	slices.Sort(names)

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
		kept := slices.DeleteFunc(ts, func(t time.Time) bool { return !t.After(horizon) })
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
	e.recent = slices.DeleteFunc(e.recent, func(x issued) bool { return !x.at.After(hourAgo) })
}
