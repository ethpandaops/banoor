package engine

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/pkg/manual"
	"github.com/ethpandaops/banoor/pkg/netaddr"
)

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

func testConfig() Config {
	return Config{
		Threshold:    50,
		Window:       24 * time.Hour,
		IPv6Prefix:   64,
		BanBase:      24 * time.Hour,
		BanMax:       21 * 24 * time.Hour,
		RepeatWindow: 30 * 24 * time.Hour,
		Caps: Caps{
			MaxEntries:             5000,
			MaxAddedPerGeneration:  500,
			MaxNewPerHour:          200,
			MaxNewPerFeederPerHour: 50,
			MaxIPv4Addresses:       1 << 20,
			MaxIPv6Networks:        1 << 20,
		},
		Signals: []Signal{
			{Name: "invalid_user", Weight: 1},
			{Name: "not_allowed", Weight: 1},
			{Name: "drop", Weight: 0},
		},
	}
}

func rows(r ...Row) []Row { return r }

func invalid(r ...Row) map[string][]Row { return map[string][]Row{"invalid_user": r} }

func cidrs(es []Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.CIDR)
	}

	return out
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}

	slices.Sort(out)

	return out
}

func banned(r Result) []string {
	out := make([]string, 0, len(r.NewBans))
	for _, b := range r.NewBans {
		out = append(out, b.Unit.String())
	}

	slices.Sort(out)

	return out
}

func lift(p string, until time.Time) manual.Entry {
	return manual.Entry{Action: manual.Lift, Prefix: netip.MustParsePrefix(p), Expires: until, Reason: "lift"}
}

func ban(p string, until time.Time) manual.Entry {
	return manual.Entry{Action: manual.Ban, Prefix: netip.MustParsePrefix(p), Expires: until, Reason: "by hand"}
}

// step runs one step and commits and publishes it, as the scorer does after
// recording it.
func step(e *Engine, in Inputs) Result {
	if in.Mode == "" {
		in.Mode = Enforce
	}

	r := e.Step(in)
	e.Commit(r)
	e.Published(r.Entries)

	return r
}

func TestThresholdIsSummedAcrossFeeders(t *testing.T) {
	t.Parallel()

	e := New(testConfig())
	r := step(e, Inputs{Now: t0, Rows: map[string][]Row{
		"invalid_user": rows(Row{"198.51.100.1", "host-a", 25}, Row{"198.51.100.2", "host-a", 49}),
		"not_allowed":  rows(Row{"198.51.100.1", "host-b", 30}),
	}})

	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32"}) {
		t.Fatalf("entries = %v, want only the source at 25+30", got)
	}

	b := r.NewBans[0]
	if !b.Expires.Equal(t0.Add(24*time.Hour)) || b.Number != 1 {
		t.Errorf("first ban lasts %v, number %d, want 24h, 1", b.Expires.Sub(t0), b.Number)
	}

	if b.Reason != "invalid_user=25 not_allowed=30 in 24h, ban 1" {
		t.Errorf("reason = %q", b.Reason)
	}

	// The feeder that contributed most points comes first: caps charge it.
	if !slices.Equal(b.Feeders, []string{"host-b", "host-a"}) {
		t.Errorf("feeders = %v", b.Feeders)
	}
}

func TestWeightsCapsAndShadowSignals(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Signals = append(cfg.Signals,
		Signal{Name: "capped", Weight: 1, Cap: 25},
		Signal{Name: "trial", Weight: 1, Shadow: true},
	)
	e := New(cfg)

	r := step(e, Inputs{Now: t0, Allow: netaddr.NewSet(netip.MustParsePrefix("198.51.100.6/32")), Rows: map[string][]Row{
		// A weight-0 signal never bans, however loud.
		"drop": rows(Row{"198.51.100.1", "h", 10000}),
		// The cap is per source, not per row: 60 + 60 attempts from two
		// feeders still give 25 points.
		"capped": rows(
			Row{"198.51.100.2", "a", 60}, Row{"198.51.100.2", "b", 60},
			Row{"198.51.100.3", "a", 100},
		),
		"invalid_user": rows(
			Row{"198.51.100.2", "a", 24}, Row{"198.51.100.3", "a", 25},
			Row{"198.51.100.4", "a", 30}, Row{"198.51.100.5", "a", 80}, Row{"198.51.100.6", "a", 30},
		),
		// The shadow signal would put .4 over (30 + 20); .5 is over already
		// and .6 is allowlisted, so neither is a would-ban.
		"trial": rows(Row{"198.51.100.4", "h", 20}, Row{"198.51.100.5", "h", 20}, Row{"198.51.100.6", "h", 20}),
	}})

	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.3/32", "198.51.100.5/32"}) {
		t.Fatalf("entries = %v", got)
	}

	if got := strs(r.WouldBan["trial"]); !slices.Equal(got, []string{"198.51.100.4/32"}) {
		t.Errorf("would-ban for trial = %v", got)
	}
}

func TestIPv6IsScoredPerNetwork(t *testing.T) {
	t.Parallel()

	e := New(testConfig())
	r := step(e, Inputs{Now: t0, Rows: invalid(
		Row{"2001:db8:1:2::a", "h", 30},
		Row{"2001:db8:1:2:ffff::b", "h", 20},
		Row{"2001:db8:1:3::a", "h", 49},
		Row{"not an address", "h", 99},
		// A query computing a ratio can return these; none is evidence.
		Row{"198.51.100.9", "h", math.NaN()},
		Row{"198.51.100.10", "h", math.Inf(1)},
		Row{"198.51.100.11", "h", -60},
	)})

	if got := cidrs(r.Entries); !slices.Equal(got, []string{"2001:db8:1:2::/64"}) {
		t.Fatalf("entries = %v", got)
	}

	if r.Invalid != 4 {
		t.Errorf("invalid = %d, want 4", r.Invalid)
	}
}

func TestAllowlistAndLiftsWin(t *testing.T) {
	t.Parallel()

	e := New(testConfig())
	allow := netaddr.NewSet(netip.MustParsePrefix("2001:db8:1:2::7/128"), netip.MustParsePrefix("198.51.100.0/28"))
	in := Inputs{Now: t0, Allow: allow, Rows: invalid(
		Row{"2001:db8:1:2::a", "h", 60}, // its /64 holds an allowed address
		Row{"198.51.100.5", "h", 60},    // inside an allowed range
		Row{"198.51.100.20", "h", 60},
		Row{"198.51.100.21", "h", 60},
	)}

	r := step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.20/32", "198.51.100.21/32"}) {
		t.Fatalf("entries = %v", got)
	}

	if got := strs(r.Suppressed); !slices.Equal(got, []string{"198.51.100.5/32", "2001:db8:1:2::/64"}) {
		t.Errorf("suppressed = %v", got)
	}

	// A lift takes an existing ban off the list until it expires.
	in.Now, in.Manual = t0.Add(time.Minute), []manual.Entry{lift("198.51.100.20/32", t0.Add(2*time.Hour))}

	r = step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.21/32"}) {
		t.Fatalf("with the lift, entries = %v", got)
	}

	if len(r.NewManual) != 1 || r.ActiveManual[manual.Lift] != 1 {
		t.Errorf("new manual = %v, active = %v", r.NewManual, r.ActiveManual)
	}

	in.Now = t0.Add(3 * time.Hour)

	r = step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.20/32", "198.51.100.21/32"}) {
		t.Fatalf("after the lift expired, entries = %v", got)
	}

	if len(r.NewManual) != 0 {
		t.Errorf("an expired lift was recorded again: %v", r.NewManual)
	}
}

func TestBlockedManualBanHidesNothing(t *testing.T) {
	t.Parallel()

	// A manual /24 with an allowlisted address inside it is not published,
	// so the sources inside it are scored as usual.
	e := New(testConfig())
	r := step(e, Inputs{
		Now:    t0,
		Allow:  netaddr.NewSet(netip.MustParsePrefix("203.0.113.5/32")),
		Manual: []manual.Entry{ban("203.0.113.0/24", t0.Add(time.Hour)), lift("198.51.100.0/24", t0.Add(time.Hour)), ban("198.51.100.0/24", t0.Add(time.Hour))},
		Rows:   invalid(Row{"203.0.113.7", "h", 500}),
	})

	if got := cidrs(r.Entries); !slices.Equal(got, []string{"203.0.113.7/32"}) {
		t.Fatalf("entries = %v", got)
	}

	if got := strs(r.Suppressed); !slices.Equal(got, []string{"198.51.100.0/24", "203.0.113.0/24"}) {
		t.Errorf("suppressed = %v", got)
	}
}

func TestHeldBackManualBanHidesNothing(t *testing.T) {
	t.Parallel()

	// Sixteen /48s fill the IPv6 coverage cap, so the last manual /48 waits,
	// and a loud /64 inside it is still considered on its own.
	e := New(testConfig())

	var bans []manual.Entry
	for i := range 17 {
		bans = append(bans, ban(fmt.Sprintf("2001:db8:%x::/48", i), t0.Add(time.Hour)))
	}

	r := step(e, Inputs{Now: t0, Manual: bans, Rows: invalid(Row{"2001:db8:f::1", "h", 500}, Row{"198.51.100.1", "h", 60})})
	if got := strs(r.Deferred[DeferCoverage]); !slices.Equal(got, []string{"2001:db8:f::/48", "2001:db8:f::/64"}) {
		t.Errorf("coverage-deferred = %v", got)
	}

	if got := banned(r); !slices.Equal(got, []string{"198.51.100.1/32"}) {
		t.Errorf("new bans = %v", got)
	}

	// A published scored ban stays listed while a new manual /24 around it
	// waits for the generation cap.
	cfg := testConfig()
	cfg.Caps.MaxAddedPerGeneration = 1
	e = New(cfg)
	e.Restore([]Ban{{Unit: netip.MustParsePrefix("198.51.100.7/32"), Issued: t0.Add(-time.Hour), Expires: t0.Add(time.Hour), Points: 60}}, nil, []string{"198.51.100.7/32"})

	r = step(e, Inputs{Now: t0, Manual: []manual.Entry{ban("192.0.2.0/24", t0.Add(time.Hour)), ban("198.51.100.0/24", t0.Add(time.Hour))}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"192.0.2.0/24", "198.51.100.7/32"}) {
		t.Fatalf("entries = %v", got)
	}

	if got := strs(r.Deferred[DeferGenerationCap]); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Errorf("generation-deferred = %v", got)
	}

	// Once the /24 is listed it covers the scored ban, which is listed once.
	r = step(e, Inputs{Now: t0.Add(time.Minute), Manual: []manual.Entry{ban("192.0.2.0/24", t0.Add(time.Hour)), ban("198.51.100.0/24", t0.Add(time.Hour))}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Fatalf("next generation: entries = %v", got)
	}
}

func TestRepeatBansDouble(t *testing.T) {
	t.Parallel()

	e := New(testConfig())
	in := Inputs{Rows: invalid(Row{"198.51.100.1", "h", 80})}
	now := t0

	for i, h := range []time.Duration{24, 48, 96, 192} {
		in.Now = now

		r := step(e, in)
		if len(r.NewBans) != 1 {
			t.Fatalf("ban %d: got %d new bans", i+1, len(r.NewBans))
		}

		b := r.NewBans[0]
		if got := b.Expires.Sub(now); got != h*time.Hour || b.Number != i+1 {
			t.Fatalf("ban %d lasts %v (number %d), want %dh", i+1, got, b.Number, h)
		}

		in.Now = b.Expires.Add(-time.Minute)
		if again := step(e, in); len(again.NewBans) != 0 {
			t.Fatalf("ban %d: banned again while in force", i+1)
		}

		now = b.Expires.Add(time.Minute)
	}

	// Bans older than the repeat window no longer count.
	e = New(testConfig())
	in.Now = t0
	step(e, in)
	in.Now = t0.Add(31 * 24 * time.Hour)

	if r := step(e, in); r.NewBans[0].Number != 1 || r.NewBans[0].Expires.Sub(in.Now) != 24*time.Hour {
		t.Fatalf("after the repeat window: %+v", r.NewBans[0])
	}
}

func TestBanLengthCapsAtMaximum(t *testing.T) {
	t.Parallel()

	e := New(testConfig())

	// Six earlier bans within the window: 24h * 2^6 = 64 days, capped at 21.
	var earlier []Ban

	for i := range 6 {
		at := t0.Add(-time.Duration(6-i) * 24 * time.Hour)
		earlier = append(earlier, Ban{Unit: netip.MustParsePrefix("198.51.100.1/32"), Issued: at, Expires: at.Add(time.Hour)})
	}

	e.Restore(earlier, nil, nil)

	r := step(e, Inputs{Now: t0, Rows: invalid(Row{"198.51.100.1", "h", 80})})
	if got := r.NewBans[0].Expires.Sub(t0); got != 21*24*time.Hour || r.NewBans[0].Number != 7 {
		t.Fatalf("seventh ban lasts %v, number %d", got, r.NewBans[0].Number)
	}
}

func TestHourAndFeederCapsDeferTheLowestScores(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxNewPerHour = 3
	cfg.Caps.MaxNewPerFeederPerHour = 2
	e := New(cfg)

	in := Inputs{Now: t0, Rows: invalid(
		Row{"198.51.100.1", "noisy", 500},
		Row{"198.51.100.2", "noisy", 400},
		Row{"198.51.100.3", "noisy", 300}, // the noisy feeder's third: feeder cap
		Row{"198.51.100.4", "quiet", 200},
		Row{"198.51.100.5", "quiet", 100}, // fourth overall: hour cap
	)}

	r := step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32", "198.51.100.2/32", "198.51.100.4/32"}) {
		t.Fatalf("entries = %v", got)
	}

	if got := strs(r.Deferred[DeferFeederCap]); !slices.Equal(got, []string{"198.51.100.3/32"}) {
		t.Errorf("feeder-capped = %v", got)
	}

	if got := strs(r.Deferred[DeferHourCap]); !slices.Equal(got, []string{"198.51.100.5/32"}) {
		t.Errorf("hour-capped = %v", got)
	}

	// The window is (now - 1h, now]: at exactly one hour the old bans are out.
	in.Now = t0.Add(time.Hour)

	r = step(e, in)
	if got := banned(r); !slices.Equal(got, []string{"198.51.100.3/32", "198.51.100.5/32"}) {
		t.Fatalf("an hour later, new bans = %v", got)
	}
}

func TestFeederCapChargesOnlyTheTopFeeder(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxNewPerFeederPerHour = 1
	e := New(cfg)

	r := step(e, Inputs{Now: t0, Rows: invalid(
		Row{"198.51.100.1", "noisy", 40}, Row{"198.51.100.1", "quiet", 20}, // charged to noisy
		Row{"198.51.100.2", "quiet", 60},
		Row{"198.51.100.3", "noisy", 55},
	)})

	if got := banned(r); !slices.Equal(got, []string{"198.51.100.1/32", "198.51.100.2/32"}) {
		t.Fatalf("new bans = %v", got)
	}

	if got := strs(r.Deferred[DeferFeederCap]); !slices.Equal(got, []string{"198.51.100.3/32"}) {
		t.Errorf("feeder-capped = %v", got)
	}
}

func TestGenerationCapHoldsBackNewBans(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxAddedPerGeneration = 1
	e := New(cfg)

	r := step(e, Inputs{Now: t0, Rows: invalid(Row{"198.51.100.1", "h", 90}, Row{"198.51.100.2", "h", 80})})
	if got := banned(r); !slices.Equal(got, []string{"198.51.100.1/32"}) {
		t.Fatalf("new bans = %v; a ban that waits must not be issued", got)
	}

	if got := strs(r.Deferred[DeferGenerationCap]); !slices.Equal(got, []string{"198.51.100.2/32"}) {
		t.Errorf("deferred = %v", got)
	}
}

func TestRestoredBansCountTowardTheHourCap(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxNewPerHour = 1
	e := New(cfg)
	e.Restore([]Ban{{Unit: netip.MustParsePrefix("192.0.2.1/32"), Issued: t0.Add(-time.Minute), Expires: t0.Add(time.Hour), Points: 60}}, nil, []string{"192.0.2.1/32"})

	r := step(e, Inputs{Now: t0, Rows: invalid(Row{"198.51.100.1", "h", 90})})
	if len(r.NewBans) != 0 || len(r.Deferred[DeferHourCap]) != 1 {
		t.Fatalf("new bans %v, deferred %v", banned(r), r.Deferred)
	}
}

func TestMaxEntriesKeepsTheHighestScores(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxEntries = 2
	e := New(cfg)
	in := Inputs{Now: t0, Rows: invalid(Row{"198.51.100.1", "h", 50}, Row{"198.51.100.2", "h", 51})}
	step(e, in)

	// A much louder source takes the lowest ban's place and is banned; the
	// displaced ban waits, still in force.
	in.Now = t0.Add(time.Minute)
	in.Rows = invalid(Row{"198.51.100.1", "h", 50}, Row{"198.51.100.2", "h", 51}, Row{"198.51.100.3", "h", 100000})

	r := step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.2/32", "198.51.100.3/32"}) {
		t.Fatalf("entries = %v", got)
	}

	if got := banned(r); !slices.Equal(got, []string{"198.51.100.3/32"}) {
		t.Errorf("new bans = %v", got)
	}

	if got := strs(r.Deferred[DeferMaxEntries]); !slices.Equal(got, []string{"198.51.100.1/32"}) {
		t.Errorf("deferred = %v", got)
	}

	// Lifted bans take no place in the list.
	in.Now = t0.Add(2 * time.Minute)
	in.Manual = []manual.Entry{lift("198.51.100.2/32", t0.Add(time.Hour)), lift("198.51.100.3/32", t0.Add(time.Hour))}
	in.Rows = invalid(Row{"198.51.100.4", "h", 60})

	r = step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32", "198.51.100.4/32"}) {
		t.Fatalf("with two bans lifted, entries = %v", got)
	}
}

func TestCoverageCapIssuesOnlyWhatFits(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.IPv6Prefix = 48
	cfg.Caps.MaxIPv6Networks = 2 << 16 // two /48s
	e := New(cfg)

	r := step(e, Inputs{Now: t0, Rows: invalid(
		Row{"2001:db8:1::1", "h", 90}, Row{"2001:db8:2::1", "h", 80}, Row{"2001:db8:3::1", "h", 70},
		Row{"198.51.100.1", "h", 60},
	)})

	if got := banned(r); !slices.Equal(got, []string{"198.51.100.1/32", "2001:db8:1::/48", "2001:db8:2::/48"}) {
		t.Fatalf("new bans = %v", got)
	}

	if got := strs(r.Deferred[DeferCoverage]); !slices.Equal(got, []string{"2001:db8:3::/48"}) {
		t.Errorf("deferred = %v", got)
	}
}

func TestManualBansComeFirstAndAreListedOnce(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxEntries = 2
	e := New(cfg)
	step(e, Inputs{Now: t0, Rows: invalid(Row{"198.51.100.1", "h", 90}, Row{"198.51.100.2", "h", 80})})

	// The same prefix banned by hand is listed once, as manual, and the
	// manual /24 pushes the lower scored ban out.
	r := step(e, Inputs{Now: t0.Add(time.Minute), Manual: []manual.Entry{
		ban("198.51.100.1/32", t0.Add(time.Hour)),
		ban("203.0.113.0/24", t0.Add(time.Hour)),
		ban("192.0.2.0/24", t0.Add(-time.Hour)), // expired
	}})

	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32", "203.0.113.0/24"}) {
		t.Fatalf("entries = %v", got)
	}

	for _, en := range r.Entries {
		if en.Source != SourceManual {
			t.Errorf("%s has source %s, want manual", en.CIDR, en.Source)
		}
	}

	if got := strs(r.Deferred[DeferMaxEntries]); !slices.Equal(got, []string{"198.51.100.2/32"}) {
		t.Errorf("deferred = %v", got)
	}
}

func TestEmptyAndTheGenerationCap(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxAddedPerGeneration = 2
	e := New(cfg)
	in := Inputs{Now: t0, Mode: Empty, Rows: invalid(
		Row{"198.51.100.1", "h", 90}, Row{"198.51.100.2", "h", 80}, Row{"198.51.100.3", "h", 70},
		Row{"198.51.100.4", "h", 60}, Row{"198.51.100.5", "h", 55},
	)}

	r := step(e, in)
	if r.Entries == nil || len(r.Entries) != 0 || len(r.NewBans) != 5 {
		t.Fatalf("empty mode: entries %v (nil %v), new bans %d", r.Entries, r.Entries == nil, len(r.NewBans))
	}

	// Back to enforce: two additions per generation, highest scores first.
	in.Mode = Enforce
	wants := [][]string{
		{"198.51.100.1/32", "198.51.100.2/32"},
		{"198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32", "198.51.100.4/32"},
		{"198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32", "198.51.100.4/32", "198.51.100.5/32"},
	}

	for i, want := range wants {
		in.Now = t0.Add(time.Duration(i+1) * time.Minute)

		r = step(e, in)
		if got := cidrs(r.Entries); !slices.Equal(got, want) {
			t.Fatalf("generation %d: entries = %v, want %v", i+1, got, want)
		}
	}
}

func TestRestoreKeepsTheGenerationCap(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxAddedPerGeneration = 1

	var bans []Ban
	for _, a := range []string{"198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32"} {
		bans = append(bans, Ban{Unit: netip.MustParsePrefix(a), Issued: t0.Add(-2 * time.Hour), Expires: t0.Add(time.Hour), Points: 60})
	}

	// Consumers held .1 when the scorer stopped, mid-ramp.
	e := New(cfg)
	e.Restore(bans, nil, []string{"198.51.100.1/32"})

	r := step(e, Inputs{Now: t0, Manual: []manual.Entry{ban("203.0.113.0/24", t0.Add(time.Hour))}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32", "203.0.113.0/24"}) {
		t.Fatalf("after a restore, entries = %v", got)
	}

	if len(r.Deferred[DeferGenerationCap]) != 2 {
		t.Errorf("deferred = %v", r.Deferred)
	}

	r = step(e, Inputs{Now: t0.Add(2 * time.Hour)})
	if len(r.Entries) != 0 {
		t.Fatalf("expired bans stay listed: %v", cidrs(r.Entries))
	}
}

func TestStepDoesNotChangeTheEngine(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Caps.MaxNewPerHour = 1
	e := New(cfg)
	in := Inputs{Now: t0, Mode: Enforce, Rows: invalid(Row{"198.51.100.1", "h", 90}), Manual: []manual.Entry{ban("203.0.113.0/24", t0.Add(time.Hour))}}

	first := e.Step(in)

	// Without Commit (the caller failed to record it) the same ban and the
	// same manual entry are proposed again, and the hour cap is untouched.
	second := e.Step(in)
	if len(first.NewBans) != 1 || len(second.NewBans) != 1 || len(second.NewManual) != 1 {
		t.Fatalf("an uncommitted step changed the engine: %v, %v", banned(first), banned(second))
	}
}
