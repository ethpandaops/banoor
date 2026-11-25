package engine

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/internal/lists"
	"github.com/ethpandaops/banoor/internal/netaddr"
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

func cidrs(es []Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.CIDR)
	}
	return out
}

func prefixes(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return out
}

// step runs one step and commits it, as the service does after recording.
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
	e := New(testConfig())
	r := step(e, Inputs{Now: t0, Rows: map[string][]Row{
		"invalid_user": rows(
			Row{"198.51.100.1", "host-a", 25},
			Row{"198.51.100.2", "host-a", 49},
		),
		"not_allowed": rows(Row{"198.51.100.1", "host-b", 25}),
	}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32"}) {
		t.Fatalf("entries = %v, want only the source at 25+25", got)
	}
	b := r.NewBans[0]
	if !b.Expires.Equal(t0.Add(24*time.Hour)) || b.Number != 1 {
		t.Errorf("first ban = %v, number %d, want 24h, 1", b.Expires.Sub(t0), b.Number)
	}
	if b.Reason != "invalid_user=25 not_allowed=25 in 24h, ban 1" {
		t.Errorf("reason = %q", b.Reason)
	}
	if !slices.Equal(b.Feeders, []string{"host-a", "host-b"}) {
		t.Errorf("feeders = %v", b.Feeders)
	}
}

func TestWeightsCapsAndShadowSignals(t *testing.T) {
	cfg := testConfig()
	cfg.Signals = append(cfg.Signals,
		Signal{Name: "capped", Weight: 1, Cap: 25},
		Signal{Name: "trial", Weight: 1, Shadow: true},
	)
	e := New(cfg)
	r := step(e, Inputs{Now: t0, Rows: map[string][]Row{
		// A weight-0 signal never bans, however loud.
		"drop": rows(Row{"198.51.100.1", "h", 10000}),
		// The cap holds 100 attempts to 25 points: 25 + 24 stays under 50,
		// 25 + 25 reaches it.
		"capped":       rows(Row{"198.51.100.2", "h", 100}, Row{"198.51.100.3", "h", 100}),
		"invalid_user": rows(Row{"198.51.100.2", "h", 24}, Row{"198.51.100.3", "h", 25}, Row{"198.51.100.4", "h", 30}),
		// The shadow signal would put 198.51.100.4 over (30 + 20) but counts nothing.
		"trial": rows(Row{"198.51.100.4", "h", 20}),
	}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.3/32"}) {
		t.Fatalf("entries = %v, want only 198.51.100.3", got)
	}
	if got := prefixes(r.WouldBan["trial"]); !slices.Equal(got, []string{"198.51.100.4/32"}) {
		t.Errorf("would-ban for trial = %v", got)
	}
}

func TestIPv6IsScoredPerNetwork(t *testing.T) {
	e := New(testConfig())
	r := step(e, Inputs{Now: t0, Rows: map[string][]Row{"invalid_user": rows(
		Row{"2001:db8:1:2::a", "h", 30},
		Row{"2001:db8:1:2:ffff::b", "h", 20},
		Row{"2001:db8:1:3::a", "h", 49},
		Row{"not an address", "h", 99},
	)}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"2001:db8:1:2::/64"}) {
		t.Fatalf("entries = %v", got)
	}
	if r.Invalid != 1 {
		t.Errorf("invalid = %d, want 1", r.Invalid)
	}
}

func TestAllowlistAndLiftsWin(t *testing.T) {
	e := New(testConfig())
	allow := netaddr.NewSet(netip.MustParsePrefix("2001:db8:1:2::7/128"), netip.MustParsePrefix("198.51.100.0/28"))
	in := Inputs{Now: t0, Allow: allow, Rows: map[string][]Row{"invalid_user": rows(
		Row{"2001:db8:1:2::a", "h", 60}, // its /64 holds an allowed address
		Row{"198.51.100.5", "h", 60},    // inside an allowed range
		Row{"198.51.100.20", "h", 60},
		Row{"198.51.100.21", "h", 60},
	)}}
	r := step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.20/32", "198.51.100.21/32"}) {
		t.Fatalf("entries = %v", got)
	}
	if got := prefixes(r.Suppressed); !slices.Equal(got, []string{"198.51.100.5/32", "2001:db8:1:2::/64"}) {
		t.Errorf("suppressed = %v", got)
	}

	// A lift takes an existing ban off the list until it expires.
	lift := lists.Manual{Action: lists.Lift, Prefix: netip.MustParsePrefix("198.51.100.20/32"), Expires: t0.Add(2 * time.Hour), Reason: "customer"}
	in.Now, in.Manual = t0.Add(time.Minute), []lists.Manual{lift}
	r = step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.21/32"}) {
		t.Fatalf("with the lift, entries = %v", got)
	}
	if len(r.NewManual) != 1 || r.ActiveManual[lists.Lift] != 1 {
		t.Errorf("new manual = %v, active = %v", r.NewManual, r.ActiveManual)
	}
	in.Now = t0.Add(3 * time.Hour)
	r = step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.20/32", "198.51.100.21/32"}) {
		t.Fatalf("after the lift expired, entries = %v", got)
	}
}

func TestRepeatBansDouble(t *testing.T) {
	e := New(testConfig())
	in := Inputs{Rows: map[string][]Row{"invalid_user": rows(Row{"198.51.100.1", "h", 80})}}
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
		// No second ban while one is in force.
		in.Now = b.Expires.Add(-time.Minute)
		if r := step(e, in); len(r.NewBans) != 0 {
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
	e := New(testConfig())
	// Six earlier bans within the window: 24h * 2^6 = 64 days, capped at 21.
	var earlier []Ban
	for i := range 6 {
		at := t0.Add(-time.Duration(6-i) * 24 * time.Hour)
		earlier = append(earlier, Ban{Unit: netip.MustParsePrefix("198.51.100.1/32"), Issued: at, Expires: at.Add(time.Hour)})
	}
	e.Restore(earlier, nil)
	r := step(e, Inputs{Now: t0, Rows: map[string][]Row{"invalid_user": rows(Row{"198.51.100.1", "h", 80})}})
	if got := r.NewBans[0].Expires.Sub(t0); got != 21*24*time.Hour || r.NewBans[0].Number != 7 {
		t.Fatalf("seventh ban lasts %v, number %d", got, r.NewBans[0].Number)
	}
}

func TestCapsDeferTheLowestScores(t *testing.T) {
	cfg := testConfig()
	cfg.Caps.MaxNewPerHour = 3
	cfg.Caps.MaxNewPerFeederPerHour = 2
	e := New(cfg)
	in := Inputs{Now: t0, Rows: map[string][]Row{"invalid_user": rows(
		Row{"198.51.100.1", "noisy", 500},
		Row{"198.51.100.2", "noisy", 400},
		Row{"198.51.100.3", "noisy", 300}, // the noisy feeder's third: feeder cap
		Row{"198.51.100.4", "quiet", 200},
		Row{"198.51.100.5", "quiet", 100}, // fourth overall: hour cap
	)}}
	r := step(e, in)
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32", "198.51.100.2/32", "198.51.100.4/32"}) {
		t.Fatalf("entries = %v", got)
	}
	if got := prefixes(r.Deferred[DeferFeederCap]); !slices.Equal(got, []string{"198.51.100.3/32"}) {
		t.Errorf("feeder-capped = %v", got)
	}
	if got := prefixes(r.Deferred[DeferHourCap]); !slices.Equal(got, []string{"198.51.100.5/32"}) {
		t.Errorf("hour-capped = %v", got)
	}

	in.Now = t0.Add(61 * time.Minute)
	r = step(e, in)
	if got := prefixes(func() []netip.Prefix {
		var ps []netip.Prefix
		for _, b := range r.NewBans {
			ps = append(ps, b.Unit)
		}
		return ps
	}()); !slices.Equal(got, []string{"198.51.100.3/32", "198.51.100.5/32"}) {
		t.Fatalf("an hour later, new bans = %v", got)
	}
}

func TestEmptyAndTheGenerationCap(t *testing.T) {
	cfg := testConfig()
	cfg.Caps.MaxAddedPerGeneration = 2
	e := New(cfg)
	in := Inputs{Now: t0, Mode: Empty, Rows: map[string][]Row{"invalid_user": rows(
		Row{"198.51.100.1", "h", 90}, Row{"198.51.100.2", "h", 80}, Row{"198.51.100.3", "h", 70},
		Row{"198.51.100.4", "h", 60}, Row{"198.51.100.5", "h", 55},
	)}}
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

func TestRestoreSkipsTheGenerationCapOnce(t *testing.T) {
	cfg := testConfig()
	cfg.Caps.MaxAddedPerGeneration = 1
	e := New(cfg)
	var bans []Ban
	for _, a := range []string{"198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32"} {
		bans = append(bans, Ban{Unit: netip.MustParsePrefix(a), Issued: t0.Add(-2 * time.Hour), Expires: t0.Add(time.Hour), Points: 60})
	}
	e.Restore(bans, nil)
	r := step(e, Inputs{Now: t0})
	if len(r.Entries) != 3 {
		t.Fatalf("after a restore, entries = %v, want all three", cidrs(r.Entries))
	}
	r = step(e, Inputs{Now: t0.Add(2 * time.Hour)})
	if len(r.Entries) != 0 {
		t.Fatalf("expired bans stay listed: %v", cidrs(r.Entries))
	}
}

func TestManualBansComeFirst(t *testing.T) {
	cfg := testConfig()
	cfg.Caps.MaxEntries = 2
	e := New(cfg)
	manual := []lists.Manual{
		{Action: lists.Ban, Prefix: netip.MustParsePrefix("203.0.113.0/24"), Expires: t0.Add(time.Hour), Reason: "range"},
		{Action: lists.Ban, Prefix: netip.MustParsePrefix("198.51.100.1/32"), Expires: t0.Add(time.Hour), Reason: "by hand", Commit: "abc1234"},
		{Action: lists.Ban, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Expires: t0.Add(-time.Hour), Reason: "expired"},
	}
	r := step(e, Inputs{Now: t0, Manual: manual, Rows: map[string][]Row{"invalid_user": rows(
		Row{"198.51.100.1", "h", 90}, // also banned by hand: listed once
		Row{"198.51.100.2", "h", 80}, // over MaxEntries
	)}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"198.51.100.1/32", "203.0.113.0/24"}) {
		t.Fatalf("entries = %v", got)
	}
	for _, en := range r.Entries {
		if en.Source != SourceManual {
			t.Errorf("%s has source %s, want manual", en.CIDR, en.Source)
		}
	}
	if r.Entries[0].Commit != "abc1234" {
		t.Errorf("commit = %q", r.Entries[0].Commit)
	}
	if got := prefixes(r.Deferred[DeferMaxEntries]); !slices.Equal(got, []string{"198.51.100.2/32"}) {
		t.Errorf("deferred = %v", got)
	}
}

func TestCoverageCap(t *testing.T) {
	cfg := testConfig()
	cfg.Caps.MaxIPv4Addresses = 300
	e := New(cfg)
	manual := []lists.Manual{
		{Action: lists.Ban, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Expires: t0.Add(time.Hour), Reason: "a"},
		{Action: lists.Ban, Prefix: netip.MustParsePrefix("203.0.113.0/24"), Expires: t0.Add(time.Hour), Reason: "b"},
	}
	r := step(e, Inputs{Now: t0, Manual: manual, Rows: map[string][]Row{"invalid_user": rows(Row{"198.51.100.1", "h", 90})}})
	if got := cidrs(r.Entries); !slices.Equal(got, []string{"192.0.2.0/24", "198.51.100.1/32"}) {
		t.Fatalf("entries = %v", got)
	}
	if got := prefixes(r.Deferred[DeferCoverage]); !slices.Equal(got, []string{"203.0.113.0/24"}) {
		t.Errorf("deferred = %v", got)
	}
}

func TestStepDoesNotChangeTheEngine(t *testing.T) {
	e := New(testConfig())
	in := Inputs{Now: t0, Mode: Enforce, Rows: map[string][]Row{"invalid_user": rows(Row{"198.51.100.1", "h", 90})}}
	if r := e.Step(in); len(r.NewBans) != 1 {
		t.Fatal("expected a new ban")
	}
	// Without Commit (the caller failed to record it) the ban is proposed again.
	if r := e.Step(in); len(r.NewBans) != 1 {
		t.Fatal("an uncommitted step changed the engine")
	}
}
