package scorer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/metrics"
	"github.com/ethpandaops/banoor/internal/publish"
	"github.com/ethpandaops/banoor/pkg/sshsig"
)

// fakeSource answers the configured queries from fixed rows and keeps what
// is inserted. Restore queries are answered from earlier inserts, so a
// restart reads back exactly what the scorer wrote.
type fakeSource struct {
	mu        sync.Mutex
	mode      string
	results   map[string][]map[string]any
	inserted  map[string][][]any
	failWrite map[string]bool
	failQuery map[string]bool
}

func newFakeSource(results map[string][]map[string]any) *fakeSource {
	return &fakeSource{results: results, inserted: map[string][][]any{}, failWrite: map[string]bool{}, failQuery: map[string]bool{}}
}

func (f *fakeSource) Select(_ context.Context, query string, _ map[string]string, row func(map[string]any) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var rows []map[string]any

	switch {
	case f.failQuery[query]:
		return errors.New("query refused")
	case strings.Contains(query, "FROM state.control"):
		if f.mode != "" {
			rows = []map[string]any{{"mode": f.mode}}
		}
	case strings.Contains(query, "FROM state.publishes"):
		if n := len(f.inserted["state.publishes"]); n > 0 {
			last := f.inserted["state.publishes"][n-1]
			rows = []map[string]any{{"generation": last[1], "cidrs": last[9]}}
		}
	case strings.Contains(query, "FROM state.fetchers"):
		latest := map[[2]any]time.Time{}

		for _, r := range f.inserted["state.fetchers"] {
			k := [2]any{r[1], r[2]}
			if t := asTime(r[0]); t.After(latest[k]) {
				latest[k] = t
			}
		}

		for k, t := range latest {
			rows = append(rows, map[string]any{"user": k[0], "address": k[1], "seen": t.Unix()})
		}
	case strings.Contains(query, "FROM state.decisions"):
		for _, d := range f.inserted["state.decisions"] {
			rows = append(rows, map[string]any{
				"time_ms": asTime(d[0]).UnixMilli(), "action": d[2], "cidr": d[3], "points": d[4],
				"expires": asTime(d[8]).Unix(), "ban_number": d[7], "reason": d[10], "feeders": d[5],
			})
		}
	default:
		r, ok := f.results[query]
		if !ok {
			return errors.New("unexpected query: " + query)
		}

		rows = r
	}

	for _, r := range rows {
		if err := row(r); err != nil {
			return err
		}
	}

	return nil
}

func asTime(v any) time.Time {
	t, _ := v.(time.Time)

	return t
}

func (f *fakeSource) Insert(_ context.Context, table string, _ []string, rows [][]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failWrite[table] {
		return errors.New("insert refused")
	}

	f.inserted[table] = append(f.inserted[table], rows...)

	return nil
}

func (f *fakeSource) count(table string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.inserted[table])
}

// decisions returns the recorded decisions as "action cidr", without the
// suppression reports.
func (f *fakeSource) decisions(withSuppressed bool) []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []string

	for _, d := range f.inserted["state.decisions"] {
		if d[2] == actionSuppressed && !withSuppressed {
			continue
		}

		out = append(out, fmt.Sprintf("%s %s", d[2], d[3]))
	}

	slices.Sort(out)

	return out
}

const testConfig = `{
	"fetchUserHeader": "X-User",
	"source": {"dsn": "clickhouse://test@127.0.0.1:9000"},
	"tables": {"decisions": "state.decisions", "publishes": "state.publishes", "control": "state.control", "fetchers": "state.fetchers"},
	"signing": {"keyFile": "unused", "namespace": "example-list"},
	"signals": [
		{"name": "invalid_user", "query": "SELECT counted", "weight": 1, "mode": "count"},
		{"name": "drops", "query": "SELECT drops", "weight": 1, "mode": "shadow"},
		{"name": "raw", "query": "SELECT lines", "weight": 1, "mode": "count", "parser": "openssh", "kinds": ["invalid_user"]}
	],
	"allow": {
		"dir": "ALLOWDIR",
		"queries": [{"name": "logins", "query": "SELECT logins", "window": "720h", "refresh": "1h", "keysFile": "KEYS"}],
		"fetchers": {"addressHeader": "X-Real-Ip", "users": "^host-", "window": "720h"}
	},
	"manualFile": "MANUAL"
}`

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

// t0Unix is t0 in Unix seconds, the first generation a test publishes.
const t0Unix = 1893499200

type harness struct {
	t        *testing.T
	src      *fakeSource
	sc       *Scorer
	reg      *metrics.Registry
	clock    time.Time
	key      ed25519.PrivateKey
	manual   string
	keys     string
	allowDir string
}

func newHarness(t *testing.T, src *fakeSource, key ed25519.PrivateKey, manualFile string) *harness {
	t.Helper()

	dir := t.TempDir()

	keys := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(keys, []byte("# pinned keys\nSHA256:listed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	allowDir := filepath.Join(dir, "allowlist")
	if err := os.Mkdir(allowDir, 0o700); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReplacer("KEYS", keys, "MANUAL", manualFile, "ALLOWDIR", allowDir).Replace(testConfig)

	cfgFile := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{t: t, src: src, clock: t0, key: key, reg: metrics.New(), manual: manualFile, keys: keys, allowDir: allowDir}
	h.sc = New(slog.New(slog.DiscardHandler), cfg, src, sshsig.New(key, "example-list"), h.reg, func() time.Time { return h.clock })

	return h
}

func (h *harness) run() error { return h.sc.RunOnce(h.t.Context()) }

func (h *harness) writeManual(body string) {
	h.t.Helper()

	if err := os.WriteFile(h.manual, []byte(body), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) payload() publish.Payload {
	h.t.Helper()

	c := h.sc.Current()
	if c == nil {
		h.t.Fatal("nothing is served")
	}

	raw, err := base64.StdEncoding.DecodeString(c.Payload)
	if err != nil {
		h.t.Fatal(err)
	}

	if want := sshsig.New(h.key, "example-list").Sign(raw); c.Signature != want {
		h.t.Fatal("the signature is not over the payload bytes")
	}

	var p publish.Payload
	if err = json.Unmarshal(raw, &p); err != nil {
		h.t.Fatal(err)
	}

	return p
}

func cidrs(p publish.Payload) []string {
	out := []string{}
	for _, e := range p.Entries {
		out = append(out, e.CIDR)
	}

	return out
}

func row(addr, feeder string, attempts uint64) map[string]any {
	return map[string]any{"address": addr, "feeder": feeder, "attempts": attempts}
}

func testSource() *fakeSource {
	return newFakeSource(map[string][]map[string]any{
		"SELECT counted": {
			row("198.51.100.1", "host-a", 60),
			row("198.51.100.2", "host-a", 10),
			row("198.51.100.3", "host-b", 70),
			row("198.51.100.4", "host-b", 70),
			row("198.51.100.20", "host-b", 70),
		},
		"SELECT drops": {row("198.51.100.5", "host-a", 5000)},
		"SELECT lines": {{"line": "Invalid user x from 192.0.2.7 port 1 from 203.0.113.9 port 2", "feeder": "host-c", "attempts": float64(55)}},
		"SELECT logins": {
			{"address": "198.51.100.3", "key": "SHA256:listed"},
			{"address": "198.51.100.4", "key": "SHA256:unknown"},
			// A login comes from one address; a row naming a range allows
			// nothing.
			{"address": "198.51.100.0/24", "key": "SHA256:listed"},
		},
	})
}

const manualList = `{"entries": [
	{"action": "ban", "cidr": "192.0.2.0/24", "expires": "2030-01-08T00:00:00Z", "reason": "scanner range", "by": "alice"},
	{"action": "lift", "cidr": "198.51.100.20/32", "expires": "2030-01-08T00:00:00Z", "reason": "customer"}
]}`

func TestScorerEndToEnd(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := testSource()
	h := newHarness(t, src, key, filepath.Join(t.TempDir(), "manual.json"))
	h.writeManual(manualList)

	if h.sc.Current() != nil {
		t.Fatal("a list exists before the first run")
	}

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	p := h.payload()

	// .3 logged in with a listed key and .20 is lifted; .4's key is not
	// listed. The framed decoy 192.0.2.7 never scores; the manual /24 is
	// published as is.
	if got, want := cidrs(p), []string{"192.0.2.0/24", "198.51.100.1/32", "198.51.100.4/32", "203.0.113.9/32"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}

	if p.Mode != "shadow" || p.Generation != t0Unix || p.PreviousGeneration != 0 || p.GeneratedAt != t0.Unix() {
		t.Fatalf("payload = %+v", p)
	}

	// Three bans, two manual entries and two suppressions recorded, one
	// generation.
	want := []string{
		"ban 198.51.100.1/32", "ban 198.51.100.4/32", "ban 203.0.113.9/32",
		"manual_ban 192.0.2.0/24", "manual_lift 198.51.100.20/32",
		"suppressed 198.51.100.20/32", "suppressed 198.51.100.3/32",
	}
	if got := src.decisions(true); !slices.Equal(got, want) || src.count("state.publishes") != 1 {
		t.Fatalf("recorded %v and %d publishes, want %v", got, src.count("state.publishes"), want)
	}

	first := h.sc.Current()

	// Unchanged 30 s later: no new generation and no new signature.
	h.clock = t0.Add(30 * time.Second)
	if err := h.run(); err != nil || h.sc.Current() != first {
		t.Fatalf("an unchanged list was re-signed before the refresh interval (%v)", err)
	}

	// The kill switch empties the list at once.
	src.mode = "empty"
	h.clock = t0.Add(40 * time.Second)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	empty := h.payload()
	if len(empty.Entries) != 0 || empty.Mode != "empty" || empty.PreviousGeneration != p.Generation || empty.Generation <= p.Generation {
		t.Fatalf("after the kill switch: %+v", empty)
	}

	if !strings.Contains(metricsText(t, h.reg), `banoor_mode{mode="empty"} 1`) {
		t.Error("banoor_mode does not show the kill switch")
	}
}

func TestFailedWrites(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := testSource()
	h := newHarness(t, src, key, filepath.Join(t.TempDir(), "manual.json"))
	h.writeManual(`{"entries": []}`)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	before := h.payload()

	// A new ban and a lift arrive, but no decision can be recorded: the list
	// is published with the lift and without the ban.
	src.results["SELECT counted"] = append(src.results["SELECT counted"], row("198.51.100.9", "host-a", 99))
	src.failWrite["state.decisions"] = true
	h.writeManual(`{"entries": [{"action": "lift", "cidr": "198.51.100.1/32", "expires": "2030-01-08T00:00:00Z", "reason": "customer"}]}`)
	h.clock = t0.Add(2 * time.Minute)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	got := cidrs(h.payload())
	if slices.Contains(got, "198.51.100.9/32") || slices.Contains(got, "198.51.100.1/32") || len(got) != len(cidrs(before))-1 {
		t.Fatalf("with decisions unrecordable: entries = %v, was %v", got, cidrs(before))
	}

	served := h.sc.Current()

	// The ban is recorded but the new generation cannot be: nothing new is
	// served.
	src.failWrite["state.decisions"] = false
	src.failWrite["state.publishes"] = true
	h.clock = t0.Add(3 * time.Minute)

	if err := h.run(); err == nil || h.sc.Current() != served {
		t.Fatalf("a generation that could not be recorded was served (%v)", err)
	}

	src.failWrite["state.publishes"] = false
	h.clock = t0.Add(4 * time.Minute)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got = cidrs(h.payload()); !slices.Contains(got, "198.51.100.9/32") {
		t.Fatalf("after recovering: %v", got)
	}

	// Four bans at the start, then .9 and the lift once: recorded when the
	// generation could not be, and not again.
	if n := len(src.decisions(false)); n != 6 {
		t.Fatalf("decisions = %v, want 6", src.decisions(false))
	}

	if got := metricsText(t, h.reg); !strings.Contains(got, `banoor_run_blocked_total{reason="record"} 1`) {
		t.Errorf("metrics lack one blocked record:\n%s", got)
	}
}

func TestTheKillSwitchNeedsOnlyTheControlTable(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := testSource()
	src.mode = "enforce"
	h := newHarness(t, src, key, filepath.Join(t.TempDir(), "manual.json"))
	h.writeManual(manualList)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	// Every signal, allowlist, key list and the manual list now fail, and so
	// do decision inserts; a new loud source has arrived.
	for _, q := range []string{"SELECT counted", "SELECT drops", "SELECT lines", "SELECT logins"} {
		src.failQuery[q] = true
	}

	src.results["SELECT counted"] = append(src.results["SELECT counted"], row("198.51.100.9", "host-a", 99))
	src.failWrite["state.decisions"] = true
	h.writeManual(`{"entries": [`)

	if err := os.RemoveAll(h.allowDir); err != nil {
		t.Fatal(err)
	}

	src.mode = "empty"
	h.clock = t0.Add(30 * time.Second)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if p := h.payload(); p.Mode != "empty" || len(p.Entries) != 0 {
		t.Fatalf("after the kill switch: %+v", p)
	}

	if got := metricsText(t, h.reg); !strings.Contains(got, `banoor_mode{mode="empty"} 1`) {
		t.Errorf("banoor_mode does not show the kill switch:\n%s", got)
	}

	// Restarted in the middle of it, with no last good input to fall back
	// on, it still publishes the empty list.
	h2 := newHarness(t, src, key, h.manual)
	if err := os.RemoveAll(h2.allowDir); err != nil {
		t.Fatal(err)
	}

	h2.clock = t0.Add(time.Minute)

	if err := h2.run(); err != nil {
		t.Fatal(err)
	}

	if p := h2.payload(); p.Mode != "empty" || len(p.Entries) != 0 {
		t.Fatalf("after a restart in empty mode: %+v", p)
	}
}

func TestAFailingSignalIsLeftOut(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := testSource()
	h := newHarness(t, src, key, filepath.Join(t.TempDir(), "manual.json"))
	h.writeManual(`{"entries": []}`)

	// One signal's query fails and another lacks a column: the run scores
	// without them.
	src.failQuery["SELECT counted"] = true
	src.results["SELECT lines"] = []map[string]any{{"line": "Invalid user x from 203.0.113.9 port 2", "attempts": float64(55)}}

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); len(got) != 0 {
		t.Fatalf("entries = %v, want none", got)
	}

	got := metricsText(t, h.reg)
	for _, want := range []string{`banoor_source_errors_total{query="signal:invalid_user"} 1`, `banoor_source_errors_total{query="signal:raw"} 1`} {
		if !strings.Contains(got, want) {
			t.Errorf("metrics lack %s:\n%s", want, got)
		}
	}

	if strings.Contains(got, "banoor_run_blocked_total{") {
		t.Errorf("a failing signal blocked the run:\n%s", got)
	}
}

func TestBrokenManualListKeepsTheLastGood(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	h := newHarness(t, testSource(), key, filepath.Join(t.TempDir(), "manual.json"))

	// With no good list yet, a broken file stops the run.
	h.writeManual(`{"entries": [`)

	if err := h.run(); err == nil || h.sc.Current() != nil {
		t.Fatalf("a broken first manual list published (%v)", err)
	}

	h.writeManual(manualList)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	want := cidrs(h.payload())

	// A half-written file later keeps the lift and the manual ban.
	h.writeManual(`{"entries": [{"action": "ban", "cidr": "192.0.2.0/24"`)
	h.clock = t0.Add(time.Minute)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); !slices.Equal(got, want) || slices.Contains(got, "198.51.100.20/32") {
		t.Fatalf("after a broken manual list entries = %v, want %v", got, want)
	}
}

func TestBrokenAllowlistKeepsTheLastGood(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	h := newHarness(t, testSource(), key, filepath.Join(t.TempDir(), "manual.json"))
	h.writeManual(`{"entries": []}`)

	// With no good allowlist yet, a missing directory stops the run.
	if err := os.Remove(h.allowDir); err != nil {
		t.Fatal(err)
	}

	if err := h.run(); err == nil || h.sc.Current() != nil {
		t.Fatalf("a missing first allowlist published (%v)", err)
	}

	if err := os.Mkdir(h.allowDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(h.allowDir, "ours.txt"), []byte("198.51.100.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); slices.Contains(got, "198.51.100.4/32") {
		t.Fatalf("entries = %v, want .4 allowed", got)
	}

	// Losing the directory later keeps .4 allowed.
	if err := os.RemoveAll(h.allowDir); err != nil {
		t.Fatal(err)
	}

	h.clock = t0.Add(time.Minute)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); slices.Contains(got, "198.51.100.4/32") {
		t.Fatalf("after losing the allowlist entries = %v, want .4 still allowed", got)
	}

	// A key list that goes missing, or is emptied, keeps the last good one:
	// .3's login still allows it.
	for i, broken := range []func() error{
		func() error { return os.Remove(h.keys) },
		func() error { return os.WriteFile(h.keys, []byte("# truncated\n"), 0o600) },
	} {
		if err := broken(); err != nil {
			t.Fatal(err)
		}

		h.clock = t0.Add(time.Duration(2+i) * time.Minute)

		if err := h.run(); err != nil {
			t.Fatal(err)
		}

		if got := cidrs(h.payload()); slices.Contains(got, "198.51.100.3/32") {
			t.Fatalf("after breaking the key list (%d) entries = %v, want .3 still allowed", i, got)
		}
	}

	// The key list is reread every run: once its key is gone, .3's login
	// no longer allows it.
	if err := os.WriteFile(h.keys, []byte("SHA256:other\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	h.clock = t0.Add(5 * time.Minute)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); !slices.Contains(got, "198.51.100.3/32") {
		t.Fatalf("after removing its key entries = %v, want .3 banned", got)
	}
}

func TestRestartContinuesFromTheState(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := testSource()
	manualFile := filepath.Join(t.TempDir(), "manual.json")
	h := newHarness(t, src, key, manualFile)
	h.writeManual(manualList)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	before := h.payload()
	decisions := len(src.decisions(false))

	h2 := newHarness(t, src, key, manualFile)
	h2.clock = t0.Add(time.Minute)

	if err := h2.run(); err != nil {
		t.Fatal(err)
	}

	after := h2.payload()
	if !slices.Equal(cidrs(after), cidrs(before)) {
		t.Fatalf("after a restart entries = %v, want %v", cidrs(after), cidrs(before))
	}

	if after.PreviousGeneration != before.Generation || after.Generation <= before.Generation {
		t.Fatalf("after a restart generation %d follows %d, want to follow %d", after.Generation, after.PreviousGeneration, before.Generation)
	}

	if n := len(src.decisions(false)); n != decisions {
		t.Fatalf("a restart recorded bans or manual entries again: %d decisions, want %d", n, decisions)
	}
}

func TestRestoreSkipsBansItCouldNotHaveIssued(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := newFakeSource(map[string][]map[string]any{
		"SELECT counted": nil, "SELECT drops": nil, "SELECT lines": nil, "SELECT logins": nil,
	})
	recorded := func(at time.Time, cidr string, d time.Duration) []any {
		return []any{at, uint64(0), actionBan, cidr, 60.0, []string{"h"}, map[string]float64{}, uint8(1), at.Add(d), "enforce", "r"}
	}
	src.inserted["state.decisions"] = [][]any{
		recorded(t0.Add(-time.Hour), "198.51.100.1/32", 24*time.Hour),
		recorded(t0.Add(-time.Hour), "198.51.0.0/13", 24*time.Hour),
		recorded(t0.Add(-time.Hour), "2001:db8:1::/48", 24*time.Hour),
		recorded(t0.Add(-time.Hour), "198.51.100.2/32", 9000*time.Hour),
		recorded(t0.Add(time.Hour), "198.51.100.3/32", 24*time.Hour),
	}

	h := newHarness(t, src, key, filepath.Join(t.TempDir(), "manual.json"))
	h.writeManual(`{"entries": []}`)

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); !slices.Equal(got, []string{"198.51.100.1/32"}) {
		t.Fatalf("entries = %v, want only the ban a scorer could have issued", got)
	}
}

func metricsText(t *testing.T, reg *metrics.Registry) string {
	t.Helper()

	var b strings.Builder
	if err := reg.Write(&b); err != nil {
		t.Fatal(err)
	}

	return b.String()
}

func TestFetchersAreAllowed(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := testSource()
	manualFile := filepath.Join(t.TempDir(), "manual.json")
	h := newHarness(t, src, key, manualFile)
	h.writeManual(`{"entries": []}`)

	// .4 and .1 would be banned. A matching user fetched from .4; .1 was
	// fetched from by a user the configuration doesn't name, and junk is
	// ignored.
	h.sc.Seen("host-a", "198.51.100.4")
	h.sc.Seen("other", "198.51.100.1")
	h.sc.Seen("host-b", "not an address")

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); slices.Contains(got, "198.51.100.4/32") || !slices.Contains(got, "198.51.100.1/32") {
		t.Fatalf("entries = %v, want .1 banned and .4 allowed", got)
	}

	if n := src.count("state.fetchers"); n != 1 {
		t.Fatalf("stored %d fetchers, want 1", n)
	}

	// Fetching again within the hour stores nothing new.
	h.sc.Seen("host-a", "198.51.100.4")
	h.clock = t0.Add(time.Minute)

	if err := h.run(); err != nil || src.count("state.fetchers") != 1 {
		t.Fatalf("a repeat fetch was stored again (%v, %d rows)", err, src.count("state.fetchers"))
	}

	// A restart remembers the fetcher without a new fetch, but not a stored
	// address of a user the configuration does not name.
	src.inserted["state.fetchers"] = append(src.inserted["state.fetchers"], []any{t0, "other", "198.51.100.1"})
	h2 := newHarness(t, src, key, manualFile)
	h2.clock = t0.Add(2 * time.Minute)

	if err := h2.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h2.payload()); slices.Contains(got, "198.51.100.4/32") || !slices.Contains(got, "198.51.100.1/32") {
		t.Fatalf("after a restart entries = %v, want .4 still allowed and .1 banned", got)
	}

	// Past the window, an address that stopped fetching is no longer allowed.
	h2.clock = t0.Add(31 * 24 * time.Hour)

	if err := h2.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h2.payload()); !slices.Contains(got, "198.51.100.4/32") {
		t.Fatalf("31 days later entries = %v, want .4 banned", got)
	}
}

func TestFetchersKeepTheNewestAddressesPerUser(t *testing.T) {
	t.Parallel()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	h := newHarness(t, testSource(), key, filepath.Join(t.TempDir(), "manual.json"))
	h.writeManual(`{"entries": []}`)

	// .4 first, then sixteen other addresses: .4 is the one dropped. Another
	// user's address is unaffected.
	h.sc.Seen("host-a", "198.51.100.4")
	h.sc.Seen("host-b", "198.51.100.1")

	for i := range maxAddressesPerUser {
		h.clock = h.clock.Add(time.Second)
		h.sc.Seen("host-a", fmt.Sprintf("203.0.113.%d", i+1))
	}

	if err := h.run(); err != nil {
		t.Fatal(err)
	}

	if got := cidrs(h.payload()); !slices.Contains(got, "198.51.100.4/32") || slices.Contains(got, "198.51.100.1/32") {
		t.Fatalf("entries = %v, want .4 banned and .1 allowed", got)
	}
}
