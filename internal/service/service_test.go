package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/publish"
	"github.com/ethpandaops/banoor/internal/sshsig"
)

// fakeSource answers the configured queries from fixed rows and keeps what
// is inserted. Restore queries are answered from earlier inserts, so a
// restart test reads back exactly what the service wrote.
type fakeSource struct {
	mu        sync.Mutex
	mode      string
	results   map[string][]string // query -> JSON rows
	inserted  map[string][][]byte
	failWrite bool
}

func (f *fakeSource) Select(_ context.Context, query string, _ map[string]string, row func([]byte) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var rows []string
	switch {
	case strings.Contains(query, "FROM state.control"):
		if f.mode != "" {
			rows = []string{`{"mode":"` + f.mode + `"}`}
		}
	case strings.Contains(query, "max(Generation)"):
		var g uint64
		for _, b := range f.inserted["state.publishes"] {
			var r struct{ Generation uint64 }
			_ = json.Unmarshal(b, &r)
			g = max(g, r.Generation)
		}
		rows = []string{`{"generation":` + jsonNum(g) + `}`}
	case strings.Contains(query, "FROM state.decisions"):
		for _, b := range f.inserted["state.decisions"] {
			var d decisionRow
			_ = json.Unmarshal(b, &d)
			at, _ := time.Parse(time.RFC3339, d.Time)
			exp, _ := time.Parse(time.RFC3339, d.Expires)
			out, _ := json.Marshal(map[string]any{
				"time_ms": at.UnixMilli(), "action": d.Action, "cidr": d.Cidr, "points": d.Points,
				"expires": exp.Unix(), "ban_number": d.BanNumber, "reason": d.Reason, "feeders": d.Feeders,
			})
			rows = append(rows, string(out))
		}
	default:
		r, ok := f.results[query]
		if !ok {
			return errors.New("unexpected query: " + query)
		}
		rows = r
	}
	for _, r := range rows {
		if err := row([]byte(r)); err != nil {
			return err
		}
	}
	return nil
}

func jsonNum(v uint64) string { b, _ := json.Marshal(v); return string(b) }

func (f *fakeSource) Insert(_ context.Context, table string, rows [][]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrite {
		return errors.New("insert refused")
	}
	if f.inserted == nil {
		f.inserted = map[string][][]byte{}
	}
	f.inserted[table] = append(f.inserted[table], rows...)
	return nil
}

func (f *fakeSource) count(table string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inserted[table])
}

const testConfig = `{
	"server": {"path": "/v1", "fetchUserHeader": "X-Fetch-User"},
	"source": {"type": "clickhouse", "url": "http://127.0.0.1:8123"},
	"tables": {"decisions": "state.decisions", "publishes": "state.publishes", "control": "state.control"},
	"signing": {"keyFile": "unused", "namespace": "example-list"},
	"signals": [
		{"name": "invalid_user", "query": "SELECT counted", "weight": 1, "mode": "count"},
		{"name": "drops", "query": "SELECT drops", "weight": 0, "mode": "count"},
		{"name": "raw", "query": "SELECT lines", "weight": 1, "mode": "count", "parser": "openssh", "kinds": ["invalid_user"]}
	],
	"allow": {"queries": [{"name": "logins", "query": "SELECT logins", "window": "720h", "refresh": "1h", "keysFile": "KEYS"}]}
}`

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

type harness struct {
	t     *testing.T
	src   *fakeSource
	svc   *Service
	srv   *httptest.Server
	clock time.Time
	key   ed25519.PrivateKey
	cfg   *config.Config
}

func newHarness(t *testing.T, src *fakeSource, key ed25519.PrivateKey) *harness {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(keys, []byte("# pinned keys\nSHA256:listed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(strings.Replace(testConfig, "KEYS", keys, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, src: src, clock: t0, key: key, cfg: cfg}
	h.svc = New(cfg, src, sshsig.New(key, "example-list"), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	h.svc.now = func() time.Time { return h.clock }
	h.srv = httptest.NewServer(h.svc.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) run() error { return h.svc.RunOnce(context.Background()) }

func (h *harness) get(etag string) (*http.Response, []byte) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/v1", nil)
	req.Header.Set("X-Fetch-User", "host-a")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func (h *harness) payload(body []byte) publish.Payload {
	h.t.Helper()
	var env publish.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		h.t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		h.t.Fatal(err)
	}
	if want := sshsig.New(h.key, "example-list").Sign(raw); env.Signature != want {
		h.t.Fatal("the signature is not over the payload bytes")
	}
	var p publish.Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func cidrs(p publish.Payload) []string {
	var out []string
	for _, e := range p.Entries {
		out = append(out, e.CIDR)
	}
	return out
}

func TestServiceEndToEnd(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	src := &fakeSource{results: map[string][]string{
		"SELECT counted": {
			`{"address":"198.51.100.1","feeder":"host-a","attempts":60}`,
			`{"address":"198.51.100.2","feeder":"host-a","attempts":10}`,
			`{"address":"198.51.100.3","feeder":"host-b","attempts":70}`,
			`{"address":"198.51.100.4","feeder":"host-b","attempts":70}`,
		},
		"SELECT drops": {`{"address":"198.51.100.5","feeder":"host-a","attempts":5000}`},
		"SELECT lines": {`{"line":"Invalid user x from 192.0.2.7 port 1 from 203.0.113.9 port 2","feeder":"host-c","attempts":55}`},
		"SELECT logins": {
			`{"address":"198.51.100.3","key":"SHA256:listed"}`,
			`{"address":"198.51.100.4","key":"SHA256:unknown"}`,
		},
	}}
	h := newHarness(t, src, key)

	if resp, _ := h.get(""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("before the first run: %s, want 503", resp.Status)
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	resp, body := h.get("")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("got %s %s", resp.Status, resp.Header.Get("Content-Type"))
	}
	p := h.payload(body)
	// 198.51.100.3 logged in with a listed key; 198.51.100.4's key is not
	// listed. The framed decoy 192.0.2.7 never scores.
	if got, want := cidrs(p), []string{"198.51.100.1/32", "198.51.100.4/32", "203.0.113.9/32"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	if p.Mode != "shadow" || p.Generation != uint64(t0.Unix()) || p.PreviousGeneration != 0 || p.GeneratedAt != t0.Unix() {
		t.Fatalf("payload = %+v", p)
	}
	if src.count("state.decisions") != 3 || src.count("state.publishes") != 1 {
		t.Fatalf("recorded %d decisions and %d publishes", src.count("state.decisions"), src.count("state.publishes"))
	}
	etag := resp.Header.Get("ETag")
	if resp, _ := h.get(etag); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("with a matching ETag: %s, want 304", resp.Status)
	}

	// Unchanged 30 s later: no new generation and no new signature.
	h.clock = t0.Add(30 * time.Second)
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.get(etag); resp.StatusCode != http.StatusNotModified {
		t.Fatal("an unchanged list was re-signed before the refresh interval")
	}

	// The kill switch empties the list at once.
	src.mode = "empty"
	h.clock = t0.Add(40 * time.Second)
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	_, body = h.get("")
	empty := h.payload(body)
	if len(empty.Entries) != 0 || empty.Mode != "empty" || empty.PreviousGeneration != p.Generation || empty.Generation <= p.Generation {
		t.Fatalf("after the kill switch: %+v", empty)
	}

	// A failed write publishes nothing and keeps the ban for the next run.
	src.mode = "enforce"
	src.results["SELECT counted"] = append(src.results["SELECT counted"], `{"address":"198.51.100.9","feeder":"host-a","attempts":99}`)
	src.failWrite = true
	h.clock = t0.Add(2 * time.Minute)
	if err := h.run(); err == nil {
		t.Fatal("a run whose decisions could not be recorded succeeded")
	}
	_, body = h.get("")
	if h.payload(body).Generation != empty.Generation {
		t.Fatal("a failed run changed the list")
	}
	src.failWrite = false
	h.clock = t0.Add(3 * time.Minute)
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if src.count("state.decisions") != 4 {
		t.Fatalf("decisions = %d, want 4", src.count("state.decisions"))
	}
	_, body = h.get("")
	before := h.payload(body)
	if got := cidrs(before); !slices.Contains(got, "198.51.100.9/32") || before.Mode != "enforce" {
		t.Fatalf("after recovering: %v %s", got, before.Mode)
	}

	var metrics strings.Builder
	mresp, err := http.Get(h.srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(&metrics, mresp.Body)
	mresp.Body.Close()
	for _, want := range []string{
		`banoor_mode{mode="enforce"} 1`,
		`banoor_entries{kind="ipv4",source="scorer"} 4`,
		`banoor_fetches_total{user="host-a",result="not_modified"} 2`,
		`banoor_run_blocked_total{reason="record"} 1`,
		`banoor_suppressed_total 1`,
	} {
		if !strings.Contains(metrics.String(), want) {
			t.Errorf("metrics lack %q", want)
		}
	}

	// A restart rebuilds the same list from what was recorded and continues
	// the generations.
	h2 := newHarness(t, src, key)
	h2.clock = t0.Add(4 * time.Minute)
	if err := h2.run(); err != nil {
		t.Fatal(err)
	}
	_, body = h2.get("")
	after := h2.payload(body)
	if !slices.Equal(cidrs(after), cidrs(before)) {
		t.Fatalf("after a restart entries = %v, want %v", cidrs(after), cidrs(before))
	}
	if after.PreviousGeneration != before.Generation || after.Generation <= before.Generation {
		t.Fatalf("after a restart generation %d follows %d, want to follow %d", after.Generation, after.PreviousGeneration, before.Generation)
	}
	if src.count("state.decisions") != 4 {
		t.Fatalf("a restart recorded the restored bans again: %d decisions", src.count("state.decisions"))
	}
}
