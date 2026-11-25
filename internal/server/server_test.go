package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-faster/yaml"

	"github.com/ethpandaops/banoor/api"
	"github.com/ethpandaops/banoor/internal/metrics"
	"github.com/ethpandaops/banoor/internal/publish"
)

type fakeLists struct {
	mu   sync.Mutex
	cur  *publish.Current
	last time.Time
	seen []string
}

func (f *fakeLists) Seen(user, address string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.seen = append(f.seen, user+"@"+address)
}

func (f *fakeLists) Current() *publish.Current {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.cur
}

func (f *fakeLists) LastSuccess() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.last
}

func (f *fakeLists) set(c *publish.Current) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cur, f.last = c, c.GeneratedAt
}

var listed = &publish.Current{
	Payload:     "eyJ2ZXJzaW9uIjoxfQ==",
	Signature:   "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n",
	ETag:        `"0123456789abcdef"`,
	Generation:  1893499200,
	GeneratedAt: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC),
}

func newTestServer(t *testing.T, lists Lists) (*Server, *metrics.Registry) {
	t.Helper()

	reg := metrics.New()

	s, err := New(slog.New(slog.DiscardHandler), Config{Version: "test", FetchUserHeader: "X-Fetch-User", FetchAddressHeader: "X-Real-Ip"}, lists, reg)
	if err != nil {
		t.Fatal(err)
	}

	return s, reg
}

func get(t *testing.T, h http.Handler, path string, header ...string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

// Every operation in the spec is served with the content type the spec
// declares for its success response.
func TestEveryOperationIsServed(t *testing.T) {
	t.Parallel()

	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.Spec, &spec); err != nil {
		t.Fatal(err)
	}

	lists := &fakeLists{}
	lists.set(listed)
	s, _ := newTestServer(t, lists)
	operations := 0

	for path, item := range spec.Paths {
		for method, raw := range item {
			op, ok := raw.(map[string]any)
			if !ok {
				continue
			}

			operations++
			want := successContentType(t, op)

			req := httptest.NewRequestWithContext(t.Context(), strings.ToUpper(method), path, nil)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)

			got, _, _ := mime.ParseMediaType(rec.Header().Get("Content-Type"))
			if rec.Code != http.StatusOK || got != want {
				t.Errorf("%s (%s %s) = %d %q, want 200 %q", op["operationId"], method, path, rec.Code, got, want)
			}
		}
	}

	if operations == 0 {
		t.Fatal("spec has no operations")
	}
}

func successContentType(t *testing.T, op map[string]any) string {
	t.Helper()

	responses, _ := op["responses"].(map[string]any)
	ok, _ := responses["200"].(map[string]any)
	content, _ := ok["content"].(map[string]any)

	if len(content) != 1 {
		t.Fatalf("%s: want exactly one 200 content type, got %d", op["operationId"], len(content))
	}

	for contentType := range content {
		return contentType
	}

	return ""
}

func TestGetList(t *testing.T) {
	t.Parallel()

	lists := &fakeLists{}
	s, reg := newTestServer(t, lists)
	h := s.Handler()

	rec := get(t, h, "/api/v1/list", "X-Fetch-User", "host-a")
	if rec.Code != http.StatusServiceUnavailable || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("before the first list: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}

	lists.set(listed)

	rec = get(t, h, "/api/v1/list", "X-Fetch-User", "host-a")
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != listed.ETag || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("got %d, ETag %q, Cache-Control %q", rec.Code, rec.Header().Get("ETag"), rec.Header().Get("Cache-Control"))
	}

	var env struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}

	if env.Payload != listed.Payload || env.Signature != listed.Signature {
		t.Fatalf("envelope = %+v", env)
	}

	for header, want := range map[string]int{
		listed.ETag:                    http.StatusNotModified,
		`W/` + listed.ETag:             http.StatusNotModified,
		`"other", ` + listed.ETag:      http.StatusNotModified,
		`*`:                            http.StatusNotModified,
		`"other"`:                      http.StatusOK,
		strings.Trim(listed.ETag, `"`): http.StatusOK,
	} {
		res := get(t, h, "/api/v1/list", "If-None-Match", header, "X-Fetch-User", "host-b")
		if res.Code != want {
			t.Errorf("If-None-Match %s: %d, want %d", header, res.Code, want)
		}

		if res.Code == http.StatusNotModified && (res.Header().Get("ETag") != listed.ETag || res.Header().Get("Cache-Control") != "no-cache" || res.Body.Len() != 0) {
			t.Errorf("304 with ETag %q, Cache-Control %q and %d bytes", res.Header().Get("ETag"), res.Header().Get("Cache-Control"), res.Body.Len())
		}
	}

	get(t, h, "/api/v1/list", "X-Fetch-User", "host-c", "X-Real-Ip", "198.51.100.30")
	get(t, h, "/api/v1/list", "X-Real-Ip", "198.51.100.31")
	get(t, h, "/api/v1/list", "X-Fetch-User", "host c", "X-Real-Ip", "198.51.100.32")

	if got := lists.seen; len(got) != 1 || got[0] != "host-c@198.51.100.30" {
		t.Errorf("fetches seen = %v, want only the one with an address and a well-formed user", got)
	}

	var out strings.Builder
	if err := reg.Write(&out); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		`banoor_fetches_total{user="host-a",result="unavailable"} 1`,
		`banoor_fetches_total{user="host-a",result="ok"} 1`,
		`banoor_fetches_total{user="host-b",result="not_modified"} 4`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}

func TestFetchHeadersNeedATrustedProxy(t *testing.T) {
	t.Parallel()

	lists := &fakeLists{}
	lists.set(listed)

	reg := metrics.New()
	cfg := Config{
		FetchUserHeader: "X-Fetch-User", FetchAddressHeader: "X-Real-Ip",
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.8/29"), netip.MustParsePrefix("2001:db8::/64")},
	}

	s, err := New(slog.New(slog.DiscardHandler), cfg, lists, reg)
	if err != nil {
		t.Fatal(err)
	}

	fetch := func(peer, user string, addresses ...string) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/list", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Fetch-User", user)

		for _, a := range addresses {
			req.Header.Add("X-Real-Ip", a)
		}

		s.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}

	fetch("192.0.2.9:4000", "host-a", "198.51.100.1")
	fetch("[2001:db8::5]:4000", "host-b", "198.51.100.2")
	fetch("[::ffff:192.0.2.10]:4000", "host-c", "198.51.100.3")
	// A client reaching the port past the proxy, and one whose own header
	// an appending proxy kept first, are not believed.
	fetch("192.0.2.16:4000", "host-d", "198.51.100.4")
	fetch("192.0.2.9:4000", "host-e", "198.51.100.5", "198.51.100.6")

	want := []string{"host-a@198.51.100.1", "host-b@198.51.100.2", "host-c@198.51.100.3"}
	if got := lists.seen; !slices.Equal(got, want) {
		t.Errorf("fetches seen = %v, want %v", got, want)
	}

	var out strings.Builder
	if err = reg.Write(&out); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), `banoor_fetches_total{user="unknown",result="ok"} 1`) {
		t.Errorf("the untrusted peer's user header counted:\n%s", out.String())
	}
}

func TestFetchUserLabelsAreBounded(t *testing.T) {
	t.Parallel()

	u := newUserLabels(2)
	for i, want := range []string{"a", "b", "other", "a"} {
		if got := u.label([]string{"a", "b", "c", "a"}[i]); got != want {
			t.Errorf("label %d = %q, want %q", i, got, want)
		}
	}

	if u.label("") != "unknown" || u.label("has space") != "invalid" || u.label(strings.Repeat("x", 65)) != "invalid" {
		t.Error("missing or malformed users are not labelled unknown or invalid")
	}
}

func TestHealthAndExtras(t *testing.T) {
	t.Parallel()

	lists := &fakeLists{}
	s, _ := newTestServer(t, lists)
	h := s.Handler()

	rec := get(t, h, "/api/v1/health")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"generation":0`) || strings.Contains(rec.Body.String(), "lastSuccess") {
		t.Fatalf("health before a run: %d %s", rec.Code, rec.Body)
	}

	lists.set(listed)

	rec = get(t, h, "/api/v1/health")
	if want := fmt.Sprintf(`"generation":%d`, listed.Generation); !strings.Contains(rec.Body.String(), want) ||
		!strings.Contains(rec.Body.String(), `"lastSuccess":"2030-01-01T12:00:00Z"`) {
		t.Fatalf("health after a run: %s", rec.Body)
	}

	if r := get(t, h, "/metrics"); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "banoor_fetches_total") {
		t.Errorf("/metrics: %d", r.Code)
	}

	// Concurrent scrapes share nothing (go test -race).
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { get(t, h, "/metrics") })
	}

	wg.Wait()

	if r := get(t, h, "/openapi.yaml"); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "getList") {
		t.Errorf("/openapi.yaml: %d", r.Code)
	}

	if r := get(t, h, "/api/v1/nope"); r.Code != http.StatusNotFound {
		t.Errorf("an unknown route answered %d", r.Code)
	}
}
