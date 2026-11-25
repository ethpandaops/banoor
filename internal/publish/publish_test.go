package publish

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/internal/engine"
)

type fakeSigner struct{ n int }

func (f *fakeSigner) Sign(m []byte) string {
	f.n++
	return "sig:" + string(m)
}

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

func decode(t *testing.T, body []byte) (Payload, map[string]any) {
	t.Helper()
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if env.Signature != "sig:"+string(raw) {
		t.Fatal("the signature does not cover the exact payload bytes")
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	return p, fields
}

func entry(cidr string) engine.Entry {
	return engine.Entry{CIDR: cidr, Expires: t0.Add(24 * time.Hour).Unix(), Source: engine.SourceScorer, Reason: "r"}
}

func TestPayloadFormat(t *testing.T) {
	p := New(&fakeSigner{}, time.Minute, 0)
	if p.Current() != nil {
		t.Fatal("a list exists before the first update")
	}
	if _, err := p.Update(t0, engine.Shadow, nil); err != nil {
		t.Fatal(err)
	}
	payload, fields := decode(t, p.Current().Body)
	for _, k := range []string{"version", "generation", "previous_generation", "generated_at", "mode", "entries"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("payload has no %q", k)
		}
	}
	if entries, ok := fields["entries"].([]any); !ok || len(entries) != 0 {
		t.Errorf("entries = %#v, want []", fields["entries"])
	}
	if payload.Version != 1 || payload.Mode != engine.Shadow || payload.GeneratedAt != t0.Unix() || payload.PreviousGeneration != 0 {
		t.Errorf("payload = %+v", payload)
	}
	if strings.Contains(string(p.Current().Body), "commit") {
		t.Error("empty optional fields are written")
	}
}

func TestGenerations(t *testing.T) {
	s := &fakeSigner{}
	// The last generation before a restart was ahead of the clock.
	last := uint64(t0.Unix()) + 100
	p := New(s, time.Minute, last)

	c, err := p.Update(t0, engine.Enforce, []engine.Entry{entry("198.51.100.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.Generation != last+1 || c.PreviousGeneration != last || c.Added != 1 {
		t.Fatalf("first change = %+v, want generation %d after %d", c, last+1, last)
	}
	first := p.Current()

	// Nothing changed and the signature is fresh: same list, same ETag.
	if c, _ := p.Update(t0.Add(30*time.Second), engine.Enforce, []engine.Entry{entry("198.51.100.1/32")}); c != nil {
		t.Fatalf("an unchanged list cut generation %d", c.Generation)
	}
	if p.Current() != first || s.n != 1 {
		t.Fatal("an unchanged list was signed again before the refresh interval")
	}

	// Nothing changed but the refresh interval passed: same generation, new
	// generated_at.
	if c, _ := p.Update(t0.Add(61*time.Second), engine.Enforce, []engine.Entry{entry("198.51.100.1/32")}); c != nil {
		t.Fatal("a refresh cut a generation")
	}
	refreshed, _ := decode(t, p.Current().Body)
	if refreshed.Generation != last+1 || refreshed.GeneratedAt != t0.Add(61*time.Second).Unix() {
		t.Fatalf("refresh = generation %d at %d", refreshed.Generation, refreshed.GeneratedAt)
	}
	if p.Current().ETag == first.ETag {
		t.Error("a re-signed list kept its ETag")
	}

	// The clock is now past the generation: the next one follows the clock.
	later := t0.Add(time.Hour)
	c, _ = p.Update(later, engine.Enforce, []engine.Entry{entry("198.51.100.1/32"), entry("198.51.100.2/32")})
	if c.Generation != uint64(later.Unix()) || c.PreviousGeneration != last+1 || c.Added != 1 || c.Removed != 0 {
		t.Fatalf("change = %+v", c)
	}

	// A mode change alone is a new generation.
	c, _ = p.Update(later.Add(time.Second), engine.Shadow, []engine.Entry{entry("198.51.100.1/32"), entry("198.51.100.2/32")})
	if c == nil || c.Generation != uint64(later.Unix())+1 {
		t.Fatalf("mode change = %+v", c)
	}
}
