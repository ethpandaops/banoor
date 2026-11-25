package publish

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/go-faster/yaml"

	"github.com/ethpandaops/banoor/api"
	"github.com/ethpandaops/banoor/pkg/engine"
)

type fakeSigner struct{ n int }

func (f *fakeSigner) Sign(m []byte) string {
	f.n++

	return "sig:" + string(m)
}

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

func decode(t *testing.T, c *Current) (Payload, map[string]any) {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(c.Payload)
	if err != nil {
		t.Fatal(err)
	}

	if c.Signature != "sig:"+string(raw) {
		t.Fatal("the signature does not cover the exact payload bytes")
	}

	var p Payload
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}

	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}

	return p, fields
}

func entry(cidr string) engine.Entry {
	return engine.Entry{CIDR: cidr, Expires: t0.Add(24 * time.Hour).Unix(), Source: engine.SourceScorer, Reason: "r"}
}

func publish(t *testing.T, p *Publisher, now time.Time, mode engine.Mode, entries ...engine.Entry) *Change {
	t.Helper()

	pr, err := p.Prepare(now, mode, entries)
	if err != nil {
		t.Fatal(err)
	}

	if pr == nil {
		return nil
	}

	p.Commit(pr)

	return pr.Change
}

func TestPayloadFormat(t *testing.T) {
	t.Parallel()

	p := New(&fakeSigner{}, time.Minute, 0, nil)
	if p.Current() != nil {
		t.Fatal("a list exists before the first commit")
	}

	publish(t, p, t0, engine.Shadow)

	payload, fields := decode(t, p.Current())
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
}

// The signed payload and its entries carry exactly the fields the spec's
// Payload and Entry document.
func TestPayloadMatchesTheSpec(t *testing.T) {
	t.Parallel()

	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.Spec, &spec); err != nil {
		t.Fatal(err)
	}

	p := New(&fakeSigner{}, time.Minute, 0, nil)
	publish(t, p, t0, engine.Enforce, entry("198.51.100.1/32"))

	_, fields := decode(t, p.Current())
	entries, _ := fields["entries"].([]any)
	first, _ := entries[0].(map[string]any)

	for name, got := range map[string]map[string]any{"Payload": fields, "Entry": first} {
		want := slices.Sorted(maps.Keys(spec.Components.Schemas[name].Properties))
		if keys := slices.Sorted(maps.Keys(got)); len(want) == 0 || !slices.Equal(keys, want) {
			t.Errorf("%s fields = %v, the spec documents %v", name, keys, want)
		}
	}
}

func TestNothingIsServedBeforeCommit(t *testing.T) {
	t.Parallel()

	p := New(&fakeSigner{}, time.Minute, 0, nil)
	publish(t, p, t0, engine.Enforce, entry("198.51.100.1/32"))
	before := p.Current()

	pr, err := p.Prepare(t0.Add(time.Second), engine.Enforce, []engine.Entry{entry("198.51.100.2/32")})
	if err != nil || pr == nil || pr.Change == nil {
		t.Fatalf("prepare = %+v, %v", pr, err)
	}

	if p.Current() != before {
		t.Fatal("a prepared list was served before Commit")
	}

	// An abandoned preparation leaves the sequence where it was.
	again, _ := p.Prepare(t0.Add(time.Second), engine.Enforce, []engine.Entry{entry("198.51.100.2/32")})
	if again.Change.Generation != pr.Change.Generation || again.Change.PreviousGeneration != before.Generation {
		t.Fatalf("change after an abandoned prepare = %+v", again.Change)
	}
}

func TestGenerations(t *testing.T) {
	t.Parallel()

	s := &fakeSigner{}
	// The last generation before a restart was ahead of the clock.
	last := unixSeconds(t0) + 100
	p := New(s, time.Minute, last, []string{"198.51.100.1/32", "198.51.100.9/32"})

	// The first change is counted against the list consumers held, even when
	// its entries are the same.
	c := publish(t, p, t0, engine.Enforce, entry("198.51.100.1/32"))
	if c == nil || c.Generation != last+1 || c.PreviousGeneration != last || c.Added != 0 || c.Removed != 1 || len(c.CIDRs) != 1 {
		t.Fatalf("first change = %+v, want generation %d after %d", c, last+1, last)
	}

	first := p.Current()

	// Nothing changed and the signature is fresh: no new signature.
	if got := publish(t, p, t0.Add(30*time.Second), engine.Enforce, entry("198.51.100.1/32")); got != nil || p.Current() != first || s.n != 1 {
		t.Fatal("an unchanged list was signed again before the refresh interval")
	}

	// The refresh interval passed: same generation, new generated_at.
	if got := publish(t, p, t0.Add(61*time.Second), engine.Enforce, entry("198.51.100.1/32")); got != nil {
		t.Fatal("a refresh cut a generation")
	}

	refreshed, _ := decode(t, p.Current())
	if refreshed.Generation != last+1 || refreshed.GeneratedAt != t0.Add(61*time.Second).Unix() || p.Current().ETag == first.ETag {
		t.Fatalf("refresh = generation %d at %d", refreshed.Generation, refreshed.GeneratedAt)
	}

	// The clock is now past the generation: the next one follows the clock.
	later := t0.Add(time.Hour)

	c = publish(t, p, later, engine.Enforce, entry("198.51.100.1/32"), entry("198.51.100.2/32"))
	if c.Generation != unixSeconds(later) || c.PreviousGeneration != last+1 || c.Added != 1 || c.Removed != 0 {
		t.Fatalf("change = %+v", c)
	}

	if p.Next(later) != c.Generation+1 {
		t.Errorf("Next = %d, want %d", p.Next(later), c.Generation+1)
	}

	// A mode change alone is a new generation.
	if got := publish(t, p, later.Add(time.Second), engine.Shadow, entry("198.51.100.1/32"), entry("198.51.100.2/32")); got == nil || got.Generation != unixSeconds(later)+1 {
		t.Fatalf("mode change = %+v", got)
	}

	// The clock steps back a minute: the list it signed is from the future,
	// so it is signed again at once, in the same generation.
	gen := p.Current().Generation
	if got := publish(t, p, later.Add(-time.Minute), engine.Shadow, entry("198.51.100.1/32"), entry("198.51.100.2/32")); got != nil {
		t.Fatalf("a clock step cut generation %+v", got)
	}

	if back, _ := decode(t, p.Current()); back.Generation != gen || back.GeneratedAt != later.Add(-time.Minute).Unix() {
		t.Fatalf("after the clock stepped back: generation %d at %d", back.Generation, back.GeneratedAt)
	}
}
