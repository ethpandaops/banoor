package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleLoads(t *testing.T) {
	c, err := Load("../../examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	ec := c.Engine()
	if len(ec.Signals) != 3 || !ec.Signals[2].Shadow || ec.Signals[0].Shadow {
		t.Fatalf("signals = %+v", ec.Signals)
	}
	if ec.Caps.MaxEntries != 5000 || ec.BanMax.Hours() != 504 {
		t.Fatalf("engine config = %+v", ec)
	}
}

const base = `{
	"source": {"url": "http://127.0.0.1:8123"},
	"tables": {"decisions": "s.decisions", "publishes": "s.publishes", "control": "s.control"},
	"signing": {"keyFile": "k", "namespace": "n"},
	"signals": [{"name": "a", "query": "SELECT 1", "weight": 1, "mode": "count"}]
}`

func load(t *testing.T, body string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	return err
}

func TestDefaultsApply(t *testing.T) {
	if err := load(t, base); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	tests := map[string]struct{ from, to, want string }{
		"unknown field":   {`"signals"`, `"signal": [], "signals"`, `unknown field "signal"`},
		"bad table":       {`"s.control"`, `"s.control; DROP TABLE x"`, "not a table name"},
		"bad mode":        {`"mode": "count"`, `"mode": "counting"`, "want count or shadow"},
		"bad default":     {`"signals"`, `"defaultMode": "off", "signals"`, "defaultMode"},
		"parser no kinds": {`"mode": "count"`, `"mode": "count", "parser": "openssh"`, "needs kinds"},
		"unknown kind":    {`"mode": "count"`, `"mode": "count", "parser": "openssh", "kinds": ["root_login"]`, `unknown kind "root_login"`},
		"negative weight": {`"weight": 1`, `"weight": -1`, "cannot be negative"},
		"bad duration":    {`"signals"`, `"window": 86400, "signals"`, "durations are strings"},
		"wide ipv6 unit":  {`"signals"`, `"ipv6Prefix": 32, "signals"`, "ipv6Prefix 32"},
		"other source":    {`"url"`, `"type": "postgres", "url"`, "only clickhouse"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(base, tt.from, tt.to, 1)
			if body == base {
				t.Fatal("the replacement did not apply")
			}
			err := load(t, body)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error containing %q", err, tt.want)
			}
		})
	}
}
