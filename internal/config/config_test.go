package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExampleLoads(t *testing.T) {
	t.Parallel()

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
	"source": {"dsn": "clickhouse://reader@127.0.0.1:9000"},
	"tables": {"decisions": "s.decisions", "publishes": "s.publishes", "control": "s.control"},
	"signing": {"keyFile": "k", "namespace": "n"},
	"signals": [{"name": "a", "query": "SELECT 1", "weight": 1, "mode": "count"}],
	"allow": {"queries": [{"name": "q", "query": "SELECT 2", "window": "720h", "refresh": "1h"}]}
}`

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return Load(path)
}

func TestDefaultsApply(t *testing.T) {
	t.Parallel()

	c, err := load(t, base)
	if err != nil {
		t.Fatal(err)
	}

	ec := c.Engine()
	if c.Interval.Duration != 30*time.Second || c.Refresh.Duration != time.Minute || c.DefaultMode != "shadow" ||
		ec.Threshold != 50 || ec.Window != 24*time.Hour || ec.IPv6Prefix != 64 || ec.BanBase != 24*time.Hour ||
		ec.Caps.MaxEntries != 5000 || ec.Caps.MaxNewPerFeederPerHour != 50 || c.Limits.IPv6MinPrefix != 48 {
		t.Errorf("defaults = %+v, engine %+v", c, ec)
	}
}

func TestValidateRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ from, to, want string }{
		"unknown field":           {`"signals"`, `"signal": [], "signals"`, `unknown field "signal"`},
		"bad table":               {`"s.control"`, `"s.control; DROP TABLE x"`, "not a table name"},
		"bad mode":                {`"mode": "count"`, `"mode": "counting"`, "want count or shadow"},
		"bad default":             {`"signals"`, `"defaultMode": "off", "signals"`, "defaultMode"},
		"parser no kinds":         {`"mode": "count"`, `"mode": "count", "parser": "openssh"`, "needs kinds"},
		"unknown kind":            {`"mode": "count"`, `"mode": "count", "parser": "openssh", "kinds": ["root_login"]`, `unknown kind "root_login"`},
		"negative weight":         {`"weight": 1`, `"weight": -1`, "weight must be positive"},
		"zero weight":             {`"weight": 1`, `"weight": 0`, "weight must be positive"},
		"ban shorter than window": {`"signals"`, `"ban": {"base": "1h"}, "signals"`, "ban.base 1h0m0s must be at least the window"},
		"data after":              {`"1h"}]}`, `"1h"}]}}{`, "data after the configuration"},
		"fetchers no proxies":     {`"allow": {`, `"fetchUserHeader": "X-User", "tables": {"decisions": "s.decisions", "publishes": "s.publishes", "control": "s.control", "fetchers": "s.fetchers"}, "allow": {"fetchers": {"addressHeader": "X-Real-Ip", "users": "^host-", "window": "720h"}, `, `and trustedProxies`},
		"bad proxy":               {`"signals"`, `"trustedProxies": ["192.0.2.1"], "signals"`, `no '/'`},
		"bad duration":            {`"signals"`, `"window": 86400, "signals"`, "durations are strings"},
		"wide ipv6 unit":          {`"signals"`, `"ipv6Prefix": 32, "signals"`, "ipv6Prefix 32"},
		"other source":            {`"dsn"`, `"type": "postgres", "dsn"`, "only clickhouse"},
		"slow refresh":            {`"signals"`, `"refresh": "15m", "signals"`, "refresh plus twice the interval"},
		"slow interval":           {`"signals"`, `"interval": "10m", "signals"`, "refresh plus twice the interval"},
		"stale at the limits":     {`"signals"`, `"interval": "4m59s", "refresh": "5m", "signals"`, "refresh plus twice the interval"},
		"tiny interval":           {`"signals"`, `"interval": "1ns", "signals"`, "at least 1s"},
		"long ban":                {`"signals"`, `"ban": {"max": "9000h"}, "signals"`, "at most 8760h"},
		"long repeat window":      {`"signals"`, `"ban": {"repeatWindow": "9000h"}, "signals"`, "at most 8760h"},
		"reserved allow name":     {`{"name": "q"`, `{"name": "fetchers"`, `name the other allowlists`},
		"fetchers any user":       {`"allow": {`, `"fetchUserHeader": "X-User", "tables": {"decisions": "s.decisions", "publishes": "s.publishes", "control": "s.control", "fetchers": "s.fetchers"}, "allow": {"fetchers": {"addressHeader": "X-Real-Ip", "users": "host|", "window": "720h"}, `, `must not match an empty user`},
		"zero limits":             {`"signals"`, `"limits": {"ipv4MinPrefix": 0, "ipv6MinPrefix": 48}, "signals"`, "limits are prefix lengths"},
		"fetchers no table":       {`"allow": {`, `"fetchUserHeader": "X-User", "allow": {"fetchers": {"addressHeader": "X-Real-Ip", "users": "^host-", "window": "720h"}, `, `tables.fetchers`},
		"fetchers bad users":      {`"allow": {`, `"fetchUserHeader": "X-User", "allow": {"fetchers": {"addressHeader": "X-Real-Ip", "users": "(", "window": "720h"}, `, `allow.fetchers.users`},
		"fetchers no user header": {`"allow": {`, `"allow": {"fetchers": {"addressHeader": "X-Real-Ip", "users": "", "window": "720h"}, `, `fetchUserHeader`},
		"twice-named allow":       {`{"name": "q"`, `{"name": "q", "query": "SELECT 3", "window": "1h", "refresh": "1h"}, {"name": "q"`, `allow query "q" is listed twice`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := strings.Replace(base, tt.from, tt.to, 1)
			if body == base {
				t.Fatal("the replacement did not apply")
			}

			_, err := load(t, body)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error containing %q", err, tt.want)
			}
		})
	}
}
