// Package config reads banoor's JSON configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/ethpandaops/banoor/internal/engine"
	"github.com/ethpandaops/banoor/internal/netaddr"
	"github.com/ethpandaops/banoor/internal/sshlog"
)

// Duration is a time.Duration written as a string such as "30s" or "24h".
type Duration struct{ time.Duration }

// UnmarshalJSON parses a Go duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("durations are strings such as \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Signal is a query and how much its rows count. The query returns one row
// per source and feeder with the columns address, feeder and attempts. With
// a parser it returns line instead of address, and only lines of the listed
// kinds count.
type Signal struct {
	Name   string   `json:"name"`
	Query  string   `json:"query"`
	Weight float64  `json:"weight"`
	Cap    float64  `json:"cap"`
	Mode   string   `json:"mode"`
	Parser string   `json:"parser"`
	Kinds  []string `json:"kinds"`
}

// AllowQuery allowlists the addresses a query returns in its address column.
// With KeysFile, a row counts only when its key column is listed there.
type AllowQuery struct {
	Name     string   `json:"name"`
	Query    string   `json:"query"`
	Window   Duration `json:"window"`
	Refresh  Duration `json:"refresh"`
	KeysFile string   `json:"keysFile"`
}

// Source is where signals are read and state is kept.
type Source struct {
	Type           string            `json:"type"`
	URL            string            `json:"url"`
	User           string            `json:"user"`
	PasswordFile   string            `json:"passwordFile"`
	Timeout        Duration          `json:"timeout"`
	Settings       map[string]string `json:"settings"`
	InsertSettings map[string]string `json:"insertSettings"`
}

// Config is the whole configuration.
type Config struct {
	Server struct {
		Listen          string `json:"listen"`
		Path            string `json:"path"`
		FetchUserHeader string `json:"fetchUserHeader"`
	} `json:"server"`

	Interval Duration `json:"interval"`
	Refresh  Duration `json:"refresh"`

	Source Source `json:"source"`

	Tables struct {
		Decisions string `json:"decisions"`
		Publishes string `json:"publishes"`
		Control   string `json:"control"`
	} `json:"tables"`

	Signing struct {
		KeyFile   string `json:"keyFile"`
		Namespace string `json:"namespace"`
	} `json:"signing"`

	DefaultMode string   `json:"defaultMode"`
	Threshold   float64  `json:"threshold"`
	Window      Duration `json:"window"`
	IPv6Prefix  int      `json:"ipv6Prefix"`

	Ban struct {
		Base         Duration `json:"base"`
		Max          Duration `json:"max"`
		RepeatWindow Duration `json:"repeatWindow"`
	} `json:"ban"`

	Signals []Signal `json:"signals"`

	Allow struct {
		Dir     string       `json:"dir"`
		Queries []AllowQuery `json:"queries"`
	} `json:"allow"`

	ManualFile string         `json:"manualFile"`
	Limits     netaddr.Limits `json:"limits"`

	Caps struct {
		MaxEntries             int    `json:"maxEntries"`
		MaxAddedPerGeneration  int    `json:"maxAddedPerGeneration"`
		MaxNewPerHour          int    `json:"maxNewPerHour"`
		MaxNewPerFeederPerHour int    `json:"maxNewPerFeederPerHour"`
		MaxIPv4Addresses       uint64 `json:"maxIPv4Addresses"`
		MaxIPv6Networks        uint64 `json:"maxIPv6Networks"`
	} `json:"caps"`
}

// Default returns the configuration every file starts from.
func Default() Config {
	var c Config
	c.Server.Listen = ":8080"
	c.Server.Path = "/v1"
	c.Interval.Duration = 30 * time.Second
	c.Refresh.Duration = 60 * time.Second
	c.Source.Type = "clickhouse"
	c.Source.Timeout.Duration = 20 * time.Second
	c.DefaultMode = string(engine.Shadow)
	c.Threshold = 50
	c.Window.Duration = 24 * time.Hour
	c.IPv6Prefix = 64
	c.Ban.Base.Duration = 24 * time.Hour
	c.Ban.Max.Duration = 21 * 24 * time.Hour
	c.Ban.RepeatWindow.Duration = 30 * 24 * time.Hour
	c.Limits = netaddr.DefaultLimits
	c.Caps.MaxEntries = 5000
	c.Caps.MaxAddedPerGeneration = 500
	c.Caps.MaxNewPerHour = 200
	c.Caps.MaxNewPerFeederPerHour = 50
	c.Caps.MaxIPv4Addresses = 1 << 20
	c.Caps.MaxIPv6Networks = 1 << 20
	return c
}

// Load reads a configuration file over the defaults and checks it.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

var tableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)

var kinds = map[string]bool{
	string(sshlog.InvalidUser): true, string(sshlog.NotAllowed): true, string(sshlog.PenaltyDrop): true,
	string(sshlog.MaxStartupsDrop): true, string(sshlog.AuthClosed): true,
}

// Validate checks the configuration for mistakes that would otherwise show
// up only at run time.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Server.Path == "" || c.Server.Path[0] != '/' {
		fail("server.path %q must start with /", c.Server.Path)
	}
	if c.Interval.Duration <= 0 || c.Refresh.Duration <= 0 {
		fail("interval and refresh must be positive")
	}
	if c.Source.Type != "clickhouse" {
		fail("source.type %q: only clickhouse is supported", c.Source.Type)
	}
	if c.Source.URL == "" {
		fail("source.url is required")
	}
	for name, t := range map[string]string{"decisions": c.Tables.Decisions, "publishes": c.Tables.Publishes, "control": c.Tables.Control} {
		if !tableName.MatchString(t) {
			fail("tables.%s: %q is not a table name", name, t)
		}
	}
	if c.Signing.KeyFile == "" || c.Signing.Namespace == "" {
		fail("signing.keyFile and signing.namespace are required")
	}
	if _, err := engine.ParseMode(c.DefaultMode); err != nil {
		fail("defaultMode: %v", err)
	}
	if c.Threshold <= 0 {
		fail("threshold must be positive")
	}
	if c.Window.Duration <= 0 {
		fail("window must be positive")
	}
	if c.Limits.IPv4MinPrefix < 0 || c.Limits.IPv4MinPrefix > 32 || c.Limits.IPv6MinPrefix < 0 || c.Limits.IPv6MinPrefix > 128 {
		fail("limits are prefix lengths: 0..32 for IPv4, 0..128 for IPv6")
	}
	if c.IPv6Prefix < c.Limits.IPv6MinPrefix || c.IPv6Prefix > 128 {
		fail("ipv6Prefix %d must be between limits.ipv6MinPrefix (%d) and 128", c.IPv6Prefix, c.Limits.IPv6MinPrefix)
	}
	if c.Ban.Base.Duration <= 0 || c.Ban.Max.Duration < c.Ban.Base.Duration {
		fail("ban.base must be positive and no longer than ban.max")
	}
	if c.Caps.MaxEntries <= 0 || c.Caps.MaxAddedPerGeneration <= 0 || c.Caps.MaxNewPerHour <= 0 || c.Caps.MaxNewPerFeederPerHour <= 0 {
		fail("caps must be positive")
	}
	if len(c.Signals) == 0 {
		fail("no signals")
	}
	seen := map[string]bool{}
	for i, s := range c.Signals {
		if s.Name == "" || s.Query == "" {
			fail("signals[%d] needs a name and a query", i)
			continue
		}
		if seen[s.Name] {
			fail("signal %q is listed twice", s.Name)
		}
		seen[s.Name] = true
		if s.Mode != "count" && s.Mode != "shadow" {
			fail("signal %q: mode %q, want count or shadow", s.Name, s.Mode)
		}
		if s.Weight < 0 || s.Cap < 0 {
			fail("signal %q: weight and cap cannot be negative", s.Name)
		}
		switch s.Parser {
		case "":
			if len(s.Kinds) > 0 {
				fail("signal %q: kinds need a parser", s.Name)
			}
		case "openssh":
			if len(s.Kinds) == 0 {
				fail("signal %q: the openssh parser needs kinds", s.Name)
			}
			for _, k := range s.Kinds {
				if !kinds[k] {
					fail("signal %q: unknown kind %q", s.Name, k)
				}
			}
		default:
			fail("signal %q: unknown parser %q", s.Name, s.Parser)
		}
	}
	for i, q := range c.Allow.Queries {
		if q.Name == "" || q.Query == "" || q.Refresh.Duration <= 0 || q.Window.Duration <= 0 {
			fail("allow.queries[%d] needs a name, a query, a window and a refresh", i)
		}
	}
	return errors.Join(errs...)
}

// Engine returns the scoring policy.
func (c *Config) Engine() engine.Config {
	ec := engine.Config{
		Threshold:    c.Threshold,
		Window:       c.Window.Duration,
		IPv6Prefix:   c.IPv6Prefix,
		BanBase:      c.Ban.Base.Duration,
		BanMax:       c.Ban.Max.Duration,
		RepeatWindow: c.Ban.RepeatWindow.Duration,
		Caps: engine.Caps{
			MaxEntries:             c.Caps.MaxEntries,
			MaxAddedPerGeneration:  c.Caps.MaxAddedPerGeneration,
			MaxNewPerHour:          c.Caps.MaxNewPerHour,
			MaxNewPerFeederPerHour: c.Caps.MaxNewPerFeederPerHour,
			MaxIPv4Addresses:       c.Caps.MaxIPv4Addresses,
			MaxIPv6Networks:        c.Caps.MaxIPv6Networks,
		},
	}
	for _, s := range c.Signals {
		ec.Signals = append(ec.Signals, engine.Signal{Name: s.Name, Weight: s.Weight, Cap: s.Cap, Shadow: s.Mode == "shadow"})
	}
	return ec
}
