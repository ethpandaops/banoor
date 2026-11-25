// Package config reads banoor's JSON configuration: the source, the state
// tables, the signing key, the scoring policy, the signals and the lists.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"time"

	"github.com/ethpandaops/banoor/pkg/engine"
	"github.com/ethpandaops/banoor/pkg/netaddr"
	"github.com/ethpandaops/banoor/pkg/sshlog"
)

// maxPeriod bounds how old a served list can get: it is signed at the start
// of a run and served at its end, and re-signed by the first run after
// refresh, so it reaches refresh plus two intervals. Consumers typically
// accept ten minutes.
const maxPeriod = 5 * time.Minute

// minInterval keeps a run's timeout (one interval) long enough to finish.
const minInterval = time.Second

// maxBan keeps ban expiries far inside the range state stores hold.
const maxBan = 365 * 24 * time.Hour

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
		return fmt.Errorf("duration: %w", err)
	}

	d.Duration = v

	return nil
}

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

// Fetchers allowlists the addresses consumers fetch the list from: every
// fetch through a trusted proxy whose user (fetchUserHeader) matches Users
// records the address in AddressHeader, which that proxy must set and
// clients must not be able to. Addresses seen within Window are allowed.
type Fetchers struct {
	AddressHeader string   `json:"addressHeader"`
	Users         string   `json:"users"`
	Window        Duration `json:"window"`
}

// Source is where signals are read and state is kept.
type Source struct {
	Type           string            `json:"type"`
	DSN            string            `json:"dsn"`
	PasswordFile   string            `json:"passwordFile"`
	Timeout        Duration          `json:"timeout"`
	Settings       map[string]string `json:"settings"`
	InsertSettings map[string]string `json:"insertSettings"`
}

// Tables are the state tables.
type Tables struct {
	Decisions string `json:"decisions"`
	Publishes string `json:"publishes"`
	Control   string `json:"control"`
	// Fetchers keeps the fetch addresses across restarts; required with
	// allow.fetchers.
	Fetchers string `json:"fetchers"`
}

// Signing is the key lists are signed with.
type Signing struct {
	KeyFile   string `json:"keyFile"`
	Namespace string `json:"namespace"`
}

// Ban is how long bans last.
type Ban struct {
	Base         Duration `json:"base"`
	Max          Duration `json:"max"`
	RepeatWindow Duration `json:"repeatWindow"`
}

// Allow is the allowlist.
type Allow struct {
	Dir      string       `json:"dir"`
	Queries  []AllowQuery `json:"queries"`
	Fetchers *Fetchers    `json:"fetchers"`
}

// Config is the whole configuration.
type Config struct {
	FetchUserHeader string `json:"fetchUserHeader"`
	// TrustedProxies are the peers whose fetchUserHeader and
	// allow.fetchers.addressHeader are believed; without any, every peer's
	// are, which allow.fetchers refuses.
	TrustedProxies []netip.Prefix `json:"trustedProxies"`
	Interval       Duration       `json:"interval"`
	Refresh        Duration       `json:"refresh"`
	Source         Source         `json:"source"`
	Tables         Tables         `json:"tables"`
	Signing        Signing        `json:"signing"`
	DefaultMode    string         `json:"defaultMode"`
	Threshold      float64        `json:"threshold"`
	Window         Duration       `json:"window"`
	IPv6Prefix     int            `json:"ipv6Prefix"`
	Ban            Ban            `json:"ban"`
	Signals        []Signal       `json:"signals"`
	Allow          Allow          `json:"allow"`
	ManualFile     string         `json:"manualFile"`
	Limits         netaddr.Limits `json:"limits"`
	Caps           engine.Caps    `json:"caps"`
}

// Default returns the configuration every file starts from.
func Default() Config {
	return Config{
		Interval:    Duration{30 * time.Second},
		Refresh:     Duration{60 * time.Second},
		Source:      Source{Type: "clickhouse", Timeout: Duration{20 * time.Second}},
		DefaultMode: string(engine.Shadow),
		Threshold:   50,
		Window:      Duration{24 * time.Hour},
		IPv6Prefix:  64,
		Ban: Ban{
			Base:         Duration{24 * time.Hour},
			Max:          Duration{21 * 24 * time.Hour},
			RepeatWindow: Duration{30 * 24 * time.Hour},
		},
		Limits: netaddr.DefaultLimits,
		Caps: engine.Caps{
			MaxEntries:             5000,
			MaxAddedPerGeneration:  500,
			MaxNewPerHour:          200,
			MaxNewPerFeederPerHour: 50,
			MaxIPv4Addresses:       1 << 20,
			MaxIPv6Networks:        1 << 20,
		},
	}
}

// Load reads a configuration file over the defaults and checks it.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	c := Default()

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	if err = dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if err = dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: data after the configuration", path)
	}

	if err = c.Validate(); err != nil {
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
	return errors.Join(
		c.validateRuntime(),
		c.validatePolicy(),
		c.validateSignals(),
		c.validateAllow(),
	)
}

func (c *Config) validateRuntime() error {
	var errs []error

	if i, r := c.Interval.Duration, c.Refresh.Duration; i < minInterval || r < minInterval || r+2*i > maxPeriod {
		errs = append(errs, fmt.Errorf("interval and refresh must be at least %s, and refresh plus twice the interval at most %s", minInterval, maxPeriod))
	}

	if c.Source.Type != "clickhouse" {
		errs = append(errs, fmt.Errorf("source.type %q: only clickhouse is supported", c.Source.Type))
	}

	if c.Source.DSN == "" {
		errs = append(errs, errors.New("source.dsn is required"))
	}

	for name, t := range map[string]string{"decisions": c.Tables.Decisions, "publishes": c.Tables.Publishes, "control": c.Tables.Control} {
		if !tableName.MatchString(t) {
			errs = append(errs, fmt.Errorf("tables.%s: %q is not a table name", name, t))
		}
	}

	if c.Signing.KeyFile == "" || c.Signing.Namespace == "" {
		errs = append(errs, errors.New("signing.keyFile and signing.namespace are required"))
	}

	return errors.Join(errs...)
}

func (c *Config) validatePolicy() error {
	var errs []error

	if _, err := engine.ParseMode(c.DefaultMode); err != nil {
		errs = append(errs, fmt.Errorf("defaultMode: %w", err))
	}

	if c.Threshold <= 0 || c.Window.Duration <= 0 {
		errs = append(errs, errors.New("threshold and window must be positive"))
	}

	if c.Limits.IPv4MinPrefix < 1 || c.Limits.IPv4MinPrefix > 32 || c.Limits.IPv6MinPrefix < 1 || c.Limits.IPv6MinPrefix > 128 {
		errs = append(errs, errors.New("limits are prefix lengths: 1..32 for IPv4, 1..128 for IPv6"))
	}

	if c.IPv6Prefix < c.Limits.IPv6MinPrefix || c.IPv6Prefix > 128 {
		errs = append(errs, fmt.Errorf("ipv6Prefix %d must be between limits.ipv6MinPrefix (%d) and 128", c.IPv6Prefix, c.Limits.IPv6MinPrefix))
	}

	if b := c.Ban; b.Base.Duration <= 0 || b.Max.Duration < b.Base.Duration || b.Max.Duration > maxBan ||
		b.RepeatWindow.Duration <= 0 || b.RepeatWindow.Duration > maxBan {
		errs = append(errs, fmt.Errorf("ban: base must be positive and no longer than max; max and repeatWindow positive and at most %s", maxBan))
	}

	// Signals count over the window, so a ban that ended sooner would be
	// issued again, and escalated, on the evidence of the first.
	if c.Ban.Base.Duration < c.Window.Duration {
		errs = append(errs, fmt.Errorf("ban.base %s must be at least the window, %s", c.Ban.Base.Duration, c.Window.Duration))
	}

	caps := c.Caps
	if caps.MaxEntries <= 0 || caps.MaxAddedPerGeneration <= 0 || caps.MaxNewPerHour <= 0 || caps.MaxNewPerFeederPerHour <= 0 ||
		caps.MaxIPv4Addresses == 0 || caps.MaxIPv6Networks == 0 {
		errs = append(errs, errors.New("caps must be positive"))
	}

	return errors.Join(errs...)
}

func (c *Config) validateSignals() error {
	if len(c.Signals) == 0 {
		return errors.New("no signals")
	}

	var errs []error

	seen := map[string]bool{}

	for i, s := range c.Signals {
		if s.Name == "" || s.Query == "" {
			errs = append(errs, fmt.Errorf("signals[%d] needs a name and a query", i))

			continue
		}

		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("signal %q is listed twice", s.Name))
		}

		seen[s.Name] = true

		if err := validateSignal(s); err != nil {
			errs = append(errs, fmt.Errorf("signal %q: %w", s.Name, err))
		}
	}

	return errors.Join(errs...)
}

func validateSignal(s Signal) error {
	var errs []error

	if s.Mode != "count" && s.Mode != "shadow" {
		errs = append(errs, fmt.Errorf("mode %q, want count or shadow", s.Mode))
	}

	switch {
	case s.Weight == 0:
		errs = append(errs, errors.New("weight 0 gives no points and, in shadow mode, no would-bans: leave the signal out"))
	case s.Weight < 0:
		errs = append(errs, errors.New("weight cannot be negative"))
	}

	if s.Cap < 0 {
		errs = append(errs, errors.New("cap cannot be negative"))
	}

	switch s.Parser {
	case "":
		if len(s.Kinds) > 0 {
			errs = append(errs, errors.New("kinds need a parser"))
		}
	case "openssh":
		if len(s.Kinds) == 0 {
			errs = append(errs, errors.New("the openssh parser needs kinds"))
		}

		for _, k := range s.Kinds {
			if !kinds[k] {
				errs = append(errs, fmt.Errorf("unknown kind %q", k))
			}
		}
	default:
		errs = append(errs, fmt.Errorf("unknown parser %q", s.Parser))
	}

	return errors.Join(errs...)
}

func (c *Config) validateAllow() error {
	var errs []error

	seen := map[string]bool{}

	for i, q := range c.Allow.Queries {
		if q.Name == "" || q.Query == "" || q.Refresh.Duration <= 0 || q.Window.Duration <= 0 {
			errs = append(errs, fmt.Errorf("allow.queries[%d] needs a name, a query, a window and a refresh", i))

			continue
		}

		if seen[q.Name] {
			errs = append(errs, fmt.Errorf("allow query %q is listed twice", q.Name))
		}

		if q.Name == "files" || q.Name == "fetchers" {
			errs = append(errs, fmt.Errorf("allow query %q: files and fetchers name the other allowlists", q.Name))
		}

		seen[q.Name] = true
	}

	if f := c.Allow.Fetchers; f != nil {
		if f.AddressHeader == "" || f.Window.Duration <= 0 || c.FetchUserHeader == "" || len(c.TrustedProxies) == 0 {
			errs = append(errs, errors.New("allow.fetchers needs an addressHeader, a window, fetchUserHeader and trustedProxies"))
		}

		switch re, err := regexp.Compile(f.Users); {
		case err != nil:
			errs = append(errs, fmt.Errorf("allow.fetchers.users: %w", err))
		case re.MatchString(""):
			errs = append(errs, errors.New("allow.fetchers.users must not match an empty user, or anyone who reaches the list unnamed is allowed"))
		}

		if !tableName.MatchString(c.Tables.Fetchers) {
			errs = append(errs, fmt.Errorf("tables.fetchers: %q is not a table name", c.Tables.Fetchers))
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
		Caps:         c.Caps,
	}

	for _, s := range c.Signals {
		ec.Signals = append(ec.Signals, engine.Signal{Name: s.Name, Weight: s.Weight, Cap: s.Cap, Shadow: s.Mode == "shadow"})
	}

	return ec
}
