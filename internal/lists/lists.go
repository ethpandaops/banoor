// Package lists reads the files an operator maintains: allowlists, key
// lists and the manual list of bans and lifts.
package lists

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethpandaops/banoor/internal/netaddr"
)

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		out = append(out, strings.TrimSpace(line))
	}
	return out, sc.Err()
}

// LoadAllowDir reads every *.txt file in dir: one address or prefix per
// line, with # comments.
func LoadAllowDir(dir string) (*netaddr.Set, error) {
	set := netaddr.NewSet()
	if dir == "" {
		return set, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		lines, err := readLines(f)
		if err != nil {
			return nil, err
		}
		for i, l := range lines {
			if l == "" {
				continue
			}
			p, err := netaddr.ParseAllow(l)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", f, i+1, err)
			}
			set.Add(p)
		}
	}
	return set, nil
}

// LoadKeys reads a key list: one key per line, with # comments.
func LoadKeys(path string) (map[string]bool, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, l := range lines {
		if l != "" {
			keys[l] = true
		}
	}
	return keys, nil
}

// Manual actions.
const (
	Ban  = "ban"
	Lift = "lift"
)

// Manual is one entry of the manual list. A ban adds its prefix to the
// published list; a lift keeps its prefix off the list, overriding scored
// bans. Both end at Expires.
type Manual struct {
	Action  string
	Prefix  netip.Prefix
	Expires time.Time
	Reason  string
	By      string
	Commit  string
}

// Key identifies an entry across restarts.
func (m Manual) Key() string {
	return m.Action + " " + m.Prefix.String() + " " + m.Expires.UTC().Format(time.RFC3339)
}

type manualFile struct {
	Entries []struct {
		Action  string `json:"action"`
		CIDR    string `json:"cidr"`
		Expires string `json:"expires"`
		Reason  string `json:"reason"`
		By      string `json:"by"`
		Commit  string `json:"commit"`
	} `json:"entries"`
}

// ParseManual reads a manual list:
//
//	{"entries": [{"action": "ban", "cidr": "192.0.2.0/24",
//	  "expires": "2030-01-01T00:00:00Z", "reason": "...", "by": "...", "commit": "..."}]}
//
// It returns the valid entries and an error for each invalid one, so one bad
// entry never discards the rest.
func ParseManual(data []byte, lim netaddr.Limits) ([]Manual, []error) {
	var f manualFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, []error{fmt.Errorf("manual list: %w", err)}
	}
	var (
		out  []Manual
		errs []error
		seen = map[string]bool{}
	)
	for i, e := range f.Entries {
		fail := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("entry %d (%s %s): %s", i+1, e.Action, e.CIDR, fmt.Sprintf(format, a...)))
		}
		if e.Action != Ban && e.Action != Lift {
			fail("action %q, want ban or lift", e.Action)
			continue
		}
		p, err := netaddr.ParseEntry(e.CIDR, lim)
		if err != nil {
			fail("%v", err)
			continue
		}
		if e.Expires == "" {
			fail("no expiry")
			continue
		}
		exp, err := time.Parse(time.RFC3339, e.Expires)
		if err != nil {
			fail("expires: %v", err)
			continue
		}
		reason := strings.TrimSpace(e.Reason)
		if reason == "" {
			fail("no reason")
			continue
		}
		k := e.Action + " " + p.String()
		if seen[k] {
			fail("listed twice")
			continue
		}
		seen[k] = true
		out = append(out, Manual{Action: e.Action, Prefix: p, Expires: exp, Reason: reason, By: e.By, Commit: e.Commit})
	}
	return out, errs
}

// Validate is the review-time check of a manual list: everything ParseManual
// checks, plus no ban overlapping the allowlist or a lift, and no expiry
// further ahead than maxAhead. Entries that have expired only warn.
func Validate(data []byte, lim netaddr.Limits, allow *netaddr.Set, now time.Time, maxAhead time.Duration) (errs, warnings []error) {
	entries, errs := ParseManual(data, lim)
	lifts := netaddr.NewSet()
	for _, m := range entries {
		if m.Action == Lift {
			lifts.Add(m.Prefix)
		}
	}
	for _, m := range entries {
		switch {
		case !m.Expires.After(now):
			warnings = append(warnings, fmt.Errorf("%s %s expired at %s and can be removed", m.Action, m.Prefix, m.Expires.Format(time.RFC3339)))
		case m.Expires.Sub(now) > maxAhead:
			errs = append(errs, fmt.Errorf("%s %s expires more than %s ahead", m.Action, m.Prefix, maxAhead))
		}
		if m.Action != Ban {
			continue
		}
		if allow.Overlaps(m.Prefix) {
			errs = append(errs, fmt.Errorf("ban %s overlaps the allowlist", m.Prefix))
		}
		if lifts.Overlaps(m.Prefix) {
			errs = append(errs, fmt.Errorf("ban %s overlaps a lift", m.Prefix))
		}
	}
	return errs, warnings
}
