// Package manual parses the lists an operator maintains: allowlists, key
// lists and the manual list of bans and lifts. It reads bytes; callers read
// the files.
package manual

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/ethpandaops/banoor/pkg/netaddr"
)

// Actions.
const (
	Ban  = "ban"
	Lift = "lift"
)

// latestExpiry keeps expiries inside the range state stores hold as a
// 32-bit Unix time.
var latestExpiry = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

// lines returns the lines of data with # comments removed and space trimmed.
func lines(data []byte) ([]string, error) {
	var out []string

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		out = append(out, strings.TrimSpace(line))
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read lines: %w", err)
	}

	return out, nil
}

// ParseAllowList reads an allowlist: one address or prefix of any width per
// line, with # comments. name prefixes the line numbers in errors.
func ParseAllowList(name string, data []byte) (*netaddr.Set, error) {
	ls, err := lines(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	set := netaddr.NewSet()

	for i, l := range ls {
		if l == "" {
			continue
		}

		p, parseErr := netaddr.ParseAllow(l)
		if parseErr != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, i+1, parseErr)
		}

		set.Add(p)
	}

	return set, nil
}

// ParseKeys reads a key list: one key per line, with # comments.
func ParseKeys(data []byte) (map[string]bool, error) {
	ls, err := lines(data)
	if err != nil {
		return nil, err
	}

	keys := map[string]bool{}

	for _, l := range ls {
		if l != "" {
			keys[l] = true
		}
	}

	return keys, nil
}

// Entry is one entry of the manual list. A ban adds its prefix to the
// published list; a lift keeps its prefix off it, overriding scored and
// manual bans. Both end at Expires.
type Entry struct {
	Action  string
	Prefix  netip.Prefix
	Expires time.Time
	Reason  string
	By      string
	Commit  string
}

// Key identifies an entry across restarts.
func (e Entry) Key() string {
	return e.Action + " " + e.Prefix.String() + " " + e.Expires.UTC().Format(time.RFC3339)
}

type rawEntry struct {
	Action  string `json:"action"`
	CIDR    string `json:"cidr"`
	Expires string `json:"expires"`
	Reason  string `json:"reason"`
	By      string `json:"by"`
	Commit  string `json:"commit"`
}

// ErrMalformed marks a manual list that could not be read as a whole, as
// opposed to one with invalid entries.
var ErrMalformed = errors.New("malformed manual list")

// Parse reads a manual list:
//
//	{"entries": [{"action": "ban", "cidr": "192.0.2.0/24",
//	  "expires": "2030-01-01T00:00:00Z", "reason": "...", "by": "...", "commit": "..."}]}
//
// A list that is not one such JSON object with an entries array fails as a
// whole, wrapping ErrMalformed, so a half-written file is never mistaken for
// an empty list.
// Otherwise it returns the valid entries and an error for each invalid one.
func Parse(data []byte, lim netaddr.Limits) ([]Entry, []error, error) {
	var f *struct {
		Entries *[]rawEntry `json:"entries"`
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&f); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("%w: data after the list", ErrMalformed)
	}

	if f == nil || f.Entries == nil {
		return nil, nil, fmt.Errorf("%w: no entries array", ErrMalformed)
	}

	var (
		out  []Entry
		errs []error
		seen = map[string]bool{}
	)

	for i, raw := range *f.Entries {
		e, err := parseEntry(raw, lim)
		if err == nil {
			key := e.Action + " " + e.Prefix.String()
			if seen[key] {
				err = errors.New("listed twice")
			}

			seen[key] = true
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("entry %d (%s %s): %w", i+1, raw.Action, raw.CIDR, err))

			continue
		}

		out = append(out, e)
	}

	return out, errs, nil
}

func parseEntry(raw rawEntry, lim netaddr.Limits) (Entry, error) {
	if raw.Action != Ban && raw.Action != Lift {
		return Entry{}, fmt.Errorf("action %q, want ban or lift", raw.Action)
	}

	p, err := netaddr.ParseEntry(raw.CIDR, lim)
	if err != nil {
		return Entry{}, err
	}

	if raw.Expires == "" {
		return Entry{}, errors.New("no expiry")
	}

	expires, err := time.Parse(time.RFC3339, raw.Expires)
	if err != nil {
		return Entry{}, fmt.Errorf("expires: %w", err)
	}

	if !expires.Before(latestExpiry) {
		return Entry{}, fmt.Errorf("expires after %s", latestExpiry.Format(time.DateOnly))
	}

	reason := strings.TrimSpace(raw.Reason)
	if reason == "" {
		return Entry{}, errors.New("no reason")
	}

	return Entry{Action: raw.Action, Prefix: p, Expires: expires, Reason: reason, By: raw.By, Commit: raw.Commit}, nil
}

// Validate is the review-time check of a manual list: everything Parse
// checks, plus no ban overlapping the allowlist or a lift, and no expiry
// further ahead of now than maxAhead. Entries that have expired only warn.
func Validate(data []byte, lim netaddr.Limits, allow *netaddr.Set, now time.Time, maxAhead time.Duration) (errs, warnings []error) {
	entries, errs, err := Parse(data, lim)
	if err != nil {
		return []error{err}, nil
	}

	lifts := netaddr.NewSet()

	for _, e := range entries {
		if e.Action == Lift {
			lifts.Add(e.Prefix)
		}
	}

	for _, e := range entries {
		switch {
		case !e.Expires.After(now):
			warnings = append(warnings, fmt.Errorf("%s %s expired at %s and can be removed", e.Action, e.Prefix, e.Expires.Format(time.RFC3339)))
		case e.Expires.Sub(now) > maxAhead:
			errs = append(errs, fmt.Errorf("%s %s expires more than %s ahead", e.Action, e.Prefix, maxAhead))
		}

		if e.Action != Ban {
			continue
		}

		if allow.Overlaps(e.Prefix) {
			errs = append(errs, fmt.Errorf("ban %s overlaps the allowlist", e.Prefix))
		}

		if lifts.Overlaps(e.Prefix) {
			errs = append(errs, fmt.Errorf("ban %s overlaps a lift", e.Prefix))
		}
	}

	return errs, warnings
}
