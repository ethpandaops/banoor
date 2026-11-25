package manual

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/pkg/netaddr"
)

func TestParseAllowList(t *testing.T) {
	t.Parallel()

	set, err := ParseAllowList("partners.txt", []byte("# monitoring\n192.0.2.10\n\n198.51.100.0/24 # partner\n2001:db8:5::1\n"))
	if err != nil {
		t.Fatal(err)
	}

	if set.Len() != 3 || !set.Overlaps(netip.MustParsePrefix("198.51.100.7/32")) {
		t.Fatalf("got %d prefixes", set.Len())
	}

	_, err = ParseAllowList("partners.txt", []byte("192.0.2.1\nnot-an-address\n"))
	if err == nil || !strings.Contains(err.Error(), "partners.txt:2") {
		t.Fatalf("want an error naming partners.txt:2, got %v", err)
	}
}

func TestParseKeys(t *testing.T) {
	t.Parallel()

	keys, err := ParseKeys([]byte("# pinned\nSHA256:a\n\nSHA256:b # laptop\n"))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 || !keys["SHA256:a"] || !keys["SHA256:b"] {
		t.Fatalf("keys = %v", keys)
	}
}

func TestParseKeepsValidEntries(t *testing.T) {
	t.Parallel()

	data := []byte(`{"entries": [
		{"action": "ban", "cidr": "192.0.2.0/24", "expires": "2030-01-01T00:00:00Z", "reason": "scanner range"},
		{"action": "ban", "cidr": "192.0.2.0/23", "expires": "2030-01-01T00:00:00Z", "reason": "too wide"},
		{"action": "ban", "cidr": "198.51.100.7/32", "reason": "no expiry"},
		{"action": "lift", "cidr": "2001:db8:1:2::/64", "expires": "2030-01-01T00:00:00Z", "reason": " "},
		{"action": "drop", "cidr": "198.51.100.8/32", "expires": "2030-01-01T00:00:00Z", "reason": "bad action"},
		{"action": "lift", "cidr": "198.51.100.9/32", "expires": "2030-01-01", "reason": "date only"},
		{"action": "ban", "cidr": "198.51.100.10/32", "expires": "2106-03-01T00:00:00Z", "reason": "beyond 2100"},
		{"action": "ban", "cidr": "192.0.2.0/24", "expires": "2031-01-01T00:00:00Z", "reason": "duplicate"},
		{"action": "lift", "cidr": "2001:db8:1:3::/64", "expires": "2030-01-01T00:00:00Z", "reason": "home network", "by": "operator"}
	]}`)

	got, errs, err := Parse(data, netaddr.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 || got[0].Prefix.String() != "192.0.2.0/24" || got[1].Action != Lift || got[1].By != "operator" {
		t.Fatalf("valid entries = %+v", got)
	}

	if len(errs) != 7 {
		t.Errorf("got %d entry errors, want 7: %v", len(errs), errs)
	}
}

func TestParseRejectsMalformedLists(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]string{
		"truncated":       `{"entries": [{"action": "ban", "cidr": "192.0.2.0/24"`,
		"two objects":     `{"entries": []} {"entries": [{"action": "lift"}]}`,
		"trailing text":   `{"entries": []} garbage`,
		"unknown field":   `{"entries": [{"action": "ban", "cidr": "192.0.2.0/24", "expiry": "2030-01-01T00:00:00Z", "reason": "typo"}]}`,
		"not an object":   `[]`,
		"empty file":      ``,
		"entries is text": `{"entries": "none"}`,
		"entries is null": `{"entries": null}`,
		"no entries":      `{}`,
		"null":            `null`,
	} {
		_, _, err := Parse([]byte(data), netaddr.DefaultLimits)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	allow := netaddr.NewSet(netip.MustParsePrefix("198.51.100.10/32"))
	data := []byte(`{"entries": [
		{"action": "ban", "cidr": "198.51.100.0/24", "expires": "2030-02-01T00:00:00Z", "reason": "covers an allowed address"},
		{"action": "ban", "cidr": "203.0.113.0/24", "expires": "2030-02-01T00:00:00Z", "reason": "overlaps a lift"},
		{"action": "lift", "cidr": "203.0.113.5/32", "expires": "2030-02-01T00:00:00Z", "reason": "customer"},
		{"action": "ban", "cidr": "192.0.2.0/24", "expires": "2035-01-01T00:00:00Z", "reason": "too far ahead"},
		{"action": "ban", "cidr": "192.0.2.77/32", "expires": "2029-06-01T00:00:00Z", "reason": "expired"},
		{"action": "ban", "cidr": "2001:db8:9::/48", "expires": "2030-01-08T00:00:00Z", "reason": "fine"}
	]}`)

	errs, warnings := Validate(data, netaddr.DefaultLimits, allow, now, 365*24*time.Hour)

	want := []string{"198.51.100.0/24 overlaps the allowlist", "203.0.113.0/24 overlaps a lift", "192.0.2.0/24 expires more than"}
	if len(errs) != len(want) {
		t.Fatalf("got errors %v, want %d", errs, len(want))
	}

	for i, w := range want {
		if !strings.Contains(errs[i].Error(), w) {
			t.Errorf("error %d = %q, want it to mention %q", i, errs[i], w)
		}
	}

	if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "192.0.2.77/32 expired") {
		t.Errorf("warnings = %v, want one for the expired entry", warnings)
	}

	if malformed, _ := Validate([]byte(`{"entries": [`), netaddr.DefaultLimits, allow, now, time.Hour); len(malformed) != 1 {
		t.Errorf("a malformed list gave %v", errs)
	}
}
