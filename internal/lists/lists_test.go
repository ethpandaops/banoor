package lists

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/internal/netaddr"
)

func TestLoadAllowDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.txt", "# monitoring\n192.0.2.10\n\n198.51.100.0/24 # partner\n")
	write("b.txt", "2001:db8:5::1\n")
	write("ignored.md", "not an address\n")

	set, err := LoadAllowDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 3 {
		t.Fatalf("got %d prefixes, want 3", set.Len())
	}

	write("c.txt", "192.0.2.1\nnot-an-address\n")
	_, err = LoadAllowDir(dir)
	if err == nil || !strings.Contains(err.Error(), "c.txt:2") {
		t.Fatalf("want an error naming c.txt:2, got %v", err)
	}
}

func TestParseManualKeepsValidEntries(t *testing.T) {
	data := []byte(`{"entries": [
		{"action": "ban", "cidr": "192.0.2.0/24", "expires": "2030-01-01T00:00:00Z", "reason": "scanner range"},
		{"action": "ban", "cidr": "192.0.2.0/23", "expires": "2030-01-01T00:00:00Z", "reason": "too wide"},
		{"action": "ban", "cidr": "198.51.100.7/32", "reason": "no expiry"},
		{"action": "lift", "cidr": "2001:db8:1:2::/64", "expires": "2030-01-01T00:00:00Z", "reason": " "},
		{"action": "drop", "cidr": "198.51.100.8/32", "expires": "2030-01-01T00:00:00Z", "reason": "bad action"},
		{"action": "lift", "cidr": "198.51.100.9/32", "expires": "2030-01-01", "reason": "date only"},
		{"action": "ban", "cidr": "192.0.2.0/24", "expires": "2031-01-01T00:00:00Z", "reason": "duplicate"},
		{"action": "lift", "cidr": "2001:db8:1:3::/64", "expires": "2030-01-01T00:00:00Z", "reason": "home network", "by": "operator"}
	]}`)
	got, errs := ParseManual(data, netaddr.DefaultLimits)
	if len(got) != 2 {
		t.Fatalf("got %d valid entries, want 2: %+v", len(got), got)
	}
	if got[0].Prefix.String() != "192.0.2.0/24" || got[1].Action != Lift || got[1].By != "operator" {
		t.Errorf("unexpected entries: %+v", got)
	}
	if len(errs) != 6 {
		t.Errorf("got %d errors, want 6: %v", len(errs), errs)
	}
}

func TestParseManualRejectsUnknownFields(t *testing.T) {
	_, errs := ParseManual([]byte(`{"entries": [{"action": "ban", "cidr": "192.0.2.0/24", "expiry": "2030-01-01T00:00:00Z", "reason": "typo"}]}`), netaddr.DefaultLimits)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "expiry") {
		t.Fatalf("want an unknown-field error, got %v", errs)
	}
}

func TestValidate(t *testing.T) {
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
}
