package netaddr

import (
	"math"
	"net/netip"
	"testing"
)

func TestUnit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		bits int
		want string
	}{
		{"192.0.2.7", 64, "192.0.2.7/32"},
		{"::ffff:192.0.2.7", 64, "192.0.2.7/32"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", 64, "2001:db8:1:2::/64"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", 48, "2001:db8:1::/48"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", 128, "2001:db8:1:2:aaaa:bbbb:cccc:dddd/128"},
		{"2001:db8:1:2::1%eth0", 64, "2001:db8:1:2::/64"},
		{" 198.51.100.1 ", 64, "198.51.100.1/32"},
	}
	for _, tt := range tests {
		got, err := Unit(tt.in, tt.bits)
		if err != nil {
			t.Fatalf("Unit(%q, %d): %v", tt.in, tt.bits, err)
		}

		if got.String() != tt.want {
			t.Errorf("Unit(%q, %d) = %s, want %s", tt.in, tt.bits, got, tt.want)
		}
	}

	for _, bad := range []string{"", "host.example", "192.0.2.300", "[2001:db8::1]"} {
		if _, err := Unit(bad, 64); err == nil {
			t.Errorf("Unit(%q) succeeded, want an error", bad)
		}
	}
}

func TestParseEntry(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"192.0.2.0/24", "192.0.2.1/32", "2001:db8:1::/48", "2001:db8:1:2::/64", "2001:db8::1/128"} {
		if _, err := ParseEntry(s, DefaultLimits); err != nil {
			t.Errorf("ParseEntry(%q): %v", s, err)
		}
	}

	for s, why := range map[string]string{
		"192.0.2.0/23":      "wider than /24",
		"2001:db8::/47":     "wider than /48",
		"192.0.2.1/24":      "host bits set",
		"::ffff:c000:2/128": "IPv4-mapped",
		"192.0.2.1":         "no prefix length",
		"0.0.0.0/0":         "everything",
		"192.0.2.001/32":    "leading zeros",
	} {
		if _, err := ParseEntry(s, DefaultLimits); err == nil {
			t.Errorf("ParseEntry(%q) succeeded, want an error (%s)", s, why)
		}
	}
}

func TestParseAllow(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"192.0.2.7":            "192.0.2.7/32",
		"2001:db8::7":          "2001:db8::7/128",
		"10.1.2.3/8":           "10.0.0.0/8",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
		"fe80::1%eth0":         "fe80::1/128",
	} {
		got, err := ParseAllow(in)
		if err != nil {
			t.Fatalf("ParseAllow(%q): %v", in, err)
		}

		if got.String() != want {
			t.Errorf("ParseAllow(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestSetOverlapsAndCovers(t *testing.T) {
	t.Parallel()

	s := NewSet(netip.MustParsePrefix("2001:db8:1:2::7/128"), netip.MustParsePrefix("198.51.100.0/25"))

	cases := []struct {
		p                string
		overlaps, covers bool
	}{
		{"2001:db8:1:2::/64", true, false}, // an allowed address inside a wider candidate
		{"2001:db8:1:2::7/128", true, true},
		{"2001:db8:1:3::/64", false, false},
		{"198.51.100.9/32", true, true},
		{"198.51.100.0/24", true, false}, // wider than the set's /25
		{"198.51.100.200/32", false, false},
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.p)
		if got := s.Overlaps(p); got != c.overlaps {
			t.Errorf("Overlaps(%s) = %v, want %v", c.p, got, c.overlaps)
		}

		if got := s.Covers(p); got != c.covers {
			t.Errorf("Covers(%s) = %v, want %v", c.p, got, c.covers)
		}
	}

	var empty *Set
	if empty.Overlaps(netip.MustParsePrefix("192.0.2.1/32")) || empty.Covers(netip.MustParsePrefix("192.0.2.1/32")) {
		t.Error("a nil set holds nothing")
	}
}

func TestCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		p      string
		v4, v6 uint64
	}{
		{"192.0.2.0/24", 256, 0},
		{"192.0.2.1/32", 1, 0},
		{"0.0.0.0/0", 1 << 32, 0},
		{"2001:db8::/48", 0, 1 << 16},
		{"2001:db8::/64", 0, 1},
		{"2001:db8::1/128", 0, 1},
		{"8000::/1", 0, 1 << 63},
		{"::/0", 0, math.MaxUint64},
	}
	for _, tt := range tests {
		v4, v6 := Coverage(netip.MustParsePrefix(tt.p))
		if v4 != tt.v4 || v6 != tt.v6 {
			t.Errorf("Coverage(%s) = %d, %d, want %d, %d", tt.p, v4, v6, tt.v4, tt.v6)
		}
	}
}

func TestSpecialPurpose(t *testing.T) {
	t.Parallel()

	sp := SpecialPurpose()
	for _, p := range []string{"10.1.2.3/32", "100.100.1.1/32", "198.18.0.1/32", "fd00::1/128", "fe80::/64", "64:ff9b::/64", "2001:0:1::/64"} {
		if !sp.Overlaps(netip.MustParsePrefix(p)) {
			t.Errorf("%s should be special-purpose", p)
		}
	}

	for _, p := range []string{"192.0.2.1/32", "2001:db8::/64"} {
		if sp.Overlaps(netip.MustParsePrefix(p)) {
			t.Errorf("%s should not be special-purpose", p)
		}
	}
}
