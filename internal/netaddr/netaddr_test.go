package netaddr

import (
	"net/netip"
	"testing"
)

func TestUnit(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"192.0.2.7", "192.0.2.7/32"},
		{"::ffff:192.0.2.7", "192.0.2.7/32"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1%eth0", "2001:db8:1:2::/64"},
		{" 198.51.100.1 ", "198.51.100.1/32"},
	}
	for _, tt := range tests {
		got, err := Unit(tt.in, 64)
		if err != nil {
			t.Fatalf("Unit(%q): %v", tt.in, err)
		}
		if got.String() != tt.want {
			t.Errorf("Unit(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
	for _, bad := range []string{"", "host.example", "192.0.2.300", "[2001:db8::1]"} {
		if _, err := Unit(bad, 64); err == nil {
			t.Errorf("Unit(%q) succeeded, want an error", bad)
		}
	}
}

func TestParseEntry(t *testing.T) {
	ok := []string{"192.0.2.0/24", "192.0.2.1/32", "2001:db8:1::/48", "2001:db8:1:2::/64", "2001:db8::1/128"}
	for _, s := range ok {
		if _, err := ParseEntry(s, DefaultLimits); err != nil {
			t.Errorf("ParseEntry(%q): %v", s, err)
		}
	}
	bad := map[string]string{
		"192.0.2.0/23":      "wider than /24",
		"2001:db8::/47":     "wider than /48",
		"192.0.2.1/24":      "host bits set",
		"::ffff:c000:2/128": "IPv4-mapped",
		"192.0.2.1":         "no prefix length",
		"0.0.0.0/0":         "everything",
	}
	for s, why := range bad {
		if _, err := ParseEntry(s, DefaultLimits); err == nil {
			t.Errorf("ParseEntry(%q) succeeded, want an error (%s)", s, why)
		}
	}
}

func TestParseAllow(t *testing.T) {
	tests := map[string]string{
		"192.0.2.7":            "192.0.2.7/32",
		"2001:db8::7":          "2001:db8::7/128",
		"10.1.2.3/8":           "10.0.0.0/8",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
	}
	for in, want := range tests {
		got, err := ParseAllow(in)
		if err != nil {
			t.Fatalf("ParseAllow(%q): %v", in, err)
		}
		if got.String() != want {
			t.Errorf("ParseAllow(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestSetOverlapsBothWays(t *testing.T) {
	s := NewSet(netip.MustParsePrefix("2001:db8:1:2::7/128"), netip.MustParsePrefix("198.51.100.0/24"))
	cases := map[string]bool{
		"2001:db8:1:2::/64": true,  // an allowed address inside the banned network
		"2001:db8:1:3::/64": false, // the neighbouring network
		"198.51.100.9/32":   true,  // an address inside an allowed range
		"198.51.101.9/32":   false,
	}
	for p, want := range cases {
		if got := s.Overlaps(netip.MustParsePrefix(p)); got != want {
			t.Errorf("Overlaps(%s) = %v, want %v", p, got, want)
		}
	}
	var nilSet *Set
	if nilSet.Overlaps(netip.MustParsePrefix("192.0.2.1/32")) {
		t.Error("a nil set overlaps nothing")
	}
}

func TestCoverage(t *testing.T) {
	tests := []struct {
		p      string
		v4, v6 uint64
	}{
		{"192.0.2.0/24", 256, 0},
		{"192.0.2.1/32", 1, 0},
		{"2001:db8::/48", 0, 65536},
		{"2001:db8::/64", 0, 1},
		{"2001:db8::1/128", 0, 1},
	}
	for _, tt := range tests {
		v4, v6 := Coverage(netip.MustParsePrefix(tt.p))
		if v4 != tt.v4 || v6 != tt.v6 {
			t.Errorf("Coverage(%s) = %d, %d, want %d, %d", tt.p, v4, v6, tt.v4, tt.v6)
		}
	}
}

func TestSpecialPurpose(t *testing.T) {
	sp := SpecialPurpose()
	for _, p := range []string{"10.1.2.3/32", "100.100.1.1/32", "fd00::1/128", "fe80::/64"} {
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
