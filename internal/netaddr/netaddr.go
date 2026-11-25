// Package netaddr turns source addresses into ban units and checks the
// prefixes a list may publish.
package netaddr

import (
	"fmt"
	"net/netip"
	"strings"
)

// Limits are the widest prefixes a published list may carry.
type Limits struct {
	IPv4MinPrefix int `json:"ipv4MinPrefix"`
	IPv6MinPrefix int `json:"ipv6MinPrefix"`
}

// DefaultLimits allow nothing wider than an IPv4 /24 or an IPv6 /48.
var DefaultLimits = Limits{IPv4MinPrefix: 24, IPv6MinPrefix: 48}

// Unit returns the prefix a source is scored and banned as: an IPv4 address
// (IPv4-mapped IPv6 included) as a /32, and an IPv6 address as its network of
// length ipv6Prefix.
func Unit(addr string, ipv6Prefix int) (netip.Prefix, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return netip.PrefixFrom(a, 32), nil
	}
	return a.Prefix(ipv6Prefix)
}

// ParseEntry parses a prefix for a published list. It must be canonical (host
// bits zero), written as IPv4 when it is IPv4, and no wider than lim.
func ParseEntry(s string, lim Limits) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, err
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%s: write IPv4 prefixes as IPv4", s)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("%s: host bits are set (%s)", s, p.Masked())
	}
	minBits := lim.IPv6MinPrefix
	if p.Addr().Is4() {
		minBits = lim.IPv4MinPrefix
	}
	if p.Bits() < minBits {
		return netip.Prefix{}, fmt.Errorf("%s is wider than /%d", s, minBits)
	}
	return p, nil
}

// ParseAllow parses an allowlist line: an address, or a prefix of any width.
func ParseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("%s: an IPv4-mapped prefix shorter than /96", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Coverage counts what a prefix covers: IPv4 addresses, or IPv6 /64
// networks, where anything narrower than a /64 counts as one.
func Coverage(p netip.Prefix) (ipv4Addresses, ipv6Networks uint64) {
	if p.Addr().Is4() {
		return 1 << (32 - p.Bits()), 0
	}
	if p.Bits() >= 64 {
		return 0, 1
	}
	return 0, 1 << (64 - p.Bits())
}

// Kind names a prefix for metrics: ipv4 or ipv6 for a single source, range
// for anything wider than a unit.
func Kind(p netip.Prefix, ipv6Prefix int) string {
	switch {
	case p.Addr().Is4() && p.Bits() == 32:
		return "ipv4"
	case p.Addr().Is6() && p.Bits() >= ipv6Prefix:
		return "ipv6"
	default:
		return "range"
	}
}

// specialPurpose is never a public source: this network, private, shared
// (carrier-grade NAT), loopback, link-local, multicast, reserved, and the
// IPv6 unspecified, loopback, unique-local, link-local and multicast blocks.
var specialPurpose = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
}

// Set is a list of prefixes. It stays small (an allowlist), so lookups scan.
type Set struct{ prefixes []netip.Prefix }

// NewSet returns a set holding ps.
func NewSet(ps ...netip.Prefix) *Set {
	return &Set{prefixes: append([]netip.Prefix(nil), ps...)}
}

// SpecialPurpose returns a set of the special-purpose blocks.
func SpecialPurpose() *Set {
	s := &Set{}
	for _, c := range specialPurpose {
		s.Add(netip.MustParsePrefix(c))
	}
	return s
}

// Add adds prefixes to the set.
func (s *Set) Add(ps ...netip.Prefix) { s.prefixes = append(s.prefixes, ps...) }

// Union returns a new set with the prefixes of every set.
func Union(sets ...*Set) *Set {
	out := &Set{}
	for _, s := range sets {
		if s != nil {
			out.Add(s.prefixes...)
		}
	}
	return out
}

// Len returns the number of prefixes.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.prefixes)
}

// Covers reports whether one prefix in the set holds all of p.
func (s *Set) Covers(p netip.Prefix) bool {
	if s == nil {
		return false
	}
	for _, q := range s.prefixes {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Overlaps reports whether p shares an address with any prefix in the set,
// either way round: an allowed address inside a wider candidate counts.
func (s *Set) Overlaps(p netip.Prefix) bool {
	if s == nil {
		return false
	}
	for _, q := range s.prefixes {
		if q.Overlaps(p) {
			return true
		}
	}
	return false
}
