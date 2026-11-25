// Package netaddr turns source addresses into ban units and checks the
// prefixes a list may publish.
package netaddr

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
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
	h, err := Host(addr)
	if err != nil || h.Addr().Is4() {
		return h, err
	}
	return h.Addr().Prefix(ipv6Prefix)
}

// Host parses one address as the prefix that holds only it, an IPv4-mapped
// address as IPv4.
func Host(addr string) (netip.Prefix, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
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

// ParseAllow parses an allowlist line: an address, or a prefix of any width
// short of /0, which would allow everything.
func ParseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		return Host(s)
	}
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
	if p.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%s allows everything", s)
	}
	return p.Masked(), nil
}

// Coverage counts what a prefix covers: IPv4 addresses, or IPv6 /64
// networks, where anything narrower than a /64 counts as one. An IPv6 /0,
// whose count does not fit, counts as math.MaxUint64.
func Coverage(p netip.Prefix) (ipv4Addresses, ipv6Networks uint64) {
	switch {
	case p.Addr().Is4():
		return 1 << (32 - p.Bits()), 0
	case p.Bits() >= 64:
		return 0, 1
	case p.Bits() == 0:
		return 0, math.MaxUint64
	default:
		return 0, 1 << (64 - p.Bits())
	}
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
// (carrier-grade NAT), loopback, link-local, IETF protocol assignments,
// benchmarking, multicast, reserved, and the IPv6 unspecified, loopback,
// unique-local, link-local and multicast blocks. The NAT64 and Teredo
// prefixes are here too: behind a translator or relay many clients share one
// IPv6 network, so banning it would ban them all. So is the IPv4-mapped
// block: a consumer that does not unmap addresses would apply a ban there to
// IPv4 clients.
var specialPurpose = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "fc00::/7", "fe80::/10", "ff00::/8",
}

// Set is a set of prefixes, such as an allowlist. Lookups take time
// logarithmic in its size; the index behind them is built by the first
// lookup after a change, so a Set is not safe for concurrent use.
type Set struct {
	prefixes []netip.Prefix
	idx      *index
}

// index finds the prefixes that hold a prefix by trying each length the set
// has, and the ones inside it by searching their sorted first addresses.
type index struct {
	has    map[netip.Prefix]bool
	lens4  [33]bool
	lens6  [129]bool
	starts []netip.Addr
}

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
func (s *Set) Add(ps ...netip.Prefix) {
	s.prefixes = append(s.prefixes, ps...)
	s.idx = nil
}

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

func (s *Set) index() *index {
	if s.idx != nil {
		return s.idx
	}
	x := &index{has: make(map[netip.Prefix]bool, len(s.prefixes))}
	for _, p := range s.prefixes {
		p = p.Masked()
		x.has[p] = true
		x.starts = append(x.starts, p.Addr())
		if p.Addr().Is4() {
			x.lens4[p.Bits()] = true
		} else {
			x.lens6[p.Bits()] = true
		}
	}
	slices.SortFunc(x.starts, netip.Addr.Compare)
	s.idx = x
	return x
}

// Covers reports whether one prefix in the set holds all of p.
func (s *Set) Covers(p netip.Prefix) bool {
	if s == nil || !p.IsValid() {
		return false
	}
	x := s.index()
	lens := x.lens6[:]
	if p.Addr().Is4() {
		lens = x.lens4[:]
	}
	for bits := range p.Bits() + 1 {
		if lens[bits] && x.has[netip.PrefixFrom(p.Addr(), bits).Masked()] {
			return true
		}
	}
	return false
}

// Overlaps reports whether p shares an address with any prefix in the set,
// either way round: an allowed address inside a wider candidate counts.
func (s *Set) Overlaps(p netip.Prefix) bool {
	if s == nil || !p.IsValid() {
		return false
	}
	if s.Covers(p) {
		return true
	}
	addrs := s.index().starts
	i, _ := slices.BinarySearchFunc(addrs, p.Masked().Addr(), netip.Addr.Compare)
	return i < len(addrs) && p.Contains(addrs[i])
}
