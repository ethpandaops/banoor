// Package sshlog extracts the client address and outcome from OpenSSH
// server log lines.
//
// sshd logs the user name a client sends verbatim, so a client can put text
// that looks like an address into it:
//
//	Invalid user x from 192.0.2.7 port 1 from 198.51.100.10 port 36465
//
// Every pattern here therefore takes the address from a part of the line the
// client does not control: the fixed end of the line, or a field sshd fills
// from its own state. The exported patterns use RE2 syntax, so a database
// that extracts with RE2 (ClickHouse's extract, for example) can use them
// unchanged.
//
// This holds only for messages sshd sends to syslog (the journal included),
// where it escapes control characters. With -e it writes to standard error
// without escaping, so a user name with a newline in it can forge a whole
// line. Only count lines that sshd itself logged through syslog.
package sshlog

import (
	"net/netip"
	"regexp"
	"strings"
)

// Kind is the outcome a line records.
type Kind string

const (
	// InvalidUser means the client named a user that does not exist.
	InvalidUser Kind = "invalid_user"
	// NotAllowed means the user exists but AllowUsers, AllowGroups, DenyUsers or
	// DenyGroups refuse it. sshd prints the account's name from the password
	// database here, not the client's string.
	NotAllowed Kind = "not_allowed"
	// PenaltyDrop means sshd refused a connection because its source is serving a
	// PerSourcePenalties penalty.
	PenaltyDrop Kind = "penalty_drop"
	// MaxStartupsDrop means sshd refused a connection because too many were
	// unauthenticated. It hits whoever is unlucky, not only the cause.
	MaxStartupsDrop Kind = "maxstartups_drop"
	// AuthClosed means a client for a real account disconnected before
	// authenticating, such as with a wrong key.
	AuthClosed Kind = "auth_closed"
	// Accepted means a public key login succeeded.
	Accepted Kind = "accepted_publickey"
)

// RE2 patterns, each with the address as its first group.
const (
	InvalidUserPattern = `^Invalid user .* from (\S+) port \d+$`
	NotAllowedPattern  = `^User \S+ from (\S+) not allowed because `
	DropPattern        = `^drop connection #\d+ from \[([^\]]+)\]:\d+ on `
	AuthClosedPattern  = `^Connection closed by authenticating user \S+ (\S+) port \d+ \[preauth\]$`
	// AcceptedPattern's groups are the user, the address and the key's
	// SHA256 fingerprint; for a certificate, the certified key's, followed by
	// the CA-signed ID, serial and CA key.
	AcceptedPattern = `^Accepted publickey for (\S+) from (\S+) port \d+ ssh2: \S+ (SHA256:\S+)(?: ID .*)?$`
)

var (
	invalidUser = regexp.MustCompile(InvalidUserPattern)
	notAllowed  = regexp.MustCompile(NotAllowedPattern)
	drop        = regexp.MustCompile(DropPattern)
	authClosed  = regexp.MustCompile(AuthClosedPattern)
	accepted    = regexp.MustCompile(AcceptedPattern)
)

// Event is what one line records.
type Event struct {
	Kind        Kind
	Address     netip.Addr
	User        string // Accepted only
	Fingerprint string // Accepted only
}

// Parse reads one message, without the syslog prefix. It reports false for
// lines it does not recognise and for addresses that do not parse, such as a
// host name when sshd runs with UseDNS.
func Parse(line string) (Event, bool) {
	var (
		kind Kind
		m    []string
	)
	switch {
	case strings.HasPrefix(line, "Invalid user "):
		kind, m = InvalidUser, invalidUser.FindStringSubmatch(line)
	case strings.HasPrefix(line, "User "):
		kind, m = NotAllowed, notAllowed.FindStringSubmatch(line)
	case strings.HasPrefix(line, "drop connection #"):
		switch {
		// OpenSSH 9.7 and earlier end the line "past MaxStartups", 9.8 and
		// 9.9 "past Maxstartups", 10.0 to 10.2 "Maxstartups", later releases
		// "MaxStartups".
		case strings.HasSuffix(strings.ToLower(line), "maxstartups"):
			kind = MaxStartupsDrop
		case strings.Contains(line, " penalty: "):
			kind = PenaltyDrop
		default:
			return Event{}, false
		}
		m = drop.FindStringSubmatch(line)
	case strings.HasPrefix(line, "Connection closed by authenticating user "):
		kind, m = AuthClosed, authClosed.FindStringSubmatch(line)
	case strings.HasPrefix(line, "Accepted publickey for "):
		m = accepted.FindStringSubmatch(line)
		if m == nil {
			return Event{}, false
		}
		a, err := netip.ParseAddr(m[2])
		if err != nil {
			return Event{}, false
		}
		return Event{Kind: Accepted, Address: a.Unmap(), User: m[1], Fingerprint: m[3]}, true
	default:
		return Event{}, false
	}
	if m == nil {
		return Event{}, false
	}
	a, err := netip.ParseAddr(m[1])
	if err != nil {
		return Event{}, false
	}
	return Event{Kind: kind, Address: a.Unmap()}, true
}
