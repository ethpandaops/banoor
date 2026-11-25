package sshlog

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name, line string
		kind       Kind
		addr       string
	}{
		{
			name: "user name framing another address",
			line: "Invalid user x from 192.0.2.7 port 1 from 198.51.100.10 port 36465",
			kind: InvalidUser, addr: "198.51.100.10",
		},
		{
			name: "framing with an IPv6 decoy",
			line: "Invalid user a from 2001:db8::bad port 22 from 2001:db8:1:2::abcd port 50022",
			kind: InvalidUser, addr: "2001:db8:1:2::abcd",
		},
		{
			name: "plain invalid user",
			line: "Invalid user admin from 198.51.100.11 port 44664",
			kind: InvalidUser, addr: "198.51.100.11",
		},
		{
			name: "empty user name",
			line: "Invalid user  from 198.51.100.12 port 22",
			kind: InvalidUser, addr: "198.51.100.12",
		},
		{
			name: "AllowGroups refusal",
			line: "User root from 198.51.100.13 not allowed because none of user's groups are listed in AllowGroups",
			kind: NotAllowed, addr: "198.51.100.13",
		},
		{
			name: "penalty drop",
			line: "drop connection #0 from [198.51.100.14]:45784 on [203.0.113.1]:22 penalty: attempted authentication by invalid user",
			kind: PenaltyDrop, addr: "198.51.100.14",
		},
		{
			name: "MaxStartups drop",
			line: "drop connection #3 from [2001:db8::15]:1234 on [2001:db8::1]:22 past MaxStartups",
			kind: MaxStartupsDrop, addr: "2001:db8::15",
		},
		{
			name: "real account disconnecting before authenticating",
			line: "Connection closed by authenticating user alice 198.51.100.16 port 63787 [preauth]",
			kind: AuthClosed, addr: "198.51.100.16",
		},
		{
			name: "IPv4-mapped address",
			line: "Invalid user test from ::ffff:198.51.100.17 port 40000",
			kind: InvalidUser, addr: "198.51.100.17",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, ok := Parse(tt.line)
			if !ok {
				t.Fatalf("Parse(%q) found nothing", tt.line)
			}
			if ev.Kind != tt.kind || ev.Address.String() != tt.addr {
				t.Fatalf("Parse(%q) = %s %s, want %s %s", tt.line, ev.Kind, ev.Address, tt.kind, tt.addr)
			}
		})
	}
}

func TestParseAccepted(t *testing.T) {
	ev, ok := Parse("Accepted publickey for alice from 198.51.100.20 port 44236 ssh2: ED25519 SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
	if !ok {
		t.Fatal("found nothing")
	}
	if ev.Kind != Accepted || ev.User != "alice" || ev.Address.String() != "198.51.100.20" || ev.Fingerprint != "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Fatalf("got %+v", ev)
	}
}

func TestParseIgnores(t *testing.T) {
	for _, line := range []string{
		"Connection closed by invalid user root 198.51.100.11 port 52821 [preauth]", // the second line of an invalid-user attempt
		"Received disconnect from 198.51.100.20 port 58464:11: disconnected by user",
		"Invalid user x from host.example port 22",           // UseDNS host name
		"Invalid user x from 198.51.100.10 port 22 trailing", // not at the end
		"drop connection #0 from [198.51.100.14]:45784 on [203.0.113.1]:22 unknown reason",
		"Accepted password for alice from 198.51.100.20 port 1 ssh2",
		"",
	} {
		if ev, ok := Parse(line); ok {
			t.Errorf("Parse(%q) = %+v, want nothing", line, ev)
		}
	}
}
