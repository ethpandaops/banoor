package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "partners.txt"), []byte("198.51.100.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	expires := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	good := `{"entries": [{"action": "ban", "cidr": "203.0.113.0/24", "expires": "` + expires + `", "reason": "scanner range"}]}`

	var out strings.Builder
	if err := run([]string{"validate", "-allow-dir", dir, "-manual", "-"}, strings.NewReader(good), &out, io.Discard); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}

	if !strings.Contains(out.String(), "manual list: ok") {
		t.Fatalf("output: %s", out.String())
	}

	bad := `{"entries": [
		{"action": "ban", "cidr": "198.51.100.0/24", "expires": "` + expires + `", "reason": "a partner"},
		{"action": "ban", "cidr": "10.0.0.0/24", "expires": "` + expires + `", "reason": "private"}
	]}`

	out.Reset()

	err := run([]string{"validate", "-allow-dir", dir, "-manual", "-"}, strings.NewReader(bad), &out, io.Discard)
	if err == nil || strings.Count(out.String(), "overlaps the allowlist") != 2 {
		t.Fatalf("err = %v, output:\n%s", err, out.String())
	}

	if err = run([]string{"validate", "-allow-dir", filepath.Join(dir, "absent")}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("a missing allowlist directory validated")
	}
}

func TestPubkey(t *testing.T) {
	t.Parallel()

	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	key := filepath.Join(t.TempDir(), "key")
	if out, cmdErr := exec.CommandContext(t.Context(), keygen, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); cmdErr != nil {
		t.Fatalf("%v: %s", cmdErr, out)
	}

	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}

	want := strings.Join(strings.Fields(string(pub))[:2], " ")

	var out strings.Builder
	if err = run([]string{"pubkey", "-key", key, "-principal", "list-signer", "-namespace", "example-banlist"}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}

	if got := strings.TrimSpace(out.String()); got != `list-signer namespaces="example-banlist" `+want {
		t.Fatalf("got %q", got)
	}
}

func TestHelpSucceeds(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"-h"}, {"validate", "-h"}, {"pubkey", "-h"}} {
		var out, errOut strings.Builder
		if err := run(args, strings.NewReader(""), &out, &errOut); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	if err := run([]string{"frobnicate"}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("an unknown command succeeded")
	}

	if err := run(nil, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("no command succeeded")
	}
}
