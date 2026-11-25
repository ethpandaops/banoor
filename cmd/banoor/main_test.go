package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "partners.txt"), []byte("198.51.100.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	good := `{"entries": [{"action": "ban", "cidr": "203.0.113.0/24", "expires": "` + expires + `", "reason": "scanner range"}]}`
	var out strings.Builder
	if err := validate([]string{"-allow-dir", dir, "-manual", "-"}, strings.NewReader(good), &out); err != nil {
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
	err := validate([]string{"-allow-dir", dir, "-manual", "-"}, strings.NewReader(bad), &out)
	if err == nil || strings.Count(out.String(), "overlaps the allowlist") != 2 {
		t.Fatalf("err = %v, output:\n%s", err, out.String())
	}
}

func TestPubkey(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	key := filepath.Join(t.TempDir(), "key")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	pub, _ := os.ReadFile(key + ".pub")
	want := strings.Join(strings.Fields(string(pub))[:2], " ")

	var out strings.Builder
	if err := pubkey([]string{"-key", key, "-principal", "list-signer", "-namespace", "example-banlist"}, &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != `list-signer namespaces="example-banlist" `+want {
		t.Fatalf("got %q", got)
	}
}
