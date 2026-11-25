package sshsig

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func sshKeygen(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	return path
}

func newKey(t *testing.T, keygen, passphrase string) (keyFile string, key []byte) {
	t.Helper()
	keyFile = filepath.Join(t.TempDir(), "key")
	cmd := exec.Command(keygen, "-q", "-t", "ed25519", "-N", passphrase, "-C", "test", "-f", keyFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return keyFile, key
}

// verify runs ssh-keygen -Y verify the way a consumer of the list does.
func verify(t *testing.T, keygen, publicKey, namespace string, message []byte, sig string) error {
	t.Helper()
	dir := t.TempDir()
	signers := filepath.Join(dir, "allowed_signers")
	line := "list-signer namespaces=\"" + namespace + "\" " + publicKey + "\n"
	if err := os.WriteFile(signers, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	sigFile := filepath.Join(dir, "sig")
	if err := os.WriteFile(sigFile, []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(keygen, "-Y", "verify", "-f", signers, "-I", "list-signer", "-n", namespace, "-s", sigFile)
	cmd.Stdin = bytes.NewReader(message)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &verifyError{out: string(out), err: err}
	}
	return nil
}

type verifyError struct {
	out string
	err error
}

func (e *verifyError) Error() string { return e.err.Error() + ": " + e.out }

func TestSignVerifiesWithSSHKeygen(t *testing.T) {
	keygen := sshKeygen(t)
	keyFile, data := newKey(t, keygen, "")
	key, err := ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	s := New(key, "example-list")

	pub, err := os.ReadFile(keyFile + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(strings.Fields(string(pub))[:2], " "); s.PublicKey() != want {
		t.Fatalf("PublicKey() = %q, want %q", s.PublicKey(), want)
	}

	message := []byte(`{"version":1,"entries":[]}`)
	sig := s.Sign(message)
	if err := verify(t, keygen, s.PublicKey(), "example-list", message, sig); err != nil {
		t.Fatalf("ssh-keygen rejected the signature: %v", err)
	}
	if err := verify(t, keygen, s.PublicKey(), "other-purpose", message, sig); err == nil {
		t.Fatal("the signature verified under another namespace")
	}
	if err := verify(t, keygen, s.PublicKey(), "example-list", append(message, ' '), sig); err == nil {
		t.Fatal("the signature verified for a changed message")
	}
}

func TestSSHKeygenSignatureMatchesOurs(t *testing.T) {
	keygen := sshKeygen(t)
	keyFile, data := newKey(t, keygen, "")
	key, err := ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	msgFile := filepath.Join(t.TempDir(), "msg")
	message := []byte("payload bytes\n")
	if err := os.WriteFile(msgFile, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(keygen, "-q", "-Y", "sign", "-f", keyFile, "-n", "example-list", msgFile).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v: %s", err, out)
	}
	theirs, err := os.ReadFile(msgFile + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 signatures are deterministic, so the same key, namespace and
	// message must give byte-identical output.
	if ours := New(key, "example-list").Sign(message); ours != string(theirs) {
		t.Fatalf("signatures differ\nours:\n%s\nssh-keygen:\n%s", ours, theirs)
	}
}

func TestParsePrivateKeyRejects(t *testing.T) {
	keygen := sshKeygen(t)
	_, encrypted := newKey(t, keygen, "a passphrase")
	if _, err := ParsePrivateKey(encrypted); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("encrypted key: got %v, want an encrypted-key error", err)
	}
	if _, err := ParsePrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")); err == nil {
		t.Error("accepted a non-OpenSSH key")
	}
	if _, err := ParsePrivateKey(nil); err == nil {
		t.Error("accepted an empty file")
	}
}
