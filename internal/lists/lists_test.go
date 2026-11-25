package lists

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAllowDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()

		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("a.txt", "# monitoring\n192.0.2.10\n")
	write("ignored.md", "not an address\n")

	// Mounted configuration is often a symbolic link.
	target := filepath.Join(t.TempDir(), "b")
	if err := os.WriteFile(target, []byte("198.51.100.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, filepath.Join(dir, "b.txt")); err != nil {
		t.Fatal(err)
	}

	set, err := ReadAllowDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if set.Len() != 2 || !set.Overlaps(netip.MustParsePrefix("198.51.100.7/32")) {
		t.Fatalf("got %d prefixes", set.Len())
	}

	write("c.txt", "192.0.2.1\nnot-an-address\n")

	if _, err = ReadAllowDir(dir); err == nil || !strings.Contains(err.Error(), "c.txt:2") {
		t.Fatalf("want an error naming c.txt:2, got %v", err)
	}

	for _, missing := range []string{filepath.Join(dir, "absent"), filepath.Join(dir, "a.txt"), dir + "[1]"} {
		if _, err = ReadAllowDir(missing); err == nil {
			t.Errorf("ReadAllowDir(%q) succeeded, want an error", missing)
		}
	}

	if none, noneErr := ReadAllowDir(""); noneErr != nil || none.Len() != 0 {
		t.Errorf("no directory gave %v, %v", none, noneErr)
	}
}
