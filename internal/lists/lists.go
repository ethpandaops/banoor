// Package lists reads the operator's allowlist directory.
package lists

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ethpandaops/banoor/pkg/manual"
	"github.com/ethpandaops/banoor/pkg/netaddr"
)

// ReadAllowDir reads every *.txt file in dir, following symbolic links (as
// mounted configuration often is). A missing directory is an error, so a
// typo never reads as an empty allowlist. An empty dir means no allowlist
// files.
func ReadAllowDir(dir string) (*netaddr.Set, error) {
	set := netaddr.NewSet()
	if dir == "" {
		return set, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}

		path := filepath.Join(dir, e.Name())

		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, statErr
		}

		if info.IsDir() {
			continue
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}

		list, parseErr := manual.ParseAllowList(path, data)
		if parseErr != nil {
			return nil, parseErr
		}

		set = netaddr.Union(set, list)
	}

	return set, nil
}
