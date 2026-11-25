package importguard_test

import (
	"slices"
	"testing"

	"github.com/ethpandaops/banoor/internal/testutil/importguard"
)

// The repository's dependency boundaries. Each entry names a package and the
// only packages allowed to import it; anything else importing it fails here.
// Add a line when a new boundary matters, and change one deliberately.
var boundaries = []struct {
	pkg     string
	allowed []string
	why     string
}{
	{
		pkg:     importguard.Module + "/api/rest",
		allowed: []string{importguard.Module + "/internal/server"},
		why:     "generated API types stay at the HTTP edge; the rest of the daemon uses its own types",
	},
	{
		pkg:     importguard.Module + "/api",
		allowed: []string{importguard.Module + "/internal/server"},
		why:     "the spec is served by the server and read by nothing else in production",
	},
	{
		pkg:     importguard.Module + "/internal/clickhouse",
		allowed: []string{importguard.Module + "/cmd/banoord"},
		why:     "only the entry point picks the source; the scorer takes a Source interface",
	},
}

func TestBoundaries(t *testing.T) {
	t.Parallel()

	packages := importguard.Packages(t, "./...")

	for _, b := range boundaries {
		for _, importer := range importguard.Importers(packages, b.pkg) {
			if !slices.Contains(b.allowed, importer) {
				t.Errorf("%s imports %s; %s", importer, b.pkg, b.why)
			}
		}
	}
}

// pkg/ holds decision packages that must stay free of the application, the
// generated API and transport.
func TestDecisionPackagesStayPure(t *testing.T) {
	t.Parallel()

	for _, p := range importguard.Packages(t, "./pkg/...") {
		for _, imp := range slices.Concat(p.Imports, p.TestImports, p.XTestImports) {
			if importguard.Within(imp, importguard.Module+"/internal") || importguard.Within(imp, importguard.Module+"/api") || imp == "net/http" {
				t.Errorf("%s imports %s; pkg/ must not depend on the application or transport", p.ImportPath, imp)
			}
		}
	}
}
