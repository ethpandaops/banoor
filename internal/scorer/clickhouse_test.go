package scorer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethpandaops/banoor/internal/clickhouse"
	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/metrics"
	"github.com/ethpandaops/banoor/internal/publish"
	"github.com/ethpandaops/banoor/pkg/sshsig"
)

// TestClickHouse runs the example schema and configuration against a real
// server, over the client the daemon uses. It is skipped unless
// BANOOR_TEST_CLICKHOUSE_DSN is set, for example to
// clickhouse://default@127.0.0.1:9000.
func TestClickHouse(t *testing.T) {
	t.Parallel()

	ch, db := testDatabase(t)
	manualFile := filepath.Join(t.TempDir(), "manual.json")

	err := os.WriteFile(manualFile, []byte(`{"entries": [{"action": "ban", "cidr": "203.0.113.0/24", "expires": "2099-01-01T00:00:00Z", "reason": "range", "by": "alice"}]}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	cfg := exampleConfig(t, db, os.Getenv("BANOOR_TEST_CLICKHOUSE_DSN"), manualFile)
	_, key, _ := ed25519.GenerateKey(rand.Reader)

	newScorer := func() *Scorer {
		return New(slog.New(slog.DiscardHandler), cfg, ch, sshsig.New(key, "example-banlist"), metrics.New(), nil)
	}

	// Recorded before this scorer ran: the manual ban, longer ago than any
	// ban lookback, and two generations, the higher one written first and
	// holding .1.
	execSQL(t, ch, "INSERT INTO "+db+`.decisions (Time, Generation, Action, Cidr, Expires, Mode, Reason) VALUES
		(now64(3) - INTERVAL 60 DAY, 0, 'manual_ban', '203.0.113.0/24', toDateTime('2099-01-01 00:00:00', 'UTC'), 'shadow', 'range')`)
	execSQL(t, ch, "INSERT INTO "+db+`.publishes (Time, Generation, Cidrs) VALUES
		(now64(3) - INTERVAL 2 HOUR, 4000000000, ['198.51.100.1/32']), (now64(3) - INTERVAL 1 HOUR, 5, [])`)

	sc := newScorer()
	sc.Seen("host-b", "198.51.100.5") // would be banned; fetched the list
	runOnce(t, sc)

	first := decodeCurrent(t, sc.Current())
	if got, want := cidrs(first), []string{"198.51.100.1/32", "198.51.100.2/32", "203.0.113.0/24"}; !slices.Equal(got, want) || first.Mode != "shadow" {
		t.Fatalf("entries = %v in %s, want %v in the default mode", got, first.Mode, want)
	}

	if first.PreviousGeneration != 4000000000 || first.Generation != 4000000001 {
		t.Fatalf("generation %d follows %d, want 4000000001 after the highest recorded", first.Generation, first.PreviousGeneration)
	}

	// Two bans and .5's suppression, but not the manual ban again; one
	// generation, with its prefixes, adding two to what consumers held; one
	// fetcher.
	if d, f := countRows(t, ch, db+".decisions"), countRows(t, ch, db+".fetchers"); d != 4 || f != 1 {
		t.Fatalf("decisions %d, fetchers %d", d, f)
	}

	if n := countRows(t, ch, db+".publishes WHERE Generation = 4000000001 AND Added = 2 AND length(Cidrs) = 3"); n != 1 {
		t.Fatal("the generation was not recorded with its prefixes and its additions over the last published list")
	}

	execSQL(t, ch, "INSERT INTO "+db+".control (Mode, Reason) VALUES ('empty', 'integration test')")
	runOnce(t, sc)

	empty := decodeCurrent(t, sc.Current())
	if empty.Mode != "empty" || len(empty.Entries) != 0 || empty.PreviousGeneration != first.Generation {
		t.Fatalf("after the kill switch: %+v", empty)
	}

	execSQL(t, ch, "INSERT INTO "+db+".control (Mode, Reason) VALUES ('enforce', 'integration test')")

	restarted := newScorer()
	runOnce(t, restarted)

	after := decodeCurrent(t, restarted.Current())
	if !slices.Equal(cidrs(after), cidrs(first)) || after.Mode != "enforce" || after.PreviousGeneration != empty.Generation {
		t.Fatalf("after a restart: %+v, previous %d, want to follow %d", after, after.PreviousGeneration, empty.Generation)
	}

	if d := countRows(t, ch, db+".decisions WHERE Action != 'suppressed'"); d != 3 {
		t.Fatalf("a restart recorded bans or manual entries again: %d decisions", d)
	}
}

// testDatabase creates a database with the example schema and test rows,
// dropped when the test ends.
func testDatabase(t *testing.T) (*clickhouse.Client, string) {
	t.Helper()

	dsn := os.Getenv("BANOOR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("BANOOR_TEST_CLICKHOUSE_DSN is not set")
	}

	ch, err := clickhouse.Open(clickhouse.Options{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	db := "banoor_test_" + hex.EncodeToString(suffix)

	applySchema(t, ch, db)
	t.Cleanup(func() {
		execSQL(t, ch, "DROP DATABASE IF EXISTS "+db)
		_ = ch.Close()
	})

	execSQL(t, ch, "INSERT INTO "+db+`.ssh_failures VALUES
		(now() - INTERVAL 10 MINUTE, 'host-a', 'invalid_user', '198.51.100.1', 60),
		(now() - INTERVAL 10 MINUTE, 'host-a', 'invalid_user', '198.51.100.2', 25),
		(now() - INTERVAL 20 MINUTE, 'host-b', 'not_allowed', '198.51.100.2', 30),
		(now() - INTERVAL 10 MINUTE, 'host-b', 'penalty_drop', '198.51.100.3', 1000),
		(now() - INTERVAL 10 MINUTE, 'host-b', 'invalid_user', '198.51.100.5', 90),
		(now() - INTERVAL 2 DAY, 'host-a', 'invalid_user', '198.51.100.4', 500)`)

	return ch, db
}

func runOnce(t *testing.T, sc *Scorer) {
	t.Helper()

	if err := sc.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// execSQL runs a statement; it also works in Cleanup, after t.Context ends.
func execSQL(t *testing.T, ch *clickhouse.Client, q string) {
	t.Helper()

	if err := ch.Exec(context.WithoutCancel(t.Context()), q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func countRows(t *testing.T, ch *clickhouse.Client, table string) int {
	t.Helper()

	n := 0

	err := ch.Select(t.Context(), "SELECT count() AS n FROM "+table, nil, func(r map[string]any) error {
		n = int(integer(r["n"]))

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return n
}

func applySchema(t *testing.T, ch *clickhouse.Client, db string) {
	t.Helper()

	schema, err := os.ReadFile("../../examples/schema.sql")
	if err != nil {
		t.Fatal(err)
	}

	var stmt strings.Builder

	for line := range strings.SplitSeq(string(schema), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			stmt.WriteString(line + "\n")
		}
	}

	for q := range strings.SplitSeq(strings.ReplaceAll(stmt.String(), "banoor.", db+"."), ";") {
		if q = strings.TrimSpace(q); q != "" {
			execSQL(t, ch, strings.Replace(q, "DATABASE IF NOT EXISTS banoor", "DATABASE IF NOT EXISTS "+db, 1))
		}
	}
}

// exampleConfig is examples/config.json pointed at the test database.
func exampleConfig(t *testing.T, db, dsn, manualFile string) *config.Config {
	t.Helper()

	example, err := os.ReadFile("../../examples/config.json")
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err = json.Unmarshal([]byte(strings.ReplaceAll(string(example), "banoor.", db+".")), &raw); err != nil {
		t.Fatal(err)
	}

	raw["source"] = map[string]any{"type": "clickhouse", "dsn": dsn}

	if allow, ok := raw["allow"].(map[string]any); ok {
		delete(allow, "dir")
	}
	raw["manualFile"] = manualFile

	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	return cfg
}

func decodeCurrent(t *testing.T, c *publish.Current) publish.Payload {
	t.Helper()

	if c == nil {
		t.Fatal("nothing is served")
	}

	raw, err := base64.StdEncoding.DecodeString(c.Payload)
	if err != nil {
		t.Fatal(err)
	}

	var p publish.Payload
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}

	return p
}
