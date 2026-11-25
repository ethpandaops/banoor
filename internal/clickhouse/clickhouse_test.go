package clickhouse

import (
	"os"
	"testing"
)

// TestSelectNullable reads Nullable columns the way other columns are read.
// It is skipped unless BANOOR_TEST_CLICKHOUSE_DSN is set.
func TestSelectNullable(t *testing.T) {
	t.Parallel()

	dsn := os.Getenv("BANOOR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("BANOOR_TEST_CLICKHOUSE_DSN is not set")
	}

	c, err := Open(Options{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = c.Close() })

	var got map[string]any

	err = c.Select(t.Context(), `SELECT toNullable('198.51.100.1') AS address, toNullable(toUInt64(5)) AS attempts,
		CAST(NULL AS Nullable(String)) AS missing, 'plain' AS plain`, nil, func(row map[string]any) error {
		got = row

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if got["address"] != "198.51.100.1" || got["attempts"] != uint64(5) || got["missing"] != nil || got["plain"] != "plain" {
		t.Fatalf("row = %#v", got)
	}
}
