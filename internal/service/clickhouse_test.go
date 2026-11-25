package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethpandaops/banoor/internal/clickhouse"
	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/publish"
	"github.com/ethpandaops/banoor/internal/sshsig"
)

// TestClickHouse runs the example schema and configuration against a real
// server. It is skipped unless BANOOR_TEST_CLICKHOUSE_URL is set.
func TestClickHouse(t *testing.T) {
	url := os.Getenv("BANOOR_TEST_CLICKHOUSE_URL")
	if url == "" {
		t.Skip("BANOOR_TEST_CLICKHOUSE_URL is not set")
	}
	ctx := context.Background()
	ch, err := clickhouse.New(clickhouse.Options{
		URL: url, User: os.Getenv("BANOOR_TEST_CLICKHOUSE_USER"), Password: os.Getenv("BANOOR_TEST_CLICKHOUSE_PASSWORD"),
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(q string) {
		t.Helper()
		if err := ch.Select(ctx, q, nil, func([]byte) error { return nil }); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	db := "banoor_test_" + hex.EncodeToString(suffix)

	schema, err := os.ReadFile("../../examples/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	var stmt strings.Builder
	for _, line := range strings.Split(string(schema), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		stmt.WriteString(line + "\n")
	}
	for _, q := range strings.Split(strings.ReplaceAll(stmt.String(), "banoor.", db+"."), ";") {
		if q = strings.TrimSpace(q); q != "" {
			exec(strings.Replace(q, "DATABASE IF NOT EXISTS banoor", "DATABASE IF NOT EXISTS "+db, 1))
		}
	}
	t.Cleanup(func() { exec("DROP DATABASE IF EXISTS " + db) })

	exec("INSERT INTO " + db + `.ssh_failures VALUES
		(now() - INTERVAL 10 MINUTE, 'host-a', 'invalid_user', '198.51.100.1', 60),
		(now() - INTERVAL 10 MINUTE, 'host-a', 'invalid_user', '198.51.100.2', 25),
		(now() - INTERVAL 20 MINUTE, 'host-b', 'not_allowed', '198.51.100.2', 30),
		(now() - INTERVAL 10 MINUTE, 'host-b', 'penalty_drop', '198.51.100.3', 1000),
		(now() - INTERVAL 2 DAY, 'host-a', 'invalid_user', '198.51.100.4', 500)`)

	// The example configuration, pointed at the test database.
	dir := t.TempDir()
	example, err := os.ReadFile("../../examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(example), "banoor.", db+".")), &raw); err != nil {
		t.Fatal(err)
	}
	raw["source"].(map[string]any)["url"] = url
	raw["source"].(map[string]any)["passwordFile"] = ""
	raw["source"].(map[string]any)["user"] = ""
	raw["allow"] = map[string]any{"dir": ""}
	raw["manualFile"] = ""
	b, _ := json.Marshal(raw)
	cfgFile := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Source.User = os.Getenv("BANOOR_TEST_CLICKHOUSE_USER")
	src, _ := clickhouse.New(clickhouse.Options{
		URL: url, User: cfg.Source.User, Password: os.Getenv("BANOOR_TEST_CLICKHOUSE_PASSWORD"), Timeout: 30 * time.Second,
	})
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	newService := func() *Service {
		return New(cfg, src, sshsig.New(key, "example-banlist"), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	}
	payload := func(s *Service) publish.Payload {
		t.Helper()
		cur := s.pub.Load().Current()
		var env publish.Envelope
		if err := json.Unmarshal(cur.Body, &env); err != nil {
			t.Fatal(err)
		}
		var p publish.Payload
		raw, _ := base64.StdEncoding.DecodeString(env.Payload)
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	svc := newService()
	if err := svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	first := payload(svc)
	if got, want := cidrs(first), []string{"198.51.100.1/32", "198.51.100.2/32"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	if first.Mode != "shadow" {
		t.Fatalf("mode = %s, want the default", first.Mode)
	}
	count := func(table string) int {
		t.Helper()
		n := 0
		if err := ch.Select(ctx, "SELECT count() AS n FROM "+db+"."+table, nil, func(b []byte) error {
			var r struct{ N int }
			err := json.Unmarshal(b, &r)
			n = r.N
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if d, p := count("decisions"), count("publishes"); d != 2 || p != 1 {
		t.Fatalf("recorded %d decisions and %d publishes", d, p)
	}

	exec("INSERT INTO " + db + ".control (Mode, Reason) VALUES ('empty', 'integration test')")
	time.Sleep(1100 * time.Millisecond) // a new generation needs a new second
	if err := svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if p := payload(svc); p.Mode != "empty" || len(p.Entries) != 0 || p.PreviousGeneration != first.Generation {
		t.Fatalf("after the kill switch: %+v", p)
	}

	exec("INSERT INTO " + db + ".control (Mode, Reason) VALUES ('enforce', 'integration test')")
	restarted := newService()
	if err := restarted.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if p := payload(restarted); !slices.Equal(cidrs(p), cidrs(first)) || p.Mode != "enforce" {
		t.Fatalf("after a restart: %+v", p)
	}
	if d := count("decisions"); d != 2 {
		t.Fatalf("a restart recorded the restored bans again: %d decisions", d)
	}
}
