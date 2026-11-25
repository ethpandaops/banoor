package clickhouse

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSelect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ClickHouse-User") != "reader" || r.Header.Get("X-ClickHouse-Key") != "secret" {
			http.Error(w, "Code: 516. Authentication failed", http.StatusUnauthorized)
			return
		}
		q := r.URL.Query()
		if q.Get("default_format") != "JSONEachRow" || q.Get("param_window") != "86400" || q.Get("max_execution_time") != "10" {
			http.Error(w, "unexpected parameters: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "SELECT 1" {
			http.Error(w, "unexpected query: "+string(body), http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "{\"a\":1}\n\n{\"a\":2}\n")
	}))
	defer srv.Close()

	c, err := New(Options{URL: srv.URL, User: "reader", Password: "secret", Timeout: time.Second, Settings: map[string]string{"max_execution_time": "10"}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	err = c.Select(context.Background(), "SELECT 1", map[string]string{"window": "86400"}, func(b []byte) error {
		got = append(got, string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != `{"a":1},{"a":2}` {
		t.Fatalf("rows = %v", got)
	}

	bad, _ := New(Options{URL: srv.URL, User: "reader", Password: "wrong", Timeout: time.Second})
	err = bad.Select(context.Background(), "SELECT 1", nil, func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "Authentication failed") {
		t.Fatalf("want the server's error, got %v", err)
	}
}

func TestInsert(t *testing.T) {
	var gotQuery, gotBody, gotSetting string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		gotSetting = r.URL.Query().Get("distributed_foreground_insert")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer srv.Close()
	c, _ := New(Options{URL: srv.URL, Timeout: time.Second, InsertSettings: map[string]string{"distributed_foreground_insert": "1"}})
	if err := c.Insert(context.Background(), "state.decisions", [][]byte{[]byte(`{"a":1}`), []byte(`{"a":2}`)}); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "INSERT INTO state.decisions FORMAT JSONEachRow" || gotBody != "{\"a\":1}\n{\"a\":2}\n" || gotSetting != "1" {
		t.Fatalf("query %q, body %q, setting %q", gotQuery, gotBody, gotSetting)
	}
}

func TestNewRejectsOtherSchemes(t *testing.T) {
	if _, err := New(Options{URL: "tcp://localhost:9000"}); err == nil {
		t.Fatal("accepted a non-HTTP URL")
	}
}
