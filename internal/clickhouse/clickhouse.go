// Package clickhouse is the ClickHouse source: it runs signal and state
// queries and inserts state rows through the official Go client, over the
// native or the HTTP protocol.
package clickhouse

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Options configure a client.
type Options struct {
	// DSN is clickhouse://user@host:9000/db for the native protocol, or
	// http(s)://user@host:8123/db for HTTP.
	DSN string
	// Password, when set, overrides the DSN's.
	Password string
	// Timeout bounds dialling and each read.
	Timeout time.Duration
	// Settings are sent with every query, such as max_execution_time.
	Settings map[string]string
	// InsertSettings are sent with every insert, such as
	// distributed_foreground_insert for Distributed tables.
	InsertSettings map[string]string
}

// Client is a ClickHouse connection pool.
type Client struct {
	conn           driver.Conn
	insertSettings ch.Settings
}

func settings(m map[string]string) ch.Settings {
	s := ch.Settings{}
	for k, v := range m {
		s[k] = v
	}

	return s
}

// Open returns a client. It does not connect until the first query.
func Open(opts Options) (*Client, error) {
	o, err := ch.ParseDSN(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("clickhouse dsn: %w", err)
	}

	if opts.Password != "" {
		o.Auth.Password = opts.Password
	}

	if opts.Timeout > 0 {
		o.DialTimeout = opts.Timeout
		o.ReadTimeout = opts.Timeout
	}

	if o.Settings == nil {
		o.Settings = ch.Settings{}
	}

	for k, v := range opts.Settings {
		o.Settings[k] = v
	}

	conn, err := ch.Open(o)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}

	return &Client{conn: conn, insertSettings: settings(opts.InsertSettings)}, nil
}

// Close closes the pool.
func (c *Client) Close() error {
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("clickhouse close: %w", err)
	}

	return nil
}

// Select runs query with params bound to its {name:Type} placeholders, and
// calls row with each result row as column name to value; NULL is nil.
func (c *Client) Select(ctx context.Context, query string, params map[string]string, row func(map[string]any) error) error {
	rows, err := c.conn.Query(ch.Context(ctx, ch.WithParameters(params)), query)
	if err != nil {
		return fmt.Errorf("clickhouse query: %w", err)
	}

	defer func() { _ = rows.Close() }()

	names := rows.Columns()
	types := rows.ColumnTypes()

	for rows.Next() {
		dest := make([]any, len(types))
		for i, t := range types {
			dest[i] = reflect.New(t.ScanType()).Interface()
		}

		if err = rows.Scan(dest...); err != nil {
			return fmt.Errorf("clickhouse scan: %w", err)
		}

		values := make(map[string]any, len(names))
		for i, n := range names {
			values[n] = deref(reflect.ValueOf(dest[i]).Elem())
		}

		if err = row(values); err != nil {
			return err
		}
	}

	if err = rows.Err(); err != nil {
		return fmt.Errorf("clickhouse rows: %w", err)
	}

	return nil
}

// deref returns a Nullable column's value, or nil for NULL, the way other
// columns are returned.
func deref(v reflect.Value) any {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}

		v = v.Elem()
	}

	return v.Interface()
}

// Exec runs a statement that returns no rows, such as DDL.
func (c *Client) Exec(ctx context.Context, query string) error {
	if err := c.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("clickhouse exec: %w", err)
	}

	return nil
}

// Insert writes rows, one value per column, into table.
func (c *Client) Insert(ctx context.Context, table string, columns []string, rows [][]any) error {
	if len(rows) == 0 {
		return nil
	}

	ctx = ch.Context(ctx, ch.WithSettings(c.insertSettings))

	batch, err := c.conn.PrepareBatch(ctx, "INSERT INTO "+table+" ("+strings.Join(columns, ", ")+")")
	if err != nil {
		return fmt.Errorf("clickhouse insert %s: %w", table, err)
	}

	for _, r := range rows {
		if err = batch.Append(r...); err != nil {
			_ = batch.Abort()

			return fmt.Errorf("clickhouse insert %s: %w", table, err)
		}
	}

	if err = batch.Send(); err != nil {
		return fmt.Errorf("clickhouse insert %s: %w", table, err)
	}

	return nil
}
