// Package clickhouse is a small client for ClickHouse's HTTP interface,
// enough to run queries that return JSONEachRow and to insert rows.
package clickhouse

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options configure a client.
type Options struct {
	URL      string
	User     string
	Password string
	Timeout  time.Duration
	// Settings are sent with every query, such as max_execution_time.
	Settings map[string]string
	// InsertSettings are sent with every insert, such as
	// distributed_foreground_insert for Distributed tables.
	InsertSettings map[string]string
}

// Client talks to one ClickHouse HTTP endpoint.
type Client struct {
	base url.URL
	opts Options
	http *http.Client
}

// New returns a client.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("clickhouse url %q: want http or https", opts.URL)
	}
	return &Client{base: *u, opts: opts, http: &http.Client{Timeout: opts.Timeout}}, nil
}

func (c *Client) do(ctx context.Context, params url.Values, body io.Reader) (*http.Response, error) {
	u := c.base
	q := u.Query()
	for k, vs := range params {
		q[k] = vs
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return nil, err
	}
	if c.opts.User != "" {
		req.Header.Set("X-ClickHouse-User", c.opts.User)
		req.Header.Set("X-ClickHouse-Key", c.opts.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("clickhouse: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

// Select runs query and calls row with each JSON object it returns. Query
// parameters in params fill {name:Type} placeholders.
func (c *Client) Select(ctx context.Context, query string, params map[string]string, row func([]byte) error) error {
	v := url.Values{}
	for k, s := range c.opts.Settings {
		v.Set(k, s)
	}
	v.Set("default_format", "JSONEachRow")
	v.Set("output_format_json_quote_64bit_integers", "0")
	// Buffer the result so that an error mid-query is an HTTP error and not
	// a truncated body.
	v.Set("wait_end_of_query", "1")
	for k, s := range params {
		v.Set("param_"+k, s)
	}
	resp, err := c.do(ctx, v, strings.NewReader(query))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := row(line); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Insert writes rows, each one JSON object, into table.
func (c *Client) Insert(ctx context.Context, table string, rows [][]byte) error {
	if len(rows) == 0 {
		return nil
	}
	v := url.Values{}
	for k, s := range c.opts.InsertSettings {
		v.Set(k, s)
	}
	v.Set("query", "INSERT INTO "+table+" FORMAT JSONEachRow")
	v.Set("date_time_input_format", "best_effort")
	resp, err := c.do(ctx, v, bytes.NewReader(append(bytes.Join(rows, []byte("\n")), '\n')))
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}
