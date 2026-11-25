package main

import (
	"io"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	o, err := parse([]string{"-config", "c.json", "-listen", "0.0.0.0:9090", "-log-format", "json", "-log-level", "DEBUG"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if o.config != "c.json" || o.listen != "0.0.0.0:9090" || o.logFormat != "json" || o.logLevel.String() != "DEBUG" {
		t.Fatalf("options = %+v", o)
	}

	for _, args := range [][]string{{}, {"-config", "c.json", "-log-format", "xml"}, {"-nope"}} {
		if _, err = parse(args, io.Discard); err == nil {
			t.Errorf("parse(%q) succeeded", args)
		}
	}

	if _, err = parse([]string{"-version"}, io.Discard); err != nil {
		t.Errorf("-version needs no config: %v", err)
	}
}

func TestRunVersionAndHelp(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	if err := run([]string{"-version"}, &out, io.Discard); err != nil || strings.TrimSpace(out.String()) != "dev" {
		t.Fatalf("-version printed %q (%v)", out.String(), err)
	}

	if err := run([]string{"-h"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("-h: %v", err)
	}

	if err := run([]string{"-config", "/nonexistent/banoor.json"}, io.Discard, io.Discard); err == nil {
		t.Fatal("a missing configuration file started")
	}
}
