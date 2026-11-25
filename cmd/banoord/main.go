// Command banoord scores network sources from configurable queries and
// serves a signed ban list.
//
//	banoord -config FILE [flags]
//	banoord -version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ethpandaops/banoor/internal/clickhouse"
	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/metrics"
	"github.com/ethpandaops/banoor/internal/scorer"
	"github.com/ethpandaops/banoor/internal/server"
	"github.com/ethpandaops/banoor/pkg/sshsig"
)

// version is set at build time: -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "banoord:", err)
		os.Exit(1)
	}
}

type options struct {
	config    string
	listen    string
	logFormat string
	logLevel  slog.Level
	version   bool
}

// errHelp is returned when -h or -help was given; usage has been printed.
var errHelp = errors.New("help requested")

func parse(args []string, stderr io.Writer) (options, error) {
	o := options{logLevel: slog.LevelInfo}

	fs := flag.NewFlagSet("banoord", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.config, "config", "", "configuration file (JSON)")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8080", "HTTP listen address")
	fs.StringVar(&o.logFormat, "log-format", "text", "log format: text or json")
	fs.TextVar(&o.logLevel, "log-level", o.logLevel, "log level: DEBUG, INFO, WARN or ERROR")
	fs.BoolVar(&o.version, "version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return o, errHelp
		}

		return o, fmt.Errorf("flags: %w", err)
	}

	if o.logFormat != "text" && o.logFormat != "json" {
		return o, fmt.Errorf("-log-format %q: text or json", o.logFormat)
	}

	if o.config == "" && !o.version {
		return o, errors.New("-config is required")
	}

	return o, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	o, err := parse(args, stderr)
	if errors.Is(err, errHelp) {
		return nil
	}

	if err != nil {
		return err
	}

	if o.version {
		fmt.Fprintln(stdout, version)

		return nil
	}

	cfg, err := config.Load(o.config)
	if err != nil {
		return err
	}

	signer, err := loadSigner(cfg.Signing.KeyFile, cfg.Signing.Namespace)
	if err != nil {
		return err
	}

	src, err := openSource(cfg.Source)
	if err != nil {
		return err
	}

	defer func() { _ = src.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := newLogger(stderr, o).With("version", version)
	reg := metrics.New()
	sc := scorer.New(log, cfg, src, signer, reg, nil)

	srvCfg := server.Config{Listen: o.listen, Version: version, FetchUserHeader: cfg.FetchUserHeader}
	if cfg.Allow.Fetchers != nil {
		srvCfg.FetchAddressHeader = cfg.Allow.Fetchers.AddressHeader
	}

	srv, err := server.New(log, srvCfg, sc, reg)
	if err != nil {
		return err
	}

	log.InfoContext(ctx, "starting", "public_key", signer.PublicKey(), "namespace", cfg.Signing.Namespace)

	done := make(chan struct{})

	go func() {
		defer close(done)
		sc.Run(ctx)
	}()

	err = srv.Run(ctx)

	stop()
	<-done

	return err
}

func loadSigner(keyFile, namespace string) (*sshsig.Signer, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	key, err := sshsig.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}

	return sshsig.New(key, namespace), nil
}

func openSource(src config.Source) (*clickhouse.Client, error) {
	var password string

	if src.PasswordFile != "" {
		b, err := os.ReadFile(src.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("source password: %w", err)
		}

		password = strings.TrimSpace(string(b))
	}

	return clickhouse.Open(clickhouse.Options{
		DSN:            src.DSN,
		Password:       password,
		Timeout:        src.Timeout.Duration,
		Settings:       src.Settings,
		InsertSettings: src.InsertSettings,
	})
}

// newLogger builds the process logger: text for a terminal, JSON for a log
// collector.
func newLogger(w io.Writer, o options) *slog.Logger {
	opts := &slog.HandlerOptions{Level: o.logLevel}
	if o.logFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}

	return slog.New(slog.NewTextHandler(w, opts))
}
