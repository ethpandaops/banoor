// Command banoor scores network sources from configurable queries and serves
// a signed ban list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethpandaops/banoor/internal/clickhouse"
	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/lists"
	"github.com/ethpandaops/banoor/internal/netaddr"
	"github.com/ethpandaops/banoor/internal/service"
	"github.com/ethpandaops/banoor/internal/sshsig"
)

var version = "dev"

const usage = `banoor scores network sources and serves a signed ban list.

Usage:
  banoor serve -config FILE      run the scorer and serve the list
  banoor validate [flags]        check a manual list and allowlist files
  banoor pubkey -key FILE        print the signing key's public half
  banoor version                 print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "serve":
		err = serve(args)
	case "validate":
		err = validate(args, os.Stdin, os.Stdout)
	case "pubkey":
		err = pubkey(args, os.Stdout)
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "banoor:", err)
		os.Exit(1)
	}
}

func loadSigner(keyFile, namespace string) (*sshsig.Signer, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := sshsig.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	return sshsig.New(key, namespace), nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "", "configuration file (JSON)")
	_ = fs.Parse(args)
	if *path == "" {
		return errors.New("serve needs -config")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	signer, err := loadSigner(cfg.Signing.KeyFile, cfg.Signing.Namespace)
	if err != nil {
		return err
	}
	var password string
	if cfg.Source.PasswordFile != "" {
		b, err := os.ReadFile(cfg.Source.PasswordFile)
		if err != nil {
			return err
		}
		password = strings.TrimSpace(string(b))
	}
	src, err := clickhouse.New(clickhouse.Options{
		URL:            cfg.Source.URL,
		User:           cfg.Source.User,
		Password:       password,
		Timeout:        cfg.Source.Timeout.Duration,
		Settings:       cfg.Source.Settings,
		InsertSettings: cfg.Source.InsertSettings,
	})
	if err != nil {
		return err
	}

	svc := service.New(cfg, src, signer, log, version)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("started", "version", version, "listen", cfg.Server.Listen, "path", cfg.Server.Path, "public_key", signer.PublicKey())

	done := make(chan struct{})
	go func() {
		svc.Run(ctx)
		close(done)
	}()
	select {
	case err := <-errc:
		stop()
		<-done
		return err
	case <-ctx.Done():
	}
	<-done
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func validate(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	manual := fs.String("manual", "", "manual list (JSON); - reads standard input")
	allowDir := fs.String("allow-dir", "", "directory of allowlist *.txt files")
	cfgPath := fs.String("config", "", "take the prefix limits from this configuration")
	maxAhead := fs.Duration("max-ahead", 365*24*time.Hour, "latest allowed expiry, from now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	lim := netaddr.DefaultLimits
	if *cfgPath != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		lim = cfg.Limits
	}
	allow, err := lists.LoadAllowDir(*allowDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "allowlist: %d prefixes\n", allow.Len())
	if *manual == "" {
		return nil
	}
	var data []byte
	if *manual == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(*manual)
	}
	if err != nil {
		return err
	}
	errs, warnings := lists.Validate(data, lim, netaddr.Union(netaddr.SpecialPurpose(), allow), time.Now(), *maxAhead)
	for _, w := range warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	for _, e := range errs {
		fmt.Fprintln(stdout, "error:", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("the manual list has %d error(s)", len(errs))
	}
	fmt.Fprintln(stdout, "manual list: ok")
	return nil
}

func pubkey(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	keyFile := fs.String("key", "", "OpenSSH Ed25519 private key file")
	principal := fs.String("principal", "", "print an allowed_signers line for this principal")
	namespace := fs.String("namespace", "", "with -principal, restrict the line to this namespace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("pubkey needs -key")
	}
	s, err := loadSigner(*keyFile, "")
	if err != nil {
		return err
	}
	switch {
	case *principal == "":
		fmt.Fprintln(stdout, s.PublicKey())
	case *namespace == "":
		fmt.Fprintf(stdout, "%s %s\n", *principal, s.PublicKey())
	default:
		fmt.Fprintf(stdout, "%s namespaces=%q %s\n", *principal, *namespace, s.PublicKey())
	}
	return nil
}
