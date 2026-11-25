// Command banoorctl checks the lists an operator maintains and prints the
// signing key's public half.
//
//	banoorctl validate -manual FILE [-allow-dir DIR] [-config FILE] [-max-ahead DURATION]
//	banoorctl pubkey -key FILE [-principal NAME [-namespace NS]]
//	banoorctl version
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ethpandaops/banoor/internal/config"
	"github.com/ethpandaops/banoor/internal/lists"
	"github.com/ethpandaops/banoor/pkg/manual"
	"github.com/ethpandaops/banoor/pkg/netaddr"
	"github.com/ethpandaops/banoor/pkg/sshsig"
)

// version is set at build time: -ldflags "-X main.version=...".
var version = "dev"

const usage = `banoorctl checks banoor's lists and keys.

Usage:
  banoorctl validate -manual FILE [-allow-dir DIR] [-config FILE] [-max-ahead DURATION]
  banoorctl pubkey -key FILE [-principal NAME [-namespace NS]]
  banoorctl version
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "banoorctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)

		return errors.New("no command")
	}

	switch cmd, rest := args[0], args[1:]; cmd {
	case "validate":
		return validate(rest, stdin, stdout, stderr)
	case "pubkey":
		return pubkey(rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)

		return nil
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)

		return nil
	default:
		fmt.Fprint(stderr, usage)

		return fmt.Errorf("unknown command %q", cmd)
	}
}

func validate(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manualFile := fs.String("manual", "", "manual list (JSON); - reads standard input")
	allowDir := fs.String("allow-dir", "", "directory of allowlist *.txt files")
	cfgPath := fs.String("config", "", "take the prefix limits from this configuration")
	maxAhead := fs.Duration("max-ahead", 365*24*time.Hour, "latest allowed expiry, from now")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return fmt.Errorf("flags: %w", err)
	}

	lim := netaddr.DefaultLimits

	if *cfgPath != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}

		lim = cfg.Limits
	}

	allow, err := lists.ReadAllowDir(*allowDir)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "allowlist: %d prefixes\n", allow.Len())

	if *manualFile == "" {
		return nil
	}

	data, err := readInput(*manualFile, stdin)
	if err != nil {
		return err
	}

	errs, warnings := manual.Validate(data, lim, netaddr.Union(netaddr.SpecialPurpose(), allow), time.Now(), *maxAhead)
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

func readInput(path string, stdin io.Reader) ([]byte, error) {
	var (
		data []byte
		err  error
	)

	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return nil, fmt.Errorf("manual list: %w", err)
	}

	return data, nil
}

func pubkey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "OpenSSH Ed25519 private key file")
	principal := fs.String("principal", "", "print an allowed_signers line for this principal")
	namespace := fs.String("namespace", "", "with -principal, restrict the line to this namespace")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return fmt.Errorf("flags: %w", err)
	}

	if *keyFile == "" {
		return errors.New("pubkey needs -key")
	}

	data, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	key, err := sshsig.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("%s: %w", *keyFile, err)
	}

	pub := sshsig.New(key, "").PublicKey()

	switch {
	case *principal == "":
		fmt.Fprintln(stdout, pub)
	case *namespace == "":
		fmt.Fprintf(stdout, "%s %s\n", *principal, pub)
	default:
		fmt.Fprintf(stdout, "%s namespaces=%q %s\n", *principal, *namespace, pub)
	}

	return nil
}
