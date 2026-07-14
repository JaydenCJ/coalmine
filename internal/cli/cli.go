// Package cli implements the coalmine command-line interface. Run is
// invoked in-process by tests, so every command reads and writes only
// through the injected streams and returns an exit code instead of calling
// os.Exit.
package cli

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/JaydenCJ/coalmine/internal/token"
	"github.com/JaydenCJ/coalmine/internal/version"
)

// Exit codes, shared by every subcommand.
const (
	ExitOK      = 0 // success / clean scan
	ExitLeak    = 1 // scan found leaks (subject to --fail-on)
	ExitUsage   = 2 // bad flags or arguments
	ExitRuntime = 3 // I/O or environment failure
)

// DefaultStore is the registry file used when --store is not given.
const DefaultStore = "coalmine.json"

// randReader supplies token randomness; tests may swap it for a
// deterministic source.
var randReader io.Reader = rand.Reader

// now supplies timestamps; tests may pin it.
var now = func() time.Time { return time.Now().UTC() }

const usageText = `coalmine — plant canary tokens in system prompts, scan outputs for leaks

usage:
  coalmine <command> [flags] [args]

commands:
  plant    embed a canary token into a system prompt and register it
  scan     scan files, directories, or stdin for planted canaries
  list     list registered canaries
  revoke   mark a canary as revoked (skipped by future scans)
  gen      generate canary tokens without registering them
  version  print the coalmine version

run "coalmine <command> -h" for command flags.

exit codes: 0 ok/clean · 1 leaks found · 2 usage error · 3 runtime error
`

// Run dispatches argv (without the program name) and returns the process
// exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return ExitUsage
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "coalmine %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usageText)
		return ExitOK
	case "gen":
		return runGen(args[1:], stdout, stderr)
	case "plant":
		return runPlant(args[1:], stdin, stdout, stderr)
	case "scan":
		return runScan(args[1:], stdin, stdout, stderr)
	case "list":
		return runList(args[1:], stdout, stderr)
	case "revoke":
		return runRevoke(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "coalmine: unknown command %q\n\n", args[0])
		fmt.Fprint(stderr, usageText)
		return ExitUsage
	}
}

// newFlagSet builds a FlagSet that reports errors on stderr without
// exiting the process.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// usageExit maps a flag-parse error to an exit code: an explicit -h/--help
// request is success (the flag package already printed the flag reference),
// anything else is a usage error.
func usageExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	return ExitUsage
}

// parseFlags parses args with fs, allowing flags and positional arguments
// to interleave. The standard library stops flag parsing at the first
// positional, which would reject the documented invocation
// `coalmine plant --label x prompt.txt -o out.txt`. An explicit `--`
// still terminates flag parsing: everything after it is positional.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		// If parsing stopped at an explicit "--", the remainder is
		// positional verbatim — do not re-parse it for flags.
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func runGen(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("gen", stderr)
	count := fs.Int("count", 1, "how many tokens to generate")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return usageExit(err)
	}
	if *count < 1 {
		fmt.Fprintln(stderr, "coalmine gen: --count must be >= 1")
		return ExitUsage
	}
	if len(pos) > 0 {
		fmt.Fprintln(stderr, "coalmine gen: takes no arguments")
		return ExitUsage
	}
	for i := 0; i < *count; i++ {
		tok, err := token.Generate(randReader)
		if err != nil {
			fmt.Fprintf(stderr, "coalmine gen: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintln(stdout, tok)
	}
	return ExitOK
}
