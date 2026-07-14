// The scan subcommand: detection-side operations and the exit-code gate.
package cli

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/JaydenCJ/coalmine/internal/report"
	"github.com/JaydenCJ/coalmine/internal/scan"
	"github.com/JaydenCJ/coalmine/internal/store"
	"github.com/JaydenCJ/coalmine/internal/variant"
)

func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan", stderr)
	storePath := fs.String("store", DefaultStore, "canary registry file")
	format := fs.String("format", "text", "output format: text or json")
	minFragment := fs.Int("min-fragment", scan.DefaultMinFragment,
		fmt.Sprintf("minimum partial-leak length in token characters (>= %d, 0 disables)", scan.MinFragmentFloor))
	failOn := fs.String("fail-on", "any", "exit 1 when leaks of this confidence exist: any, high, never")
	all := fs.Bool("all", false, "also scan for revoked canaries")
	maxFileSize := fs.Int64("max-file-size", scan.DefaultMaxFileSize, "skip files larger than this many bytes")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return usageExit(err)
	}
	if len(pos) == 0 {
		fmt.Fprintln(stderr, "coalmine scan: at least one path required (or - for stdin)")
		return ExitUsage
	}
	if *minFragment != 0 && *minFragment < scan.MinFragmentFloor {
		fmt.Fprintf(stderr, "coalmine scan: --min-fragment must be 0 or >= %d (shorter fragments match by coincidence)\n", scan.MinFragmentFloor)
		return ExitUsage
	}
	switch *failOn {
	case "any", "high", "never":
	default:
		fmt.Fprintf(stderr, "coalmine scan: unknown --fail-on %q (want any, high or never)\n", *failOn)
		return ExitUsage
	}
	switch *format {
	case "text", "json":
	default:
		fmt.Fprintf(stderr, "coalmine scan: unknown --format %q (want text or json)\n", *format)
		return ExitUsage
	}

	st, err := store.Load(*storePath)
	if err != nil {
		fmt.Fprintf(stderr, "coalmine scan: %v\n", err)
		return ExitRuntime
	}
	canaries := st.Active()
	if *all {
		canaries = st.Canaries
	}
	if len(canaries) == 0 {
		fmt.Fprintf(stderr, "coalmine scan: no active canaries in %s (plant one first: coalmine plant)\n", *storePath)
		return ExitRuntime
	}

	fsc := &scan.FileScanner{
		Engine:      scan.New(canaries, *minFragment),
		MaxFileSize: *maxFileSize,
		SkipPaths:   map[string]bool{},
	}
	if abs, err := filepath.Abs(*storePath); err == nil {
		fsc.SkipPaths[abs] = true
	}
	res, err := fsc.ScanPaths(pos, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "coalmine scan: %v\n", err)
		return ExitRuntime
	}

	switch *format {
	case "text":
		report.ScanText(stdout, res)
	case "json":
		if err := report.ScanJSON(stdout, res); err != nil {
			fmt.Fprintf(stderr, "coalmine scan: %v\n", err)
			return ExitRuntime
		}
	}
	return gate(res, *failOn)
}

// gate maps a scan result and --fail-on policy to the process exit code.
func gate(res scan.Result, failOn string) int {
	switch failOn {
	case "never":
		return ExitOK
	case "high":
		for _, f := range res.Findings {
			if f.Confidence == variant.High {
				return ExitLeak
			}
		}
		return ExitOK
	default: // any
		if res.Clean() {
			return ExitOK
		}
		return ExitLeak
	}
}
