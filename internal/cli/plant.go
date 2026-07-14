// The plant, list and revoke subcommands: registry-side operations.
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/JaydenCJ/coalmine/internal/plant"
	"github.com/JaydenCJ/coalmine/internal/report"
	"github.com/JaydenCJ/coalmine/internal/store"
	"github.com/JaydenCJ/coalmine/internal/token"
)

func runPlant(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("plant", stderr)
	storePath := fs.String("store", DefaultStore, "canary registry file")
	label := fs.String("label", "", "human-readable name for this canary (default: its id)")
	explicit := fs.String("token", "", "use this token instead of generating one")
	template := fs.String("template", plant.TemplateRule, "marker template: rule, comment, bare, or a custom string containing {token}")
	at := fs.String("at", plant.AtEnd, "where to insert the marker: start or end")
	out := fs.String("o", "", "write the instrumented prompt here (default: stdout)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return usageExit(err)
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, "coalmine plant: at most one prompt file (or - for stdin)")
		return ExitUsage
	}

	// Resolve the prompt source.
	src := "-"
	if len(pos) == 1 {
		src = pos[0]
	}
	var promptBytes []byte
	if src == "-" {
		promptBytes, err = io.ReadAll(stdin)
	} else {
		promptBytes, err = os.ReadFile(src)
	}
	if err != nil {
		fmt.Fprintf(stderr, "coalmine plant: reading prompt: %v\n", err)
		return ExitRuntime
	}

	// Resolve the token.
	tok := *explicit
	if tok == "" {
		if tok, err = token.Generate(randReader); err != nil {
			fmt.Fprintf(stderr, "coalmine plant: %v\n", err)
			return ExitRuntime
		}
	} else if !token.Valid(tok) {
		fmt.Fprintf(stderr, "coalmine plant: %q is not a valid coalmine token (generate one with: coalmine gen)\n", tok)
		return ExitUsage
	}

	marker, err := plant.Render(*template, tok)
	if err != nil {
		fmt.Fprintf(stderr, "coalmine plant: %v\n", err)
		return ExitUsage
	}
	instrumented, err := plant.Embed(string(promptBytes), marker, *at)
	if err != nil {
		fmt.Fprintf(stderr, "coalmine plant: %v\n", err)
		return ExitUsage
	}

	// Register before writing output, so a half-planted prompt can never
	// exist without its registry entry.
	st, err := store.Load(*storePath)
	if err != nil {
		fmt.Fprintf(stderr, "coalmine plant: %v\n", err)
		return ExitRuntime
	}
	sum := sha256.Sum256([]byte(instrumented))
	c := store.Canary{
		Token:        tok,
		Label:        *label,
		Created:      now().Format(time.RFC3339),
		PromptSHA256: hex.EncodeToString(sum[:]),
		Status:       store.StatusActive,
	}
	if src != "-" {
		c.Source = src
	}
	if c.Label == "" {
		c.Label = store.IDFor(tok)
	}
	if err := st.Add(c); err != nil {
		fmt.Fprintf(stderr, "coalmine plant: %v\n", err)
		return ExitRuntime
	}
	if err := st.Save(); err != nil {
		fmt.Fprintf(stderr, "coalmine plant: %v\n", err)
		return ExitRuntime
	}

	if *out == "" {
		fmt.Fprint(stdout, instrumented)
	} else if err := os.WriteFile(*out, []byte(instrumented), 0o644); err != nil {
		fmt.Fprintf(stderr, "coalmine plant: writing %s: %v\n", *out, err)
		return ExitRuntime
	}
	fmt.Fprintf(stderr, "coalmine: planted canary %s (label %q) — registry %s\n",
		store.IDFor(tok), c.Label, *storePath)
	return ExitOK
}

func runList(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("list", stderr)
	storePath := fs.String("store", DefaultStore, "canary registry file")
	format := fs.String("format", "text", "output format: text or json")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return usageExit(err)
	}
	if len(pos) > 0 {
		fmt.Fprintln(stderr, "coalmine list: takes no arguments")
		return ExitUsage
	}
	st, err := store.Load(*storePath)
	if err != nil {
		fmt.Fprintf(stderr, "coalmine list: %v\n", err)
		return ExitRuntime
	}
	switch *format {
	case "text":
		report.ListText(stdout, st.Canaries)
	case "json":
		if err := report.ListJSON(stdout, st.Canaries); err != nil {
			fmt.Fprintf(stderr, "coalmine list: %v\n", err)
			return ExitRuntime
		}
	default:
		fmt.Fprintf(stderr, "coalmine list: unknown --format %q (want text or json)\n", *format)
		return ExitUsage
	}
	return ExitOK
}

func runRevoke(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("revoke", stderr)
	storePath := fs.String("store", DefaultStore, "canary registry file")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return usageExit(err)
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "coalmine revoke: exactly one canary id or label required")
		return ExitUsage
	}
	st, err := store.Load(*storePath)
	if err != nil {
		fmt.Fprintf(stderr, "coalmine revoke: %v\n", err)
		return ExitRuntime
	}
	n, err := st.Revoke(pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "coalmine revoke: %v\n", err)
		return ExitRuntime
	}
	if err := st.Save(); err != nil {
		fmt.Fprintf(stderr, "coalmine revoke: %v\n", err)
		return ExitRuntime
	}
	noun := "canaries"
	if n == 1 {
		noun = "canary"
	}
	fmt.Fprintf(stdout, "revoked %d %s matching %q\n", n, noun, pos[0])
	return ExitOK
}
