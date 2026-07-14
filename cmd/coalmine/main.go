// Command coalmine plants canary tokens in system prompts and scans
// outputs and logs for extraction leaks. See README.md for usage.
package main

import (
	"os"

	"github.com/JaydenCJ/coalmine/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
