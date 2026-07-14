// File and directory walking for the scanner: deterministic order, binary
// sniffing, size caps, and self-exclusion of the canary store (which
// contains every token by definition and must never flag itself).
package scan

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMaxFileSize caps how large a file the scanner will read (10 MiB).
const DefaultMaxFileSize = 10 << 20

// StdinName is the file label used for findings read from standard input.
const StdinName = "<stdin>"

// Result aggregates one scan run.
type Result struct {
	FilesScanned int
	FilesSkipped int
	Findings     []Finding
}

// Clean reports whether the run found nothing.
func (r Result) Clean() bool { return len(r.Findings) == 0 }

// FilesAffected counts distinct files with at least one finding.
func (r Result) FilesAffected() int {
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.File] = true
	}
	return len(seen)
}

// FileScanner walks paths and feeds their contents to an Engine.
type FileScanner struct {
	Engine      *Engine
	MaxFileSize int64
	// SkipPaths holds absolute paths to exclude — the canary store itself,
	// so a scan over the repo root does not report its own registry.
	SkipPaths map[string]bool
}

// ScanPaths scans each path (file, directory, or "-" for stdin) and
// returns the merged result. Directories are walked in lexical order and
// ".git" directories are skipped, so results are deterministic.
func (fsc *FileScanner) ScanPaths(paths []string, stdin io.Reader) (Result, error) {
	var res Result
	maxSize := fsc.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	for _, p := range paths {
		if p == "-" {
			data, err := io.ReadAll(io.LimitReader(stdin, maxSize+1))
			if err != nil {
				return res, fmt.Errorf("scan: reading stdin: %w", err)
			}
			if int64(len(data)) > maxSize {
				return res, fmt.Errorf("scan: stdin exceeds --max-file-size (%d bytes)", maxSize)
			}
			res.FilesScanned++
			res.Findings = append(res.Findings, fsc.Engine.ScanText(StdinName, string(data))...)
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return res, fmt.Errorf("scan: %w", err)
		}
		if info.IsDir() {
			if err := fsc.walkDir(p, maxSize, &res); err != nil {
				return res, err
			}
			continue
		}
		if err := fsc.scanFile(p, info.Size(), maxSize, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (fsc *FileScanner) walkDir(root string, maxSize int64, res *Result) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		return fsc.scanFile(path, info.Size(), maxSize, res)
	})
}

func (fsc *FileScanner) scanFile(path string, size, maxSize int64, res *Result) error {
	if abs, err := filepath.Abs(path); err == nil && fsc.SkipPaths[abs] {
		res.FilesSkipped++
		return nil
	}
	if size > maxSize {
		res.FilesSkipped++
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if isBinary(data) {
		res.FilesSkipped++
		return nil
	}
	res.FilesScanned++
	res.Findings = append(res.Findings, fsc.Engine.ScanText(filepath.ToSlash(path), string(data))...)
	return nil
}

// binarySniffLen is how many leading bytes are checked for NUL.
const binarySniffLen = 8192

// isBinary uses the same heuristic as grep: a NUL byte near the start
// means not text.
func isBinary(data []byte) bool {
	n := len(data)
	if n > binarySniffLen {
		n = binarySniffLen
	}
	return strings.IndexByte(string(data[:n]), 0) >= 0
}
