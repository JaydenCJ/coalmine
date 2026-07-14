// Tests for the file walker: deterministic directory traversal, binary and
// size skipping, store self-exclusion, stdin, and error propagation.
package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JaydenCJ/coalmine/internal/store"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fileScanner(t *testing.T) *FileScanner {
	t.Helper()
	return &FileScanner{
		Engine: New([]store.Canary{{
			ID: store.IDFor(tok), Token: tok, Label: "prod-bot", Status: store.StatusActive,
		}}, DefaultMinFragment),
		SkipPaths: map[string]bool{},
	}
}

func TestScanPathsWalksDirectoryRecursivelyInLexicalOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "z.log"), "leak "+tok+"\n")
	writeFile(t, filepath.Join(dir, "a.log"), "clean\n")
	writeFile(t, filepath.Join(dir, "sub", "b.log"), "leak "+tok+"\n")
	res, err := fileScanner(t).ScanPaths([]string{dir}, strings.NewReader(""))
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if res.FilesScanned != 3 || len(res.Findings) != 2 {
		t.Fatalf("scanned=%d findings=%d", res.FilesScanned, len(res.Findings))
	}
	if !strings.HasSuffix(res.Findings[0].File, "sub/b.log") ||
		!strings.HasSuffix(res.Findings[1].File, "z.log") {
		t.Fatalf("lexical order violated: %s before %s",
			res.Findings[0].File, res.Findings[1].File)
	}
}

func TestScanPathsSkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "blob.bin"), "leak\x00"+tok+"\n")
	res, err := fileScanner(t).ScanPaths([]string{dir}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesSkipped != 1 || res.FilesScanned != 0 || len(res.Findings) != 0 {
		t.Fatalf("binary not skipped: %+v", res)
	}
}

func TestScanPathsSkipsOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "big.log"), strings.Repeat("x", 100)+tok+"\n")
	fs := fileScanner(t)
	fs.MaxFileSize = 50
	res, err := fs.ScanPaths([]string{dir}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesSkipped != 1 || len(res.Findings) != 0 {
		t.Fatalf("oversized file not skipped: %+v", res)
	}
}

func TestScanPathsSkipsTheCanaryStoreItself(t *testing.T) {
	// The registry contains every token by construction; scanning a tree
	// that includes it must not self-flag.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "coalmine.json")
	writeFile(t, storePath, `{"token": "`+tok+`"}`)
	writeFile(t, filepath.Join(dir, "app.log"), "clean\n")
	fs := fileScanner(t)
	abs, _ := filepath.Abs(storePath)
	fs.SkipPaths[abs] = true
	res, err := fs.ScanPaths([]string{dir}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("store file self-flagged: %+v", res.Findings)
	}
	if res.FilesSkipped != 1 {
		t.Fatalf("store not counted as skipped: %+v", res)
	}
}

func TestScanPathsSkipsDotGitDirectories(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "objects", "pack.idx"), tok+"\n")
	writeFile(t, filepath.Join(dir, "app.log"), "clean\n")
	res, err := fileScanner(t).ScanPaths([]string{dir}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.FilesScanned != 1 {
		t.Fatalf(".git not skipped: %+v", res)
	}
}

func TestScanPathsReadsStdinAsDash(t *testing.T) {
	res, err := fileScanner(t).ScanPaths([]string{"-"}, strings.NewReader("model said "+tok+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].File != StdinName {
		t.Fatalf("stdin scan wrong: %+v", res)
	}
}

func TestScanPathsErrorsOnMissingPath(t *testing.T) {
	_, err := fileScanner(t).ScanPaths([]string{filepath.Join(t.TempDir(), "nope")}, strings.NewReader(""))
	if err == nil {
		t.Fatal("missing path should error")
	}
}

func TestResultHelpers(t *testing.T) {
	res := Result{Findings: []Finding{{File: "a"}, {File: "a"}, {File: "b"}}}
	if res.Clean() {
		t.Fatal("Clean() true with findings")
	}
	if res.FilesAffected() != 2 {
		t.Fatalf("FilesAffected = %d, want 2", res.FilesAffected())
	}
	if !(Result{}).Clean() {
		t.Fatal("empty result should be clean")
	}
}
