// Package store persists planted canaries in a small, human-readable JSON
// file (coalmine.json by default). The file is the single source of truth
// the scanner reads; it lives next to your prompts, diffs cleanly, and is
// written atomically with 0600 permissions because it contains the very
// secrets the scanner hunts for.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/JaydenCJ/coalmine/internal/token"
)

// Canary statuses.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// Canary is one planted token and its provenance.
type Canary struct {
	ID           string `json:"id"`
	Token        string `json:"token"`
	Label        string `json:"label"`
	Created      string `json:"created"` // RFC 3339, UTC
	Source       string `json:"source,omitempty"`
	PromptSHA256 string `json:"prompt_sha256,omitempty"`
	Status       string `json:"status"`
}

// Store is the on-disk canary registry.
type Store struct {
	Version  int      `json:"version"`
	Canaries []Canary `json:"canaries"`

	path string
}

// SchemaVersion is bumped only on incompatible file-format changes.
const SchemaVersion = 1

// IDFor derives the stable public identifier for a token: the first eight
// hex characters of its SHA-256. Safe to quote in tickets and CI logs
// without disclosing the token itself.
func IDFor(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])[:8]
}

// Load reads the store at path. A missing file yields an empty store bound
// to that path, so `plant` works on a fresh tree without a separate init.
func Load(path string) (*Store, error) {
	s := &Store{Version: SchemaVersion, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading %s: %w", path, err)
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("store: parsing %s: %w", path, err)
	}
	if s.Version != SchemaVersion {
		return nil, fmt.Errorf("store: %s has schema version %d, this build understands %d", path, s.Version, SchemaVersion)
	}
	s.path = path
	return s, nil
}

// Path returns the file the store was loaded from (and will save to).
func (s *Store) Path() string { return s.path }

// Save writes the store atomically: marshal, write a temp file in the same
// directory with 0600 permissions, then rename over the target.
func (s *Store) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encoding: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".coalmine-*.tmp")
	if err != nil {
		return fmt.Errorf("store: creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("store: setting permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store: writing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("store: replacing %s: %w", s.path, err)
	}
	return nil
}

// Add registers a canary after validating its token and rejecting
// duplicates — planting the same token twice would make scan attribution
// ambiguous.
func (s *Store) Add(c Canary) error {
	if !token.Valid(c.Token) {
		return fmt.Errorf("store: %q is not a valid coalmine token", c.Token)
	}
	for _, existing := range s.Canaries {
		if existing.Token == c.Token {
			return fmt.Errorf("store: token already planted as canary %s (label %q)", existing.ID, existing.Label)
		}
	}
	if c.ID == "" {
		c.ID = IDFor(c.Token)
	}
	if c.Status == "" {
		c.Status = StatusActive
	}
	s.Canaries = append(s.Canaries, c)
	return nil
}

// Revoke marks every canary whose ID or label equals key as revoked and
// returns how many changed. Zero matches is an error so typos fail loudly.
func (s *Store) Revoke(key string) (int, error) {
	n := 0
	for i := range s.Canaries {
		if s.Canaries[i].ID == key || s.Canaries[i].Label == key {
			if s.Canaries[i].Status != StatusRevoked {
				s.Canaries[i].Status = StatusRevoked
				n++
			}
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("store: no active canary with id or label %q", key)
	}
	return n, nil
}

// Active returns the canaries the scanner should hunt for.
func (s *Store) Active() []Canary {
	var out []Canary
	for _, c := range s.Canaries {
		if c.Status == StatusActive {
			out = append(out, c)
		}
	}
	return out
}
