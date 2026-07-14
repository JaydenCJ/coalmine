// Tests for the canary registry: load/save round trips, duplicate and
// validity guards, revocation semantics, and the atomic-write contract.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goodToken is the pinned documentation token (valid checksum).
const goodToken = "CM7Q3KXN4TP2A9ZR6WB0"

// secondToken is a second valid token for multi-canary cases.
const secondToken = "CM4TQ7XKN2P9A3ZR6WWG"

func tempStore(t *testing.T) *Store {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "coalmine.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

func canary(tok, label string) Canary {
	return Canary{Token: tok, Label: label, Created: "2026-07-12T00:00:00Z"}
}

func TestLoadMissingFileYieldsEmptyStore(t *testing.T) {
	s := tempStore(t)
	if len(s.Canaries) != 0 || s.Version != SchemaVersion {
		t.Fatalf("empty store wrong: %+v", s)
	}
}

func TestAddSaveLoadRoundTrip(t *testing.T) {
	s := tempStore(t)
	if err := s.Add(canary(goodToken, "prod-bot")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(s.Path())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(loaded.Canaries) != 1 {
		t.Fatalf("reloaded %d canaries, want 1", len(loaded.Canaries))
	}
	c := loaded.Canaries[0]
	if c.Token != goodToken || c.Label != "prod-bot" || c.Status != StatusActive {
		t.Fatalf("round-tripped canary wrong: %+v", c)
	}
	if c.ID != IDFor(goodToken) {
		t.Fatalf("ID %q not derived from token", c.ID)
	}
}

func TestAddRejectsInvalidToken(t *testing.T) {
	s := tempStore(t)
	for _, bad := range []string{"", "CMNOTAVALIDTOKEN", strings.ToLower(goodToken)} {
		if err := s.Add(canary(bad, "x")); err == nil {
			t.Errorf("Add(%q) succeeded, want error", bad)
		}
	}
}

func TestAddRejectsDuplicateToken(t *testing.T) {
	s := tempStore(t)
	if err := s.Add(canary(goodToken, "a")); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err := s.Add(canary(goodToken, "b"))
	if err == nil {
		t.Fatal("duplicate Add succeeded")
	}
	if !strings.Contains(err.Error(), IDFor(goodToken)) {
		t.Errorf("duplicate error %q should name the existing canary id", err)
	}
}

func TestRevokeByIDOnceThenErrorsOnRepeat(t *testing.T) {
	s := tempStore(t)
	_ = s.Add(canary(goodToken, "prod-bot"))
	n, err := s.Revoke(IDFor(goodToken))
	if err != nil || n != 1 {
		t.Fatalf("Revoke = (%d, %v), want (1, nil)", n, err)
	}
	if s.Canaries[0].Status != StatusRevoked {
		t.Fatal("status not revoked")
	}
	// A second revoke changes nothing, so it reports zero matches.
	if _, err := s.Revoke(IDFor(goodToken)); err == nil {
		t.Fatal("second revoke should error with zero changes")
	}
}

func TestRevokeByLabelHitsAllMatchesButUnknownKeyErrors(t *testing.T) {
	s := tempStore(t)
	_ = s.Add(canary(goodToken, "staging"))
	_ = s.Add(canary(secondToken, "staging"))
	if _, err := s.Revoke("nonexistent"); err == nil {
		t.Fatal("revoking an unknown key should error")
	}
	n, err := s.Revoke("staging")
	if err != nil || n != 2 {
		t.Fatalf("Revoke(label) = (%d, %v), want (2, nil)", n, err)
	}
}

func TestActiveExcludesRevoked(t *testing.T) {
	s := tempStore(t)
	_ = s.Add(canary(goodToken, "keep"))
	_ = s.Add(canary(secondToken, "drop"))
	_, _ = s.Revoke("drop")
	active := s.Active()
	if len(active) != 1 || active[0].Label != "keep" {
		t.Fatalf("Active = %+v", active)
	}
}

func TestSaveIsAtomicRestrictiveAndWellFormed(t *testing.T) {
	s := tempStore(t)
	_ = s.Add(canary(goodToken, "prod"))
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("store file mode %o, want 600 (it contains tokens)", perm)
	}
	data, _ := os.ReadFile(s.Path())
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("store file must end with a newline")
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("store file is not valid JSON: %v", err)
	}
	// The temp file used for the atomic rename must not linger.
	entries, _ := os.ReadDir(filepath.Dir(s.Path()))
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory should hold only the store, got %v", names)
	}
}

func TestLoadRejectsBadStoreFiles(t *testing.T) {
	cases := map[string]string{
		"future schema": `{"version": 99, "canaries": []}`,
		"corrupt json":  "{not json",
	}
	for name, content := range cases {
		path := filepath.Join(t.TempDir(), "coalmine.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("%s: Load should fail", name)
		}
	}
}

func TestIDForIsStableShortAndNonRevealing(t *testing.T) {
	a, b := IDFor(goodToken), IDFor(goodToken)
	if a != b {
		t.Fatal("IDFor not deterministic")
	}
	if len(a) != 8 {
		t.Fatalf("IDFor length %d, want 8", len(a))
	}
	if a == IDFor(secondToken) {
		t.Fatal("distinct tokens share an id")
	}
	if strings.Contains(goodToken, strings.ToUpper(a)) {
		t.Fatal("id must not reveal token material")
	}
}
