// ABOUTME: Asserts an item id cannot escape the data directory through the path join.
// ABOUTME: Covers Save, Get, Exists and Delete, not only the two CodeQL reported.

package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// Save, Get, Exists and Delete each build dir + id + ".json". An id carrying a
// separator would escape the data directory, and Delete would remove whatever
// it landed on.
//
// All four are covered rather than the two that were reported: CodeQL flagged
// Get and Delete and did not flag Save, which is the one that writes. Testing
// only what a scanner noticed is how the unreported half stays broken.
func TestAnItemIDCannotEscapeTheDataDirectory(t *testing.T) {
	base := t.TempDir()
	s := &LocalStorage{baseDir: base}

	outside := filepath.Join(base, "..", "escaped.json")
	const canary = `{"canary":true}`
	if err := os.WriteFile(outside, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	const traversal = "../escaped"

	// Read side first, while nothing inside the directory answers to the
	// neutralised name. Checking after the write would find the file Save
	// legitimately created inside, and pass for the wrong reason.
	if _, err := s.Get("observation", traversal); err == nil {
		t.Error("Get read the file outside the data directory")
	}
	if ok, _ := s.Exists("observation", traversal); ok {
		t.Error("Exists reported the file outside the data directory")
	}

	_ = s.Delete("observation", traversal)
	if _, err := os.Stat(outside); err != nil {
		t.Error("Delete removed the file outside the data directory")
	}

	// Write side: the id is neutralised rather than refused, so the write lands
	// inside and the file outside is untouched.
	if err := s.Save("observation", traversal, map[string]string{"x": "y"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	after, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("the file outside the data directory is gone: %v", err)
	}
	if string(after) != canary {
		t.Error("Save wrote through a traversing id")
	}
	if _, err := os.Stat(filepath.Join(base, "observation", "escaped.json")); err != nil {
		t.Errorf("the write did not land inside the data directory: %v", err)
	}
}
