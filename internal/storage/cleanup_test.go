// ABOUTME: Tests the verified migration and deletion of the legacy plaintext store.
// ABOUTME: Plaintext may only disappear after its encrypted copy is read back and matched.
package storage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testDB opens a real SQLCipher database in a temp directory. The verification
// this file is about is a round trip through the actual schema, so a fake
// backend would test nothing.
func testDB(t *testing.T) *SQLCipherStorage {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	db, err := NewSQLCipherStorage(filepath.Join(t.TempDir(), "memory.db"), key)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// sampleObservation builds an observation with something in most fields, so a
// comparison that only looked at the id would pass where a real one fails.
func sampleObservation(id string) *Observation {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	return &Observation{
		ID: id,
		Core: Core{
			Title:     "title for " + id,
			Summary:   "summary for " + id,
			Content:   "content for " + id,
			Type:      "discovery",
			Project:   "sinesync",
			SessionID: "session-" + id,
			CreatedAt: created,
			UpdatedAt: created.Add(time.Hour),
		},
		Structured: Structured{
			Facts:    []string{"fact one", "fact two"},
			Concepts: []string{"concept"},
			Files:    Files{Read: []string{"a.go"}, Modified: []string{"b.go"}},
			CodeRefs: []string{"a.go:12"},
		},
		Meta: Meta{
			Tags:           []string{"tag"},
			Classification: "private",
			Starred:        true,
			Notes:          "notes for " + id,
		},
		Source: Source{Adapter: "sinesync", ID: "src-" + id, Machine: "box", Epoch: created.Unix()},
	}
}

// writeLegacyObservation writes obs in the exact shape LocalStorage.Save wrote,
// at the permissive modes an older build used.
func writeLegacyObservation(t *testing.T, dir string, obs *Observation) string {
	t.Helper()
	item := StoredItem{
		ID:        obs.ID,
		Type:      "observation",
		Data:      obs,
		CreatedAt: obs.Core.CreatedAt,
		UpdatedAt: obs.Core.UpdatedAt,
	}
	blob, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, obs.ID+".json")
	writeAt(t, path, string(blob), 0o644)
	return path
}

// saveDirect puts an observation straight into the database the way the live
// capture path does — session row first, because of the foreign key.
func saveDirect(t *testing.T, db *SQLCipherStorage, obs *Observation) {
	t.Helper()
	if obs.Core.SessionID != "" {
		if err := db.EnsureSession(obs.Core.SessionID, obs.Core.Project, obs.Core.CreatedAt.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SaveObservation(obs); err != nil {
		t.Fatal(err)
	}
}

// snapshot records the bytes and mode of every file under root.
func snapshot(t *testing.T, root string) map[string][2]string {
	t.Helper()
	out := map[string][2]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			out[path] = [2]string{"dir", info.Mode().Perm().String()}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		out[path] = [2]string{string(sum[:]), info.Mode().Perm().String()}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshotting %s: %v", root, err)
	}
	return out
}

// TestCleanupRemovesVerifiedPlaintext is the happy path the whole policy exists
// for: the plaintext is gone, and every observation that was in it is readable
// out of the encrypted database with its content intact.
func TestCleanupRemovesVerifiedPlaintext(t *testing.T) {
	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	want := map[string]*Observation{}
	for _, id := range []string{"obs-1", "obs-2", "obs-3"} {
		obs := sampleObservation(id)
		want[id] = obs
		writeLegacyObservation(t, obsDir, obs)
	}

	db := testDB(t)
	if _, err := CleanupLegacyPlaintext(db, base); err != nil {
		t.Fatalf("cleanup failed on a tree it should have understood completely: %v", err)
	}

	if _, err := os.Stat(obsDir); !os.IsNotExist(err) {
		t.Errorf("%s still exists after every observation in it verified", obsDir)
	}

	for id, source := range want {
		got, err := db.GetObservation(id)
		if err != nil {
			t.Errorf("%s is not in the encrypted database after its plaintext was deleted: %v", id, err)
			continue
		}
		if !sameObservation(got, source) {
			t.Errorf("%s came back different from what was deleted:\n got %s\nwant %s",
				id, canonicalObservation(got), canonicalObservation(source))
		}
	}
}

// TestCleanupRemovesPreexistingArchive covers the directory the old policy left
// behind. Someone who ran an older build has an observation.migrated/ full of
// plaintext and no reason to expect anything to ever deal with it.
func TestCleanupRemovesPreexistingArchive(t *testing.T) {
	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	archive := filepath.Join(base, "observation.migrated")
	mkdirAt(t, obsDir, 0o755)
	mkdirAt(t, archive, 0o755)

	live := sampleObservation("obs-live")
	archived := sampleObservation("obs-archived")
	writeLegacyObservation(t, obsDir, live)
	writeLegacyObservation(t, archive, archived)

	db := testDB(t)
	if _, err := CleanupLegacyPlaintext(db, base); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	for _, dir := range []string{obsDir, archive} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s still exists after everything in it verified", dir)
		}
	}
	for _, obs := range []*Observation{live, archived} {
		got, err := db.GetObservation(obs.ID)
		if err != nil {
			t.Errorf("%s missing from the encrypted database: %v", obs.ID, err)
			continue
		}
		if !sameObservation(got, obs) {
			t.Errorf("%s does not match what was deleted", obs.ID)
		}
	}
}

// TestCleanupIsIdempotentOverAlreadyMigratedData covers the second run: the
// database already holds identical copies, so there is nothing to write and the
// plaintext is still safe to remove.
func TestCleanupIsIdempotentOverAlreadyMigratedData(t *testing.T) {
	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	obs := sampleObservation("obs-1")
	writeLegacyObservation(t, obsDir, obs)

	db := testDB(t)
	saveDirect(t, db, obs)

	if _, err := CleanupLegacyPlaintext(db, base); err != nil {
		t.Fatalf("cleanup failed over data that was already migrated: %v", err)
	}
	if _, err := os.Stat(obsDir); !os.IsNotExist(err) {
		t.Errorf("%s still exists after its contents were confirmed already present", obsDir)
	}
}

// TestCleanupIgnoresAbsentTrees: the ordinary case, on every start forever
// after the one that cleaned up.
func TestCleanupIgnoresAbsentTrees(t *testing.T) {
	if _, err := CleanupLegacyPlaintext(testDB(t), t.TempDir()); err != nil {
		t.Errorf("cleanup failed with no legacy trees present: %v", err)
	}
}

// assertTreeIsOwnerOnly checks a retained tree is still 0700/0600 throughout.
func assertTreeIsOwnerOnly(t *testing.T, root string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := fileMode
		if info.IsDir() {
			want = dirMode
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s is %04o in a retained tree, want %04o", path, got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// quarantineDirOf is where offending legacy entries end up.
func quarantineDirOf(base string) string {
	return filepath.Join(base, legacyQuarantineDirName)
}

// assertQuarantined checks one entry was set aside intact, owner-only, with a
// reason recorded, and returns it.
func assertQuarantined(t *testing.T, base string, entries []QuarantinedEntry, originalPath, wantContent string) QuarantinedEntry {
	t.Helper()

	var found *QuarantinedEntry
	for i := range entries {
		if entries[i].OriginalPath == originalPath {
			found = &entries[i]
		}
	}
	if found == nil {
		t.Fatalf("%s was not reported as quarantined; got %+v", originalPath, entries)
	}
	if found.Reason == "" {
		t.Errorf("%s was quarantined with no reason recorded", originalPath)
	}
	if filepath.Dir(found.QuarantinePath) != quarantineDirOf(base) {
		t.Errorf("%s went to %s, outside the quarantine directory %s", originalPath, found.QuarantinePath, quarantineDirOf(base))
	}
	if _, err := os.Stat(originalPath); !os.IsNotExist(err) {
		t.Errorf("%s is still in the legacy tree after being quarantined", originalPath)
	}

	info, err := os.Stat(found.QuarantinePath)
	if err != nil {
		t.Fatalf("quarantined entry %s is missing: %v", found.QuarantinePath, err)
	}
	if info.IsDir() {
		if got := info.Mode().Perm(); got != dirMode {
			t.Errorf("quarantined directory %s is %04o, want %04o", found.QuarantinePath, got, dirMode)
		}
		return *found
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Errorf("quarantined file %s is %04o, want %04o", found.QuarantinePath, got, fileMode)
	}
	got, err := os.ReadFile(found.QuarantinePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantContent {
		t.Errorf("quarantined file %s was altered:\n got %q\nwant %q", found.QuarantinePath, got, wantContent)
	}
	return *found
}

// assertManifestRecords checks the on-disk record names the entry, since the
// log will eventually rotate away.
func assertManifestRecords(t *testing.T, base string, want QuarantinedEntry) {
	t.Helper()
	manifestPath := filepath.Join(quarantineDirOf(base), quarantineManifestName)
	info, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatalf("no quarantine manifest at %s: %v", manifestPath, err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != fileMode {
			t.Errorf("manifest is %04o, want %04o", got, fileMode)
		}
	}
	blob, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var recorded []QuarantinedEntry
	if err := json.Unmarshal(blob, &recorded); err != nil {
		t.Fatalf("manifest is not readable JSON: %v", err)
	}
	for _, r := range recorded {
		if r.OriginalPath == want.OriginalPath && r.QuarantinePath == want.QuarantinePath && r.Reason != "" {
			return
		}
	}
	t.Errorf("manifest does not record %s: %+v", want.OriginalPath, recorded)
}

// TestCleanupQuarantinesCorruptEntryAndStillFinishes is the case that used to
// stop the daemon dead. One unreadable file is set aside, everything else
// migrates, the tree goes, and the user is told what was left out.
func TestCleanupQuarantinesCorruptEntryAndStillFinishes(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	for _, id := range []string{"obs-1", "obs-2", "obs-3"} {
		writeLegacyObservation(t, obsDir, sampleObservation(id))
	}
	const brokenContent = "{ this is not json"
	brokenPath := filepath.Join(obsDir, "broken.json")
	writeAt(t, brokenPath, brokenContent, 0o644)

	db := testDB(t)
	quarantined, err := CleanupLegacyPlaintext(db, base)
	if err != nil {
		t.Fatalf("cleanup failed instead of quarantining one bad file: %v", err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("quarantined %d entries, want 1: %+v", len(quarantined), quarantined)
	}

	entry := assertQuarantined(t, base, quarantined, brokenPath, brokenContent)
	assertManifestRecords(t, base, entry)
	if !strings.Contains(entry.Reason, "JSON") {
		t.Errorf("reason does not say why it could not be migrated: %q", entry.Reason)
	}

	// The tree is gone and everything in it that could be verified is readable
	// out of the encrypted database.
	if _, err := os.Stat(obsDir); !os.IsNotExist(err) {
		t.Errorf("%s still exists after everything in it was either migrated or quarantined", obsDir)
	}
	for _, id := range []string{"obs-1", "obs-2", "obs-3"} {
		if _, err := db.GetObservation(id); err != nil {
			t.Errorf("%s did not make it into the encrypted database: %v", id, err)
		}
	}

	if got := quarantineDirPerm(t, base); got != dirMode {
		t.Errorf("quarantine directory is %04o, want %04o", got, dirMode)
	}
}

// TestCleanupQuarantinesConflictWithoutOverwriting: two observations claiming
// one id. The one on disk is set aside; the one already in the database keeps
// its content.
func TestCleanupQuarantinesConflictWithoutOverwriting(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	db := testDB(t)
	inDatabase := sampleObservation("obs-clash")
	inDatabase.Core.Title = "the copy already in the database"
	saveDirect(t, db, inDatabase)

	onDisk := sampleObservation("obs-clash")
	onDisk.Core.Title = "a different observation with the same id"
	clashPath := writeLegacyObservation(t, obsDir, onDisk)
	clashContent := readFileString(t, clashPath)
	writeLegacyObservation(t, obsDir, sampleObservation("obs-fine"))

	quarantined, err := CleanupLegacyPlaintext(db, base)
	if err != nil {
		t.Fatalf("cleanup failed instead of quarantining the conflict: %v", err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("quarantined %d entries, want 1: %+v", len(quarantined), quarantined)
	}
	entry := assertQuarantined(t, base, quarantined, clashPath, clashContent)
	if !strings.Contains(entry.Reason, "obs-clash") {
		t.Errorf("reason does not name the conflicting id: %q", entry.Reason)
	}

	stored, err := db.GetObservation("obs-clash")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Core.Title != "the copy already in the database" {
		t.Errorf("the conflicting id was overwritten in the database: %q", stored.Core.Title)
	}
	if _, err := db.GetObservation("obs-fine"); err != nil {
		t.Errorf("the file that was fine did not migrate: %v", err)
	}
	if _, err := os.Stat(obsDir); !os.IsNotExist(err) {
		t.Errorf("%s still exists", obsDir)
	}
}

// TestCleanupQuarantinesUnexpectedEntries covers a stray file and a stray
// directory: things the legacy store never wrote, which this code cannot claim
// to have migrated and must not delete.
func TestCleanupQuarantinesUnexpectedEntries(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)
	writeLegacyObservation(t, obsDir, sampleObservation("obs-1"))

	const notesContent = "the user's own notes"
	notesPath := filepath.Join(obsDir, "notes.txt")
	writeAt(t, notesPath, notesContent, 0o644)
	nestedPath := filepath.Join(obsDir, "nested")
	mkdirAt(t, nestedPath, 0o755)
	writeAt(t, filepath.Join(nestedPath, "deep.json"), `{"id":"deep"}`, 0o644)

	db := testDB(t)
	quarantined, err := CleanupLegacyPlaintext(db, base)
	if err != nil {
		t.Fatalf("cleanup failed instead of quarantining: %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("quarantined %d entries, want 2: %+v", len(quarantined), quarantined)
	}

	assertQuarantined(t, base, quarantined, notesPath, notesContent)
	dirEntry := assertQuarantined(t, base, quarantined, nestedPath, "")
	// The directory came across whole, and hardened.
	deep, err := os.ReadFile(filepath.Join(dirEntry.QuarantinePath, "deep.json"))
	if err != nil || string(deep) != `{"id":"deep"}` {
		t.Errorf("the quarantined directory lost its contents: %q, %v", deep, err)
	}
	assertTreeIsOwnerOnly(t, dirEntry.QuarantinePath)

	if _, err := os.Stat(obsDir); !os.IsNotExist(err) {
		t.Errorf("%s still exists", obsDir)
	}
}

// TestCleanupQuarantineDoesNotOverwriteExistingEntries: the same filename can
// appear in both legacy trees, and a second run must not clobber what a first
// one set aside.
func TestCleanupQuarantineDoesNotOverwriteExistingEntries(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	archive := filepath.Join(base, "observation.migrated")
	mkdirAt(t, obsDir, 0o755)
	mkdirAt(t, archive, 0o755)

	writeAt(t, filepath.Join(obsDir, "broken.json"), "first broken file", 0o644)
	writeAt(t, filepath.Join(archive, "broken.json"), "second broken file", 0o644)

	quarantined, err := CleanupLegacyPlaintext(testDB(t), base)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("quarantined %d entries, want 2: %+v", len(quarantined), quarantined)
	}
	if quarantined[0].QuarantinePath == quarantined[1].QuarantinePath {
		t.Fatalf("both entries went to the same path %s — one overwrote the other", quarantined[0].QuarantinePath)
	}

	seen := map[string]bool{}
	for _, q := range quarantined {
		seen[readFileString(t, q.QuarantinePath)] = true
	}
	for _, want := range []string{"first broken file", "second broken file"} {
		if !seen[want] {
			t.Errorf("quarantine lost %q", want)
		}
	}
}

// TestCleanupRetainsWhenQuarantineIsImpossible is the remaining hard-fail. If
// an entry cannot be secured or moved, the tree stays where it is: deleting it
// would take verified observations with it and leave the unhandled one behind,
// and at that point this code cannot say what state the directory is in.
func TestCleanupRetainsWhenQuarantineIsImpossible(t *testing.T) {
	skipIfWindows(t)
	skipIfRoot(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)
	writeLegacyObservation(t, obsDir, sampleObservation("obs-1"))
	writeAt(t, filepath.Join(obsDir, "broken.json"), "{ not json", 0o644)

	before := snapshot(t, obsDir)

	// Moving anything out of the tree needs write permission on the tree.
	if err := os.Chmod(obsDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(obsDir, 0o700) })

	_, err := CleanupLegacyPlaintext(testDB(t), base)
	if err == nil {
		t.Fatal("cleanup reported success although the offending file could not be moved")
	}
	var lc *LegacyCleanupError
	if !errors.As(err, &lc) {
		t.Fatalf("error is not a *LegacyCleanupError: %T", err)
	}
	if lc.Path != obsDir || !strings.Contains(err.Error(), "broken.json") {
		t.Errorf("error does not name the tree and the file: %q", err)
	}
	if !strings.Contains(lc.Remedy(), obsDir) {
		t.Errorf("remedy does not name the tree: %q", lc.Remedy())
	}

	if err := os.Chmod(obsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, obsDir)
	if len(after) != len(before) {
		t.Errorf("tree changed size: %d before, %d after", len(before), len(after))
	}
	for path, want := range before {
		if got, ok := after[path]; !ok || got[0] != want[0] {
			t.Errorf("%s not preserved after a failed quarantine", path)
		}
	}
}

// lyingDB accepts every write and then, once something has been written,
// returns content that does not match. SQLCipher does not behave this way; the
// point is that this code must not assume so, because "the INSERT returned no
// error" is not the same claim as "the observation survived".
type lyingDB struct {
	*SQLCipherStorage
	sabotage bool
}

func (l *lyingDB) SaveObservation(obs *Observation) error {
	if err := l.SQLCipherStorage.SaveObservation(obs); err != nil {
		return err
	}
	l.sabotage = true
	return nil
}

func (l *lyingDB) GetObservation(id string) (*Observation, error) {
	obs, err := l.SQLCipherStorage.GetObservation(id)
	if err != nil || obs == nil || !l.sabotage {
		return obs, err
	}
	corrupted := *obs
	corrupted.Core.Content = "this is not what was written"
	return &corrupted, nil
}

// TestCleanupQuarantinesWhenTheReadBackDisagrees is the test for the reason
// this flow reads its writes. Without the read-back the plaintext would be
// deleted on the strength of a nil error from the insert.
func TestCleanupQuarantinesWhenTheReadBackDisagrees(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)
	p1 := writeLegacyObservation(t, obsDir, sampleObservation("obs-1"))
	p2 := writeLegacyObservation(t, obsDir, sampleObservation("obs-2"))
	c1, c2 := readFileString(t, p1), readFileString(t, p2)

	quarantined, err := cleanupLegacyTree(&lyingDB{SQLCipherStorage: testDB(t)}, base, obsDir)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("quarantined %d entries, want 2: %+v", len(quarantined), quarantined)
	}
	for _, q := range quarantined {
		if !strings.Contains(q.Reason, "does not match what was written") {
			t.Errorf("reason does not say the read-back disagreed: %q", q.Reason)
		}
	}
	assertQuarantined(t, base, quarantined, p1, c1)
	assertQuarantined(t, base, quarantined, p2, c2)
}

// TestCleanupQuarantinesWhenTheVectorIsMissing covers the embedding. Its insert
// is deliberately non-fatal in SaveObservation, so an observation can be fully
// present with no vector at all — fine for a live capture, not a basis for
// deleting the file the vector came from.
func TestCleanupQuarantinesWhenTheVectorIsMissing(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	// 384 dimensions is what the vec0 table declares; 8 is not, so the vector
	// insert fails the way a real mismatch would, non-fatally.
	wrongDims := sampleObservation("obs-wrong-dims")
	wrongDims.Embedding.Model = "m"
	wrongDims.Embedding.Tokenizer = "tk"
	wrongDims.Embedding.Dims = 8
	wrongDims.Embedding.Vector = []float32{1, 2, 3, 4, 5, 6, 7, 8}
	badPath := writeLegacyObservation(t, obsDir, wrongDims)
	badContent := readFileString(t, badPath)

	good := sampleObservation("obs-good-dims")
	good.Embedding.Model = "m"
	good.Embedding.Tokenizer = "tk"
	good.Embedding.Dims = 384
	good.Embedding.Vector = make([]float32, 384)
	for i := range good.Embedding.Vector {
		good.Embedding.Vector[i] = float32(i) / 384
	}
	writeLegacyObservation(t, obsDir, good)

	db := testDB(t)
	quarantined, err := CleanupLegacyPlaintext(db, base)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("quarantined %d entries, want 1: %+v", len(quarantined), quarantined)
	}
	entry := assertQuarantined(t, base, quarantined, badPath, badContent)
	if !strings.Contains(entry.Reason, "embedding") {
		t.Errorf("reason does not mention the embedding: %q", entry.Reason)
	}

	// The one whose vector did land is migrated, and the vector matches.
	stored, err := db.GetObservationVector("obs-good-dims")
	if err != nil {
		t.Fatalf("reading back the stored vector: %v", err)
	}
	if len(stored) != len(good.Embedding.Vector) {
		t.Fatalf("stored vector has %d dimensions, want %d", len(stored), len(good.Embedding.Vector))
	}
	for i := range stored {
		if stored[i] != good.Embedding.Vector[i] {
			t.Fatalf("stored vector differs at %d: %v vs %v", i, stored[i], good.Embedding.Vector[i])
		}
	}
}

// TestMigrationCreatesSessionWithoutOverwriting pins both halves of the
// foreign-key fix: a legacy observation's session row is created when it is
// missing, and an existing session's own fields are left alone.
func TestMigrationCreatesSessionWithoutOverwriting(t *testing.T) {
	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	db := testDB(t)

	// One session already exists, recorded against a different project.
	existing := sampleObservation("obs-existing-session")
	existing.Core.SessionID = "session-already-here"
	existing.Core.Project = "the-new-project"
	if err := db.EnsureSession("session-already-here", "the-original-project", 1000); err != nil {
		t.Fatal(err)
	}
	writeLegacyObservation(t, obsDir, existing)

	// The other references a session that has never existed as a row.
	fresh := sampleObservation("obs-new-session")
	fresh.Core.SessionID = "session-never-seen"
	fresh.Core.Project = "brand-new-project"
	writeLegacyObservation(t, obsDir, fresh)

	if _, err := CleanupLegacyPlaintext(db, base); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	var project string
	var startedAt int64
	if err := db.db.QueryRow("SELECT project, started_at_epoch FROM sessions WHERE session_id = ?", "session-already-here").
		Scan(&project, &startedAt); err != nil {
		t.Fatal(err)
	}
	if project != "the-original-project" || startedAt != 1000 {
		t.Errorf("migration overwrote an existing session row: project=%q startedAt=%d", project, startedAt)
	}

	if err := db.db.QueryRow("SELECT project, started_at_epoch FROM sessions WHERE session_id = ?", "session-never-seen").
		Scan(&project, &startedAt); err != nil {
		t.Fatalf("migration did not create the missing session row: %v", err)
	}
	if project != "brand-new-project" || startedAt != fresh.Core.CreatedAt.Unix() {
		t.Errorf("created session row does not carry the observation's own project and time: project=%q startedAt=%d", project, startedAt)
	}

	// Both observations kept their session id through the round trip.
	for _, want := range []*Observation{existing, fresh} {
		got, err := db.GetObservation(want.ID)
		if err != nil {
			t.Fatalf("%s did not migrate: %v", want.ID, err)
		}
		if got.Core.SessionID != want.Core.SessionID {
			t.Errorf("%s lost its session id: %q", want.ID, got.Core.SessionID)
		}
	}
}

// TestTimestampsRoundTripExactly is what makes exact verification possible.
func TestTimestampsRoundTripExactly(t *testing.T) {
	db := testDB(t)

	obs := sampleObservation("obs-nano")
	obs.Core.CreatedAt = time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)
	obs.Core.UpdatedAt = time.Date(2026, 3, 4, 8, 9, 10, 987654321, time.UTC)
	saveDirect(t, db, obs)

	got, err := db.GetObservation(obs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Core.CreatedAt.Equal(obs.Core.CreatedAt) {
		t.Errorf("createdAt round-tripped as %v, want %v", got.Core.CreatedAt, obs.Core.CreatedAt)
	}
	if !got.Core.UpdatedAt.Equal(obs.Core.UpdatedAt) {
		t.Errorf("updatedAt round-tripped as %v, want %v", got.Core.UpdatedAt, obs.Core.UpdatedAt)
	}
	if !sameObservation(got, obs) {
		t.Error("an observation with sub-second timestamps did not verify against itself after a round trip")
	}
}

// TestRFC3339NanoIsReadableByAnRFC3339Reader is the backward-compatibility
// proof the format change rests on. It parses, rather than asserting: a reader
// built before this change uses the RFC3339 layout, and it has to accept what
// is written now. Rows already stored without a fraction must keep working too.
func TestRFC3339NanoIsReadableByAnRFC3339Reader(t *testing.T) {
	written := time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC).Format(time.RFC3339Nano)
	if !strings.Contains(written, ".123456789") {
		t.Fatalf("RFC3339Nano did not keep the fraction: %q", written)
	}

	// The old layout, exactly as deserializeObservation uses it.
	parsed, err := time.Parse(time.RFC3339, written)
	if err != nil {
		t.Fatalf("a reader using time.RFC3339 cannot parse %q: %v", written, err)
	}
	if parsed.Nanosecond() != 123456789 {
		t.Errorf("RFC3339 parse dropped the fraction: got %d nanoseconds", parsed.Nanosecond())
	}

	// A value already in the database, written before this change.
	legacy := "2026-03-04T05:06:07Z"
	old, err := time.Parse(time.RFC3339, legacy)
	if err != nil {
		t.Fatalf("existing rows no longer parse: %v", err)
	}
	if old.Nanosecond() != 0 {
		t.Errorf("a second-precision value gained a fraction: %d", old.Nanosecond())
	}
}

// TestSameObservationComparesContent documents exactly what the comparison
// covers, now that nothing about it is approximate except the vector, which is
// verified separately against the table it actually lives in.
func TestSameObservationComparesContent(t *testing.T) {
	base := sampleObservation("obs-1")
	if !sameObservation(base, sampleObservation("obs-1")) {
		t.Error("two identical observations did not compare equal")
	}

	for name, mutate := range map[string]func(*Observation){
		"core content":    func(o *Observation) { o.Core.Content = "different" },
		"core title":      func(o *Observation) { o.Core.Title = "different" },
		"session id":      func(o *Observation) { o.Core.SessionID = "different" },
		"whole second":    func(o *Observation) { o.Core.CreatedAt = o.Core.CreatedAt.Add(time.Second) },
		"one nanosecond":  func(o *Observation) { o.Core.CreatedAt = o.Core.CreatedAt.Add(time.Nanosecond) },
		"half a second":   func(o *Observation) { o.Core.UpdatedAt = o.Core.UpdatedAt.Add(500 * time.Millisecond) },
		"facts":           func(o *Observation) { o.Structured.Facts = append(o.Structured.Facts, "extra") },
		"files modified":  func(o *Observation) { o.Structured.Files.Modified = nil },
		"tags":            func(o *Observation) { o.Meta.Tags = []string{"other"} },
		"starred":         func(o *Observation) { o.Meta.Starred = !o.Meta.Starred },
		"source machine":  func(o *Observation) { o.Source.Machine = "elsewhere" },
		"extensions":      func(o *Observation) { o.Extensions = map[string]interface{}{"k": "v"} },
		"embedding model": func(o *Observation) { o.Embedding.Model = "other-model" },
		"embedding dims":  func(o *Observation) { o.Embedding.Dims = 768 },
		"classification":  func(o *Observation) { o.Meta.Classification = "public" },
		"source checksum": func(o *Observation) { o.Source.Checksum = "deadbeef" },
	} {
		other := sampleObservation("obs-1")
		mutate(other)
		if sameObservation(base, other) {
			t.Errorf("a difference in %s was not detected — the comparison is too shallow", name)
		}
	}

	// The vector is the one field left out here, because GetObservation never
	// populates it. verifyVector checks it against the vec table instead.
	withVector := sampleObservation("obs-1")
	withVector.Embedding.Vector = []float32{0.1, 0.2}
	if !sameObservation(base, withVector) {
		t.Error("Embedding.Vector should be left to verifyVector, not compared here")
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func quarantineDirPerm(t *testing.T, base string) os.FileMode {
	t.Helper()
	info, err := os.Stat(quarantineDirOf(base))
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
