// ABOUTME: Pins the rule that an existing database decides which stored key opens it.
// ABOUTME: The sequence under test is first run before login, then a login, then a restart.
package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/keychain"
)

// fakeKeychain replaces the two keychain calls the resolver makes. A CI runner
// has no OS keychain, and what is being tested is a sequence of keychain states
// rather than the keychain itself.
type fakeKeychain struct {
	candidates []keychain.DBKeyCandidate
	created    [][]byte // keys CreateLocalDBKey handed out, in order
	listErr    error
}

func (f *fakeKeychain) install(t *testing.T) {
	t.Helper()
	origList, origCreate := dbKeyCandidates, createLocalDBKey
	t.Cleanup(func() { dbKeyCandidates, createLocalDBKey = origList, origCreate })

	dbKeyCandidates = func() ([]keychain.DBKeyCandidate, error) {
		if f.listErr != nil {
			return nil, f.listErr
		}
		return f.candidates, nil
	}
	createLocalDBKey = func() ([]byte, error) {
		key := testKey(byte(0x40 + len(f.created)))
		f.created = append(f.created, key)
		f.candidates = append(f.candidates, keychain.DBKeyCandidate{Source: keychain.DBKeyLocal, Key: key})
		return key, nil
	}
}

func testKey(fill byte) []byte {
	key := make([]byte, keychain.DBKeyLen)
	for i := range key {
		key[i] = fill
	}
	return key
}

// writeDatabase creates a database at path encrypted with key and puts one
// observation in it, so a later open can prove the contents survived.
func writeDatabase(t *testing.T, path string, key []byte, obsID string) {
	t.Helper()
	db, err := NewSQLCipherStorage(path, key)
	if err != nil {
		t.Fatalf("creating the database: %v", err)
	}
	obs := sampleObservation(obsID)
	if err := db.EnsureSession(obs.Core.SessionID, obs.Core.Project, obs.Core.CreatedAt.Unix()); err != nil {
		db.Close()
		t.Fatalf("creating the session row: %v", err)
	}
	if err := db.SaveObservation(obs); err != nil {
		db.Close()
		t.Fatalf("saving an observation: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing the database: %v", err)
	}
}

// The regression. Before this, resolution asked the keychain "is there a
// derived key?" and never asked the database anything, so a user who ran
// sinesync once before logging in had a local-key database and a derived key
// that had never encrypted a byte of it.
func TestExistingLocalKeyDatabaseSurvivesLogin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory.db")
	fk := &fakeKeychain{}
	fk.install(t)

	// 1. First run, before any login: no keys at all, no database.
	key, source, err := ResolveDBKey(dbPath)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if source != keychain.DBKeyLocal {
		t.Fatalf("first run opened with the %s, want a local key", source)
	}
	if len(fk.created) != 1 || !bytes.Equal(fk.created[0], key) {
		t.Fatalf("first run did not generate and store exactly one local key (created %d)", len(fk.created))
	}
	localKey := key
	writeDatabase(t, dbPath, localKey, "before-login")

	// 2. The user logs in, which stores a derived key. Nothing rekeys the
	//    database — that is the whole situation being recovered from.
	derivedKey := testKey(0xD1)
	fk.candidates = append([]keychain.DBKeyCandidate{
		{Source: keychain.DBKeyDerived, Key: derivedKey},
	}, fk.candidates...)

	// 3. Restart. The database, not the keychain's preference order, decides.
	key, source, err = ResolveDBKey(dbPath)
	if err != nil {
		t.Fatalf("after login the database could not be resolved at all: %v", err)
	}
	if source != keychain.DBKeyLocal {
		t.Fatalf("resolved the %s, want the local key the database was actually encrypted with", source)
	}
	if !bytes.Equal(key, localKey) {
		t.Fatal("resolved a key that is not the one the database was created with")
	}
	if len(fk.created) != 1 {
		t.Fatalf("resolution generated %d extra keys; selection must never create one", len(fk.created)-1)
	}

	// 4. And the database opens, with everything still in it.
	db, err := NewSQLCipherStorage(dbPath, key)
	if err != nil {
		t.Fatalf("opening with the resolved key: %v", err)
	}
	defer db.Close()
	obs, err := db.GetObservation("before-login")
	if err != nil {
		t.Fatalf("reading back the observation written before login: %v", err)
	}
	if obs.Core.Title != sampleObservation("before-login").Core.Title {
		t.Errorf("observation came back changed: title %q", obs.Core.Title)
	}

	// An install already broken by the old behaviour is the same state as this
	// one — a local-key database with a derived key sitting in front of it — so
	// it recovers on the next start with no user action. Resolving twice more
	// must keep giving the same answer and still create nothing.
	for i := 0; i < 2; i++ {
		again, source, err := ResolveDBKey(dbPath)
		if err != nil || !bytes.Equal(again, localKey) || source != keychain.DBKeyLocal {
			t.Fatalf("repeat %d resolved differently: key equal=%v source=%s err=%v", i, bytes.Equal(again, localKey), source, err)
		}
	}
	if len(fk.created) != 1 {
		t.Errorf("repeated resolution generated %d keys", len(fk.created))
	}
}

// The other direction: a database that really was created with the derived key
// must keep resolving to it, or the fix would have traded one broken install
// for another.
func TestDerivedKeyDatabaseResolvesToDerived(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory.db")
	derivedKey, localKey := testKey(0xD1), testKey(0x10)
	writeDatabase(t, dbPath, derivedKey, "after-login")

	fk := &fakeKeychain{candidates: []keychain.DBKeyCandidate{
		{Source: keychain.DBKeyDerived, Key: derivedKey},
		{Source: keychain.DBKeyLocal, Key: localKey},
	}}
	fk.install(t)

	key, source, err := ResolveDBKey(dbPath)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if source != keychain.DBKeyDerived || !bytes.Equal(key, derivedKey) {
		t.Fatalf("resolved the %s, want the derived key the database was encrypted with", source)
	}
}

// With no database yet there is nothing to be bound by, so preference order is
// the whole answer.
func TestFreshInstallPrefersTheDerivedKey(t *testing.T) {
	derivedKey, localKey := testKey(0xD1), testKey(0x10)
	fk := &fakeKeychain{candidates: []keychain.DBKeyCandidate{
		{Source: keychain.DBKeyDerived, Key: derivedKey},
		{Source: keychain.DBKeyLocal, Key: localKey},
	}}
	fk.install(t)

	key, source, err := ResolveDBKey(filepath.Join(t.TempDir(), "memory.db"))
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if source != keychain.DBKeyDerived || !bytes.Equal(key, derivedKey) {
		t.Fatalf("fresh install resolved the %s, want the derived key", source)
	}
	if len(fk.created) != 0 {
		t.Errorf("fresh install generated a key even though one was stored")
	}
}

// A zero-byte file is not a database: SQLCipher would happily adopt it under
// any key, so pinning the install to whichever candidate was tried first would
// be arbitrary.
func TestEmptyFileIsTreatedAsNoDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory.db")
	if err := os.WriteFile(dbPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	derivedKey := testKey(0xD1)
	fk := &fakeKeychain{candidates: []keychain.DBKeyCandidate{
		{Source: keychain.DBKeyDerived, Key: derivedKey},
		{Source: keychain.DBKeyLocal, Key: testKey(0x10)},
	}}
	fk.install(t)

	_, source, err := ResolveDBKey(dbPath)
	if err != nil {
		t.Fatalf("resolving against an empty file: %v", err)
	}
	if source != keychain.DBKeyDerived {
		t.Errorf("resolved the %s against an empty file, want fresh-install preference order", source)
	}
}

// When nothing opens the database, the database must come out of it untouched.
// This is the state a user is in when they are most likely to be told to delete
// it, so the one thing that must be true is that there is still something to
// recover.
func TestUnopenableDatabaseIsReportedAndLeftAlone(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory.db")
	writeDatabase(t, dbPath, testKey(0xAA), "orphaned")
	before := hashFile(t, dbPath)

	fk := &fakeKeychain{candidates: []keychain.DBKeyCandidate{
		{Source: keychain.DBKeyDerived, Key: testKey(0xD1)},
		{Source: keychain.DBKeyLocal, Key: testKey(0x10)},
	}}
	fk.install(t)

	_, _, err := ResolveDBKey(dbPath)
	var mismatch *DBKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("got %v, want a DBKeyMismatchError so callers can explain it", err)
	}
	if len(mismatch.Tried) != 2 {
		t.Errorf("reported %d keys tried, want both", len(mismatch.Tried))
	}
	if len(fk.created) != 0 {
		t.Error("a new key was generated for a database that already exists; that orphans it permanently")
	}
	if after := hashFile(t, dbPath); after != before {
		t.Error("the database changed while its key was being looked for")
	}
}

// The probe opens with PRAGMA query_only, which refuses every write. A WAL
// database is the case where that could backfire — a reader may need to touch
// the -wal file — so it is checked rather than assumed.
func TestProbeWorksOnAWALDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory.db")
	key := testKey(0x77)
	db, err := NewSQLCipherStorage(dbPath, key)
	if err != nil {
		t.Fatalf("creating the database: %v", err)
	}
	if _, err := db.DB().Exec("PRAGMA journal_mode = WAL"); err != nil {
		db.Close()
		t.Fatalf("switching to WAL: %v", err)
	}
	obs := sampleObservation("in-wal")
	if err := db.EnsureSession(obs.Core.SessionID, obs.Core.Project, obs.Core.CreatedAt.Unix()); err != nil {
		db.Close()
		t.Fatalf("creating the session row: %v", err)
	}
	if err := db.SaveObservation(obs); err != nil {
		db.Close()
		t.Fatalf("saving an observation: %v", err)
	}
	db.Close()

	opens, err := keyOpensDatabase(dbPath, key)
	if err != nil {
		t.Fatalf("probing a WAL database: %v", err)
	}
	if !opens {
		t.Error("the correct key did not open a WAL database")
	}

	opens, err = keyOpensDatabase(dbPath, testKey(0x78))
	if err != nil {
		t.Fatalf("probing a WAL database with the wrong key reported an error rather than a wrong key: %v", err)
	}
	if opens {
		t.Error("a wrong key opened the database")
	}
}

// A keychain that could not be reached must stop resolution, not read as "no
// keys stored" — that path ends in a generated key and an orphaned database.
func TestUnreachableKeychainStopsResolution(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory.db")
	fk := &fakeKeychain{listErr: keychain.ErrNoKeychainSession}
	fk.install(t)

	_, _, err := ResolveDBKey(dbPath)
	if !errors.Is(err, keychain.ErrNoKeychainSession) {
		t.Fatalf("got %v, want ErrNoKeychainSession", err)
	}
	if len(fk.created) != 0 {
		t.Error("a key was generated even though the keychain could not be read")
	}
}

func hashFile(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return sha256.Sum256(data)
}

// "I could not look" is not "there is nothing there". A stat that fails for any
// reason other than not-exist has to stop resolution: the path it could not
// inspect may well be a database, and the next step after "no database" is
// generating a key.
func TestUninspectableDatabaseIsAnErrorNotAnAbsence(t *testing.T) {
	t.Run("a directory in the database's place", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "memory.db")
		if err := os.Mkdir(dbPath, 0755); err != nil {
			t.Fatal(err)
		}
		fk := &fakeKeychain{}
		fk.install(t)

		if _, _, err := ResolveDBKey(dbPath); err == nil {
			t.Fatal("resolved against a directory; want an error")
		}
		if len(fk.created) != 0 {
			t.Error("a key was generated for a path that is not a file")
		}
	})

	t.Run("a directory that cannot be searched", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission bits do not stop stat on Windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("root can stat through a 0000 directory")
		}
		parent := filepath.Join(t.TempDir(), "data")
		if err := os.Mkdir(parent, 0755); err != nil {
			t.Fatal(err)
		}
		dbPath := filepath.Join(parent, "memory.db")
		if err := os.WriteFile(dbPath, []byte("not empty"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(parent, 0755) })

		fk := &fakeKeychain{}
		fk.install(t)

		_, _, err := ResolveDBKey(dbPath)
		if err == nil {
			t.Fatal("resolved against an unreadable path; want an error")
		}
		if errors.Is(err, os.ErrNotExist) {
			t.Errorf("reported the database as absent: %v", err)
		}
		if len(fk.created) != 0 {
			t.Error("a key was generated for a database that could not be inspected — that orphans it")
		}
	})
}

// The probe opens read-only, so a candidate can be tested against a database
// without the file or its sidecars changing at all — whichever way the test
// comes out.
func TestProbeDoesNotModifyTheDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "memory.db")
	key := testKey(0x55)
	writeDatabase(t, dbPath, key, "untouched")

	before, beforeFiles := hashFile(t, dbPath), dirListing(t, dir)

	for _, tc := range []struct {
		name string
		key  []byte
		want bool
	}{
		{"the right key", key, true},
		{"a wrong key", testKey(0x56), false},
	} {
		opens, err := keyOpensDatabase(dbPath, tc.key)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if opens != tc.want {
			t.Errorf("%s: opened=%v, want %v", tc.name, opens, tc.want)
		}
		if hashFile(t, dbPath) != before {
			t.Fatalf("%s: the database changed", tc.name)
		}
		if got := dirListing(t, dir); got != beforeFiles {
			t.Fatalf("%s: sidecar files changed: %q, was %q", tc.name, got, beforeFiles)
		}
	}

	// Read-only also means a probe cannot bring a database into existence at a
	// path where there was none — the driver otherwise opens every connection
	// with SQLITE_OPEN_CREATE.
	missing := filepath.Join(dir, "not-there.db")
	if _, err := keyOpensDatabase(missing, key); err == nil {
		t.Error("probing a path with no database succeeded")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the probe created %s", missing)
	}
}

// dirListing is every filename in dir, so a -wal or -journal appearing during a
// probe is caught rather than only a change to the database itself.
func dirListing(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name(), err)
		}
		names = append(names, fmt.Sprintf("%s:%d", e.Name(), info.Size()))
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}
