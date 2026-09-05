// ABOUTME: Teardown must not delete the keychain entry that opens a database the user kept.
// ABOUTME: Which entry that is comes from the database itself, never from a guess.
package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/keychain"
	"github.com/sinesync/cli/internal/storage"
)

func tdKey(fill byte) []byte {
	key := make([]byte, keychain.DBKeyLen)
	for i := range key {
		key[i] = fill
	}
	return key
}

// tdDatabase writes a real SQLCipher database encrypted with key. The selection
// this file is about is a real decryption attempt against a real file, so a
// stubbed resolver would leave the actual question untested.
func tdDatabase(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "memory.db")
	db, err := storage.NewSQLCipherStorage(path, key)
	if err != nil {
		t.Fatalf("creating the database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing the database: %v", err)
	}
	return path
}

// Both stored keys are offered every time. Which one comes back has to be
// decided by the file, because that is the only thing that knows.
func tdCandidates(derived, local []byte) []keychain.DBKeyCandidate {
	return []keychain.DBKeyCandidate{
		{Source: keychain.DBKeyDerived, Key: derived},
		{Source: keychain.DBKeyLocal, Key: local},
	}
}

// The regression. Teardown used to keep 'local-db-key' unconditionally, so a
// user who logged in, then kept their database, had the derived key it was
// encrypted with deleted out from under it.
func TestKeptDerivedKeyDatabaseKeepsTheDerivedEntry(t *testing.T) {
	derived, local := tdKey(0xD1), tdKey(0x10)
	path := tdDatabase(t, derived)

	keep, err := preservedKeychainEntries(path, true, tdCandidates(derived, local))
	if err != nil {
		t.Fatalf("resolving the kept database: %v", err)
	}
	if len(keep) != 1 || keep[0] != keychain.EntryDerivedKey {
		t.Fatalf("kept %v, want just %q — the key the database is actually encrypted with", keep, keychain.EntryDerivedKey)
	}
}

// And the case that always worked must keep working: someone who never logged
// in has a local-key database, and that entry is the one to spare.
func TestKeptLocalKeyDatabaseKeepsTheLocalEntry(t *testing.T) {
	derived, local := tdKey(0xD1), tdKey(0x10)
	path := tdDatabase(t, local)

	keep, err := preservedKeychainEntries(path, true, tdCandidates(derived, local))
	if err != nil {
		t.Fatalf("resolving the kept database: %v", err)
	}
	if len(keep) != 1 || keep[0] != keychain.EntryLocalDBKey {
		t.Fatalf("kept %v, want just %q", keep, keychain.EntryLocalDBKey)
	}
}

// When the answer cannot be established, nothing may be cleared. Teardown can
// be run again; a deleted key cannot be brought back.
func TestUnresolvableKeptDatabaseClearsNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (path string, candidates []keychain.DBKeyCandidate)
	}{
		{
			name: "no stored key opens it",
			setup: func(t *testing.T) (string, []keychain.DBKeyCandidate) {
				return tdDatabase(t, tdKey(0xAA)), tdCandidates(tdKey(0xD1), tdKey(0x10))
			},
		},
		{
			name: "no keys stored at all",
			setup: func(t *testing.T) (string, []keychain.DBKeyCandidate) {
				return tdDatabase(t, tdKey(0xAA)), nil
			},
		},
		{
			name: "the database cannot be inspected",
			setup: func(t *testing.T) (string, []keychain.DBKeyCandidate) {
				dir := t.TempDir()
				path := filepath.Join(dir, "memory.db")
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
				return path, tdCandidates(tdKey(0xD1), tdKey(0x10))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, candidates := tc.setup(t)

			keep, err := preservedKeychainEntries(path, true, candidates)
			if err == nil {
				t.Fatalf("returned %v with no error; teardown would have cleared the keychain", keep)
			}
			if keep != nil {
				t.Errorf("returned %v alongside the error", keep)
			}

			// What the caller does with that error is the part that matters: it
			// must stop, and it must say the database was kept and nothing was
			// deleted.
			msg := teardownKeyError(path, err).Error()
			for _, want := range []string{"no keychain credentials were deleted", "was kept and is unchanged", path} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal does not mention %q:\n%s", want, msg)
				}
			}
		})
	}
}

// A mismatch specifically must arrive as the storage layer's typed error, so the
// message a user sees names the keys that were tried rather than something
// generic.
func TestUnresolvableKeptDatabaseReportsAMismatch(t *testing.T) {
	path := tdDatabase(t, tdKey(0xAA))

	_, err := preservedKeychainEntries(path, true, tdCandidates(tdKey(0xD1), tdKey(0x10)))
	var mismatch *storage.DBKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("got %v, want a *storage.DBKeyMismatchError", err)
	}
	if len(mismatch.Tried) != 2 {
		t.Errorf("reported %d keys tried, want both", len(mismatch.Tried))
	}
}

// A deleted or absent database keeps nothing, exactly as before — and asks the
// database nothing, so a machine with no keychain session can still finish a
// teardown that has no database to protect.
func TestDeletedOrAbsentDatabaseKeepsNothing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "memory.db")

	keep, err := preservedKeychainEntries(missing, false, tdCandidates(tdKey(0xD1), tdKey(0x10)))
	if err != nil || keep != nil {
		t.Fatalf("deleted database: kept %v, err %v; want nothing kept and no error", keep, err)
	}

	// "Kept" but nothing there: an empty file left by a crashed create holds no
	// memories, so there is no key worth sparing.
	empty := filepath.Join(t.TempDir(), "memory.db")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	keep, err = preservedKeychainEntries(empty, true, tdCandidates(tdKey(0xD1), tdKey(0x10)))
	if err != nil || keep != nil {
		t.Fatalf("empty database: kept %v, err %v; want nothing kept and no error", keep, err)
	}
}

// fakeTeardownKeychain records what step 7 did instead of doing it. The whole
// point of these tests is what is NOT called, which a real keychain cannot show
// and could not be undone if it did.
type fakeTeardownKeychain struct {
	candidates     []keychain.DBKeyCandidate
	candidatesErr  error
	candidatesRuns int
	clearErr       error
	clears         [][]string // one entry per ClearExcept call, holding the keep list
	deleted        []string
}

func (f *fakeTeardownKeychain) deps() teardownKeychain {
	return teardownKeychain{
		candidates: func() ([]keychain.DBKeyCandidate, error) {
			f.candidatesRuns++
			return f.candidates, f.candidatesErr
		},
		clearExcept: func(keep []string) error {
			f.clears = append(f.clears, append([]string(nil), keep...))
			return f.clearErr
		},
		deleteEntry: func(name string) error {
			f.deleted = append(f.deleted, name)
			return nil
		},
	}
}

// Step 7 end to end against a real database: the derived-key case has to reach
// ClearExcept exactly once, with exactly the entry that opens the file.
func TestStep7ClearsPreservingTheKeyThatOpensTheDatabase(t *testing.T) {
	derived, local := tdKey(0xD1), tdKey(0x10)

	cases := []struct {
		name     string
		dbKey    []byte
		wantKept []string
	}{
		{"a database created after login", derived, []string{keychain.EntryDerivedKey}},
		{"a database created before login", local, []string{keychain.EntryLocalDBKey}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tdDatabase(t, tc.dbKey)
			fake := &fakeTeardownKeychain{candidates: tdCandidates(derived, local)}

			if err := clearKeychainCredentials(path, true, fake.deps()); err != nil {
				t.Fatalf("clearing: %v", err)
			}
			if len(fake.clears) != 1 {
				t.Fatalf("ClearExcept called %d times, want exactly 1", len(fake.clears))
			}
			if got := fake.clears[0]; len(got) != 1 || got[0] != tc.wantKept[0] {
				t.Errorf("cleared keeping %v, want %v", got, tc.wantKept)
			}
			if len(fake.deleted) != 3 {
				t.Errorf("deleted %v, want the three session tokens", fake.deleted)
			}
		})
	}
}

// Every way of not knowing which key opens a kept database must reach
// ClearExcept zero times and delete nothing.
func TestStep7ClearsNothingWhenTheKeyCannotBeEstablished(t *testing.T) {
	derived, local := tdKey(0xD1), tdKey(0x10)

	cases := []struct {
		name  string
		setup func(t *testing.T) (string, *fakeTeardownKeychain)
	}{
		{
			name: "no stored key opens the database",
			setup: func(t *testing.T) (string, *fakeTeardownKeychain) {
				return tdDatabase(t, tdKey(0xAA)), &fakeTeardownKeychain{candidates: tdCandidates(derived, local)}
			},
		},
		{
			name: "the keychain cannot be read",
			setup: func(t *testing.T) (string, *fakeTeardownKeychain) {
				return tdDatabase(t, derived), &fakeTeardownKeychain{candidatesErr: keychain.ErrNoKeychainSession}
			},
		},
		{
			name: "the database cannot be inspected",
			setup: func(t *testing.T) (string, *fakeTeardownKeychain) {
				path := filepath.Join(t.TempDir(), "memory.db")
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
				return path, &fakeTeardownKeychain{candidates: tdCandidates(derived, local)}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, fake := tc.setup(t)

			err := clearKeychainCredentials(path, true, fake.deps())
			if err == nil {
				t.Fatal("step 7 succeeded; it must refuse rather than clear on a guess")
			}
			if len(fake.clears) != 0 {
				t.Errorf("ClearExcept was called %d times: %v", len(fake.clears), fake.clears)
			}
			if len(fake.deleted) != 0 {
				t.Errorf("entries were deleted anyway: %v", fake.deleted)
			}
			if !strings.Contains(err.Error(), "no keychain credentials were deleted") {
				t.Errorf("the refusal does not tell the user nothing was deleted:\n%s", err)
			}
		})
	}
}

// A deleted or absent database clears everything, as it always has — and does
// not touch the keychain to decide that, so a headless machine can still finish
// a teardown that has no database to protect.
func TestStep7ClearsEverythingWhenNoDatabaseWasKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.db")
	fake := &fakeTeardownKeychain{candidatesErr: keychain.ErrNoKeychainSession}

	if err := clearKeychainCredentials(path, false, fake.deps()); err != nil {
		t.Fatalf("clearing after a deleted database: %v", err)
	}
	if fake.candidatesRuns != 0 {
		t.Errorf("read the keychain %d times to decide there was nothing to protect", fake.candidatesRuns)
	}
	if len(fake.clears) != 1 || len(fake.clears[0]) != 0 {
		t.Fatalf("cleared %v, want exactly one call keeping nothing", fake.clears)
	}
	if len(fake.deleted) != 3 {
		t.Errorf("deleted %v, want the three session tokens", fake.deleted)
	}
}

// A failed clear is REPORTED but must not abandon the live sync credentials.
//
// This test previously asserted the opposite — that nothing was deleted after a
// clear failure — which encoded a real defect as a requirement: one stuck entry
// meant token, refreshToken and deviceToken were never attempted, and every
// retry stopped in the same place, so the user could not complete a teardown at
// all. Those three are the credentials that still authenticate to the service,
// so they are exactly the ones that must not be hostage to an unrelated failure.
func TestStep7ReportsAFailedClearButStillRemovesLiveCredentials(t *testing.T) {
	path := tdDatabase(t, tdKey(0xD1))
	fake := &fakeTeardownKeychain{
		candidates: tdCandidates(tdKey(0xD1), tdKey(0x10)),
		clearErr:   errors.New("keychain locked"),
	}

	err := clearKeychainCredentials(path, true, fake.deps())
	if err == nil {
		t.Fatal("a failed clear was reported as success")
	}

	for _, want := range []string{"token", "refreshToken", "deviceToken"} {
		found := false
		for _, got := range fake.deleted {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s was never attempted after the clear failed; it is a live credential", want)
		}
	}
}
