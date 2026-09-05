// ABOUTME: Chooses which stored key opens memory.db by testing candidates against the file itself.
// ABOUTME: Selection never writes: it may not generate, rekey, delete, or rewrite anything.
package storage

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	sqlite3 "github.com/mutecomm/go-sqlcipher/v4"

	"github.com/sinesync/cli/internal/keychain"
)

// Indirected for tests: a CI runner has no OS keychain, and the sequence this
// file exists to fix — first run before login, then a login, then a restart —
// is a sequence of keychain states.
var (
	dbKeyCandidates  = keychain.DBKeyCandidates
	createLocalDBKey = keychain.CreateLocalDBKey
)

// DBKeyMismatchError means a database exists and none of the stored keys opens
// it. It is never returned alongside a repair: the database is left exactly as
// it was found, because a key that is merely missing from this machine may
// still be recoverable, and a database deleted to make an error go away is not.
type DBKeyMismatchError struct {
	Path  string
	Tried []keychain.DBKeySource
}

func (e *DBKeyMismatchError) Error() string {
	if len(e.Tried) == 0 {
		return fmt.Sprintf("%s exists but no database key is stored in the keychain, so it cannot be opened", e.Path)
	}
	tried := make([]string, len(e.Tried))
	for i, s := range e.Tried {
		tried[i] = string(s)
	}
	return fmt.Sprintf("%s could not be opened with any stored key (tried the %s)", e.Path, strings.Join(tried, " and the "))
}

// Remedy is the user-facing half, in the shape the daemon's refusal and the
// CLI's error both already use.
func (e *DBKeyMismatchError) Remedy() string {
	return "The database is intact and was not modified. Its key is not in this machine's keychain —\n" +
		"restore the keychain entry it was created with (a keychain restored from backup, or the\n" +
		"login keychain of the account that created it) rather than deleting the database."
}

// ResolveDBKey returns the key that opens dbPath, and where it came from.
//
// The rule is: an existing database decides. Every stored candidate is tested
// against the file, non-destructively, and the one that opens it wins no matter
// what order it is stored in. Only when there is no database does preference
// order apply — derived key, then local key, then a newly generated local key.
//
// This is the fix for a specific, reproducible way to lose access to a working
// install. Run sinesync before logging in and the database is created with the
// local key. Log in, and a derived key is stored. Restart, and the old
// resolution — "derived key if one exists" — handed over a key that had never
// encrypted anything, against a database that was completely intact. The daemon
// fails closed, so the result was a refusal to start, and the obvious next move
// for a user staring at "wrong key?" is to delete the database.
//
// Nothing here writes to the database. Testing a candidate opens a second,
// read-only connection, so a probe cannot modify the file even if something
// below it tried to.
func ResolveDBKey(dbPath string) ([]byte, keychain.DBKeySource, error) {
	candidates, err := dbKeyCandidates()
	if err != nil {
		return nil, "", err
	}

	exists, err := DatabaseExists(dbPath)
	if err != nil {
		return nil, "", err
	}
	if !exists {
		// Fresh install. There is nothing to be wrong about yet, so preference
		// order is the whole answer: prefer the derived key so an authenticated
		// user's database is bound to their credentials from the start.
		if len(candidates) > 0 {
			return candidates[0].Key, candidates[0].Source, nil
		}
		key, err := createLocalDBKey()
		if err != nil {
			return nil, "", err
		}
		return key, keychain.DBKeyLocal, nil
	}

	return ResolveDBKeyFrom(dbPath, candidates)
}

// ResolveDBKeyFrom is ResolveDBKey without the keychain and without the create
// path: it answers "which of these opens the database that is already there",
// and nothing else.
//
// It exists for callers that must not create a key under any circumstances —
// teardown, which needs to know which keychain entry to spare, would do real
// damage by generating one — and because it makes the selection rule testable
// against a real database without a real keychain.
//
// A database must already exist at dbPath. "No database" is not an answer this
// function is allowed to improvise on.
func ResolveDBKeyFrom(dbPath string, candidates []keychain.DBKeyCandidate) ([]byte, keychain.DBKeySource, error) {
	exists, err := DatabaseExists(dbPath)
	if err != nil {
		return nil, "", err
	}
	if !exists {
		return nil, "", fmt.Errorf("no database at %s to choose a key for", dbPath)
	}

	tried := make([]keychain.DBKeySource, 0, len(candidates))
	for _, c := range candidates {
		opens, err := keyOpensDatabase(dbPath, c.Key)
		if err != nil {
			// Not "this key is wrong" — a locked file, a permission problem, a
			// truncated database. Reporting it as a wrong key would send the
			// user after their keychain for a fault that is not in it.
			return nil, "", fmt.Errorf("checking the %s against %s: %w", c.Source, dbPath, err)
		}
		if opens {
			return c.Key, c.Source, nil
		}
		tried = append(tried, c.Source)
	}

	// A database exists that nothing can open. Generating a key here would
	// "succeed" and orphan it, so this is where resolution stops.
	return nil, "", &DBKeyMismatchError{Path: dbPath, Tried: tried}
}

// DatabaseExists reports whether dbPath holds a database to be bound by.
//
// Only two answers are safe: "there is one" and "there is definitely not one".
// Anything else is an error. A stat that fails for any reason other than
// not-exist — a permission problem on the directory, an I/O error, a path that
// is not a file — means the database cannot be inspected, and treating that as
// "no database" leads straight to generating a key over the top of one that
// exists.
//
// Zero bytes counts as absent: SQLCipher treats an empty file as a new
// database, so any key at all would "open" it, and a crash between creating the
// file and writing the header must not pin the install to whichever key was
// tried first.
func DatabaseExists(dbPath string) (bool, error) {
	info, err := os.Stat(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("cannot inspect %s, so it is not known whether a database is there: %w", dbPath, err)
	}
	if !info.Mode().IsRegular() {
		// A directory, a device, a socket. Not something to open, and not
		// something to quietly create a key for either.
		return false, fmt.Errorf("%s is not a regular file (mode %s), so it cannot be opened as a database", dbPath, info.Mode().Type())
	}
	return info.Size() > 0, nil
}

// keyOpensDatabase reports whether key decrypts the database at dbPath.
//
// (false, nil) means the key is wrong. A non-nil error means the question could
// not be answered — the caller must not read that as a wrong key.
func keyOpensDatabase(dbPath string, key []byte) (bool, error) {
	db, err := sql.Open("sqlite3", probeDSN(dbPath, key))
	if err != nil {
		return false, fmt.Errorf("open probe connection: %w", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&count); err != nil {
		// A wrong SQLCipher key does not decrypt the header, so the file stops
		// looking like a database at all: SQLITE_NOTADB. Anything else — busy,
		// locked, I/O, permissions — is a different question and is passed up.
		var serr sqlite3.Error
		if errors.As(err, &serr) && serr.Code == sqlite3.ErrNotADB {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// probeDSN builds a connection string that can read the database and do
// nothing else.
//
// mode=ro is the part that matters, and it has to be a file: URI to get there:
// the driver opens every other DSN with SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE
// and offers no way to change those flags. A URI mode parameter may only narrow
// that, which is exactly what is wanted — the probe cannot write, and cannot
// create a database at a path where none was found. PRAGMA query_only is kept
// behind it as a second lock on the same door, in case a future driver or
// SQLite version stops honouring one of them.
//
// The parameter names are the driver's own: it recognises _pragma_key,
// _busy_timeout, _foreign_keys, _journal_mode and _query_only. A
// _pragma_-prefixed spelling of the others parses as a URL parameter and is
// then silently dropped, so the spelling here is not cosmetic. mode is not the
// driver's at all — it is passed through to SQLite, which ignores the
// parameters it does not recognise.
//
// _busy_timeout lets a probe wait out the daemon holding a write lock instead
// of reporting a locked database as an unopenable one.
func probeDSN(dbPath string, key []byte) string {
	// Absolute-path form with an empty authority: file:///home/u/memory.db, and
	// on Windows file:///C:/Users/u/memory.db. ToSlash and the leading slash are
	// what make the Windows spelling come out right; EscapedPath covers the
	// home directory with a space in it.
	p := filepath.ToSlash(dbPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	escaped := (&url.URL{Path: p}).EscapedPath()

	return fmt.Sprintf("file://%s?mode=ro&_pragma_key=%s&_query_only=1&_busy_timeout=5000",
		escaped, url.QueryEscape("x'"+hex.EncodeToString(key)+"'"))
}
