// ABOUTME: Enumerates the stored keys that could open the encrypted database.
// ABOUTME: Choosing between them lives in internal/storage, which alone can test a key against the file.
package keychain

import (
	"crypto/rand"
	"fmt"

	"github.com/zalando/go-keyring"
)

// DBKeyLen is the key size SQLCipher is opened with.
const DBKeyLen = 32

// The keychain entries the two database keys live in. Named rather than spelled
// out at each use: teardown decides which entry to spare by asking a
// DBKeySource for its entry name, and a typo there would delete the key to a
// database the user asked to keep.
const (
	EntryDerivedKey = "derived-key"
	EntryLocalDBKey = "local-db-key"
)

// DBKeySource names where a candidate database key was stored. It exists to be
// put in front of a user: "opened with the local key" is the difference between
// a working install and one that is about to be told its memories are gone.
type DBKeySource string

const (
	// DBKeyDerived is derived from the user's credentials at login.
	DBKeyDerived DBKeySource = "derived key (from your login)"
	// DBKeyLocal is generated on first run, before any login.
	DBKeyLocal DBKeySource = "local key (from before you logged in)"
)

// Entry is the keychain entry this key was read from, or "" for a source that
// has none. Callers that clear credentials use it to spare the one entry that
// still opens a database the user kept.
func (s DBKeySource) Entry() string {
	switch s {
	case DBKeyDerived:
		return EntryDerivedKey
	case DBKeyLocal:
		return EntryLocalDBKey
	default:
		return ""
	}
}

// DBKeyCandidate is one stored key that might open the encrypted database.
type DBKeyCandidate struct {
	Source DBKeySource
	Key    []byte
}

// DBKeyCandidates returns every stored key that could open the encrypted
// database, in fresh-install preference order: the derived key first, then the
// local one.
//
// It deliberately does not choose between them. Which key opens an existing
// database is a fact about that file, not about the keychain, and only the
// storage layer can find it out. This function used to be GetOrCreateDBKey,
// which returned the derived key whenever one existed — so a user who ran
// sinesync before logging in got a database encrypted with the local key and
// then, at the next start after login, a "wrong key" refusal against a database
// that was perfectly intact.
//
// The order here still matters, but only for a machine with no database yet.
//
// A candidate that is not DBKeyLen bytes is left out rather than returned:
// SQLCipher is never opened with any other length, so such an entry cannot be
// the key to an existing database and can only crowd the real one out.
//
// An entry that exists but cannot be read is an error, not an absence. Callers
// must not respond to it by generating a replacement, which is why the read
// errors are not folded into "no candidates".
func DBKeyCandidates() ([]DBKeyCandidate, error) {
	// The same guard GetOrCreateDBKey carried, for the same reason: in a
	// context with no keychain session "not found" carries no information, and
	// a caller that reads it as "no key exists" orphans the database.
	if !usable() {
		return nil, ErrNoKeychainSession
	}

	var candidates []DBKeyCandidate
	add := func(source DBKeySource, read func() ([]byte, error)) error {
		key, err := read()
		if err != nil {
			if err == keyring.ErrNotFound {
				return nil
			}
			return fmt.Errorf("%s unreadable: %w", source, err)
		}
		if len(key) != DBKeyLen {
			return nil
		}
		candidates = append(candidates, DBKeyCandidate{Source: source, Key: key})
		return nil
	}

	if err := add(DBKeyDerived, GetDerivedKey); err != nil {
		return nil, err
	}
	if err := add(DBKeyLocal, GetLocalDBKey); err != nil {
		return nil, err
	}
	return candidates, nil
}

// CreateLocalDBKey generates a local database key and stores it.
//
// Only for a machine with no database: creating a key is how an existing
// database stops being readable, so the decision to call this belongs to the
// code that has looked at the disk.
func CreateLocalDBKey() ([]byte, error) {
	if !usable() {
		return nil, ErrNoKeychainSession
	}
	key := make([]byte, DBKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := SetLocalDBKey(key); err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}
	return key, nil
}
