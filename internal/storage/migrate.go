// ABOUTME: Verified migration and removal of the legacy plaintext observation store.
// ABOUTME: Plaintext is deleted only after every entry is read back out of SQLCipher and matched.
package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// legacyPlaintextDirs are the two names an older build could have left
// unencrypted observations under. observation/ is the live legacy store;
// observation.migrated/ is what an earlier build's migration renamed it to and
// then kept forever, which is the policy this file exists to end.
var legacyPlaintextDirs = []string{"observation", "observation.migrated"}

// maxListedProblems caps how many individual files an error names. Someone
// looking at a wall of a thousand identical lines learns less than someone
// looking at ten and a count.
const maxListedProblems = 10

// LegacyPlaintextError reports a legacy plaintext tree that could not be made
// owner-only. It carries the exact path because every remedy is something the
// user has to run against that one directory.
type LegacyPlaintextError struct {
	Path string
	Err  error
}

func (e *LegacyPlaintextError) Error() string {
	return fmt.Sprintf("legacy plaintext observations at %s could not be made owner-only: %v", e.Path, e.Err)
}

func (e *LegacyPlaintextError) Unwrap() error { return e.Err }

// Remedy is the instruction to put in front of the user.
func (e *LegacyPlaintextError) Remedy() string {
	return fmt.Sprintf(
		"Make %s owner-only yourself — `chmod -R go-rwx %s` — and check it is yours to change with `ls -ld %s`.",
		e.Path, e.Path, e.Path,
	)
}

// HardenLegacyPlaintext makes every known legacy plaintext observation tree
// under dataDir owner-only. Trees that do not exist are skipped.
//
// This is a preflight, run before the key lookup that decides whether anything
// else can happen at all. The reasoning is that a start which fails still has
// to leave the machine better than it found it: whatever an older build wrote
// in the clear is readable by every account on the box right now, and the
// keychain being unreachable does not make that less true. Tightening modes
// neither reads nor rewrites the files, so it is safe to do before knowing
// whether the rest of startup will succeed.
func HardenLegacyPlaintext(dataDir string) error {
	for _, name := range legacyPlaintextDirs {
		path := filepath.Join(dataDir, name)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return &LegacyPlaintextError{Path: path, Err: err}
		}
		if err := HardenTree(path); err != nil {
			return &LegacyPlaintextError{Path: path, Err: err}
		}
	}
	return nil
}

// HardenTree sets every directory under root to 0700 and every regular file to
// 0600, root included. It changes modes only — no entry is read, moved, or
// removed.
//
// Exported because os.Rename is not the only way plaintext observations end up
// somewhere new: doctor --fix moves corrupted ones into a quarantine directory,
// and a rename carries the file's old mode with it wherever it goes.
func HardenTree(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var want os.FileMode
		switch {
		case d.IsDir():
			want = dirMode
		case d.Type().IsRegular():
			want = fileMode
		default:
			// Symlinks and other irregular entries are left alone on purpose:
			// os.Chmod follows a symlink, so tightening one here would change
			// the mode of whatever it points at, which need not be inside this
			// tree.
			return nil
		}
		// Only chmod what is actually wrong. This walk runs on every CLI
		// invocation now, and an archive that is already owner-only should cost
		// a stat per entry, not a write per entry.
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm() == want {
			return nil
		}
		return os.Chmod(path, want)
	})
}

// legacyQuarantineDirName is where entries that cannot be migrated are put.
// It sits beside the data rather than inside the tree being removed, because
// the tree is about to be deleted.
const legacyQuarantineDirName = "legacy-migration-quarantine"

// quarantineManifestName records what was set aside and why, so the answer
// survives log rotation.
const quarantineManifestName = "manifest.json"

// QuarantineLogMarker prefixes every quarantine log line. `sinesync daemon
// start` picks these out of the daemon log to show the user what happened
// inside a child process they never see.
const QuarantineLogMarker = "[migrate] QUARANTINED"

// QuarantinedEntry is one legacy file that could not be migrated and was moved
// out of the way instead of blocking startup or being deleted.
type QuarantinedEntry struct {
	OriginalPath   string    `json:"originalPath"`
	QuarantinePath string    `json:"quarantinePath"`
	Reason         string    `json:"reason"`
	QuarantinedAt  time.Time `json:"quarantinedAt"`
}

// Describe is the one-line form used in logs and in the terminal.
func (q QuarantinedEntry) Describe() string {
	return fmt.Sprintf("%s (was %s): %s", q.QuarantinePath, q.OriginalPath, q.Reason)
}

// LegacyCleanupError reports a legacy tree that could not be finished, with the
// plaintext left exactly where it was.
//
// This is now the rare case. Entries that cannot be migrated are quarantined
// rather than fatal; what remains here is the filesystem refusing to cooperate
// — a file that cannot be secured, a move that fails, a directory that cannot
// be removed. Those are worth stopping for, because they mean this code no
// longer knows what state the data is in.
type LegacyCleanupError struct {
	Path     string
	Problems []string
}

func (e *LegacyCleanupError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "legacy plaintext observations at %s were kept, not removed: %d could not be handled safely.",
		e.Path, len(e.Problems))
	for i, p := range e.Problems {
		if i == maxListedProblems {
			fmt.Fprintf(&b, "\n  ... and %d more", len(e.Problems)-maxListedProblems)
			break
		}
		fmt.Fprintf(&b, "\n  %s", p)
	}
	return b.String()
}

// Remedy tells the user what state they are in and what to do about it.
func (e *LegacyCleanupError) Remedy() string {
	return fmt.Sprintf(
		"Nothing in %s was deleted — it still holds every byte, owner-only. "+
			"Check that %s and everything in it is readable and writable by you (`ls -la %s`), then retry.",
		e.Path, e.Path, e.Path,
	)
}

// legacyDest is the narrow slice of the encrypted store that migration needs.
//
// It is an interface rather than *SQLCipherStorage for one reason: the
// verification below guards against a database that accepts a write and then
// returns something else, and SQLCipher does not do that. Without a stand-in
// there is no way to execute the guard that protects against deleting the only
// readable copy of someone's data, and an unexecuted guard is a guess.
type legacyDest interface {
	GetObservation(id string) (*Observation, error)
	GetObservationVector(id string) ([]float32, error)
	SaveObservation(obs *Observation) error
	EnsureSession(sessionID, project string, startedAtEpoch int64) error
}

// CleanupLegacyPlaintext migrates every legacy plaintext observation into the
// encrypted database and removes the plaintext, one tree at a time.
//
// It replaces a policy of renaming the directory and keeping it indefinitely,
// which left an unencrypted copy of everything the user had ever recorded
// sitting next to the encrypted one, forever, making the encryption decorative.
//
// Two rules hold the whole thing together. Nothing is deleted without being
// read back out of SQLCipher and compared field by field — an INSERT that
// returns no error is not evidence the observation survived the schema. And
// nothing that cannot be migrated is either deleted or allowed to stop the
// daemon: it is secured, moved into a quarantine directory, and reported. A
// user with one stray file in a legacy directory has done nothing wrong and
// should not be left with a daemon that will not start.
func CleanupLegacyPlaintext(dest *SQLCipherStorage, dataDir string) ([]QuarantinedEntry, error) {
	return cleanupLegacyPlaintext(dest, dataDir)
}

func cleanupLegacyPlaintext(dest legacyDest, dataDir string) ([]QuarantinedEntry, error) {
	var quarantined []QuarantinedEntry
	for _, name := range legacyPlaintextDirs {
		entries, err := cleanupLegacyTree(dest, dataDir, filepath.Join(dataDir, name))
		quarantined = append(quarantined, entries...)
		if err != nil {
			return quarantined, err
		}
	}
	if len(quarantined) > 0 {
		if err := writeQuarantineManifest(dataDir, quarantined); err != nil {
			// The files are safe; only the record of them failed. Say so and
			// carry on — the log lines below still name every one.
			log.Printf("[migrate] Could not write the quarantine manifest: %v", err)
		}
	}
	return quarantined, nil
}

// cleanupLegacyTree handles one directory. Everything in it is either verified
// into the encrypted database or moved to quarantine; then the directory goes.
func cleanupLegacyTree(dest legacyDest, dataDir, path string) ([]QuarantinedEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, &LegacyCleanupError{
			Path:     path,
			Problems: []string{fmt.Sprintf("the directory itself could not be read: %v", err)},
		}
	}

	type offender struct {
		name   string
		reason string
	}
	var offenders []offender
	verified := 0

	for _, entry := range entries {
		name := entry.Name()

		// Strict about what is allowed to be in here. The legacy store wrote
		// flat .json files and nothing else, so anything else is something this
		// code has never seen and cannot claim to have migrated.
		switch {
		case !entry.Type().IsRegular():
			offenders = append(offenders, offender{name, "not a regular file — the legacy store held only flat .json observations"})
			continue
		case filepath.Ext(name) != ".json":
			offenders = append(offenders, offender{name, "not a .json file, so there is no observation in it to migrate"})
			continue
		}

		obs, err := readLegacyObservation(filepath.Join(path, name))
		if err != nil {
			offenders = append(offenders, offender{name, err.Error()})
			continue
		}
		if err := persistAndVerify(dest, obs); err != nil {
			offenders = append(offenders, offender{name, err.Error()})
			continue
		}
		verified++
	}

	var quarantined []QuarantinedEntry
	var problems []string
	for _, o := range offenders {
		entry, err := quarantineEntry(dataDir, filepath.Join(path, o.name), o.reason)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", o.name, err))
			continue
		}
		log.Printf("%s %s", QuarantineLogMarker, entry.Describe())
		quarantined = append(quarantined, entry)
	}

	if len(problems) > 0 {
		// Something could not be secured or moved. Stop here with the tree
		// intact: removing it now would delete verified observations while
		// leaving unhandled ones behind, and this code can no longer say what
		// state the directory is in.
		if err := HardenTree(path); err != nil {
			problems = append(problems, fmt.Sprintf("(it could also not be re-secured to owner-only: %v)", err))
		}
		return quarantined, &LegacyCleanupError{Path: path, Problems: problems}
	}

	// Say what was verified before saying what is being deleted, and name the
	// exact path in both. Someone reading this later needs to be able to tell
	// which directory went away and on what basis.
	log.Printf("[migrate] Verified encrypted copies of all %d remaining plaintext observations in %s", verified, path)
	log.Printf("[migrate] Removing plaintext observations at %s", path)
	if err := os.RemoveAll(path); err != nil {
		return quarantined, &LegacyCleanupError{
			Path: path,
			Problems: []string{fmt.Sprintf(
				"every remaining observation verified inside the encrypted database, but the plaintext directory could not be removed: %v", err)},
		}
	}
	log.Printf("[migrate] Removed %s", path)
	return quarantined, nil
}

// quarantineEntry secures one offending entry and moves it out of the tree.
//
// Secured first, then moved: os.Rename carries the source's mode with it, and a
// file that cannot be made owner-only must not be relocated into a directory
// this code has just told the user is private.
func quarantineEntry(dataDir, srcPath, reason string) (QuarantinedEntry, error) {
	quarantineDir := filepath.Join(dataDir, legacyQuarantineDirName)
	if err := os.MkdirAll(quarantineDir, dirMode); err != nil {
		return QuarantinedEntry{}, fmt.Errorf("the quarantine directory could not be created: %w", err)
	}
	// MkdirAll leaves an existing directory's mode alone.
	if err := os.Chmod(quarantineDir, dirMode); err != nil {
		return QuarantinedEntry{}, fmt.Errorf("the quarantine directory could not be made owner-only: %w", err)
	}

	info, err := os.Lstat(srcPath)
	if err != nil {
		return QuarantinedEntry{}, fmt.Errorf("it could not be examined: %w", err)
	}
	switch {
	case info.IsDir():
		if err := HardenTree(srcPath); err != nil {
			return QuarantinedEntry{}, fmt.Errorf("it could not be made owner-only: %w", err)
		}
	case info.Mode().IsRegular():
		if err := os.Chmod(srcPath, fileMode); err != nil {
			return QuarantinedEntry{}, fmt.Errorf("it could not be made owner-only: %w", err)
		}
		// Symlinks and irregular entries are moved as they are: os.Chmod
		// follows a symlink and would retarget the mode change outside the tree.
	}

	dstPath, err := reserveQuarantinePath(quarantineDir, filepath.Base(srcPath), info.IsDir())
	if err != nil {
		return QuarantinedEntry{}, err
	}
	if err := os.Rename(srcPath, dstPath); err != nil {
		os.Remove(dstPath) // drop the placeholder; the source is untouched
		return QuarantinedEntry{}, fmt.Errorf("it could not be moved to %s: %w", dstPath, err)
	}

	return QuarantinedEntry{
		OriginalPath:   srcPath,
		QuarantinePath: dstPath,
		Reason:         reason,
		QuarantinedAt:  time.Now(),
	}, nil
}

// reserveQuarantinePath picks a free name in the quarantine directory.
//
// Nothing already in quarantine may be overwritten — the same filename can
// legitimately appear in both legacy trees, and a second run must not clobber
// what a first one set aside. For files the name is claimed with O_EXCL rather
// than merely checked, so the answer cannot go stale between the check and the
// rename; os.Rename then replaces that empty placeholder.
func reserveQuarantinePath(dir, base string, isDir bool) (string, error) {
	for i := 0; i < 1000; i++ {
		candidate := filepath.Join(dir, base)
		if i > 0 {
			candidate = filepath.Join(dir, fmt.Sprintf("%s.%d", base, i))
		}
		if isDir {
			if _, err := os.Lstat(candidate); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				return "", fmt.Errorf("the quarantine directory could not be checked: %w", err)
			}
			return candidate, nil
		}
		f, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
		if err == nil {
			f.Close()
			return candidate, nil
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("a place in quarantine could not be claimed: %w", err)
		}
	}
	return "", fmt.Errorf("no free name for %s in %s after 1000 tries", base, dir)
}

// writeQuarantineManifest records every quarantined entry, appending to what is
// already there so an earlier run's record is not lost.
func writeQuarantineManifest(dataDir string, added []QuarantinedEntry) error {
	quarantineDir := filepath.Join(dataDir, legacyQuarantineDirName)
	manifestPath := filepath.Join(quarantineDir, quarantineManifestName)

	var all []QuarantinedEntry
	if existing, err := os.ReadFile(manifestPath); err == nil {
		if err := json.Unmarshal(existing, &all); err != nil {
			// An unreadable manifest is not a reason to lose the new entries.
			log.Printf("[migrate] The existing quarantine manifest could not be parsed and will be replaced: %v", err)
			all = nil
		}
	}
	all = append(all, added...)

	blob, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	return writeFilePrivate(manifestPath, blob, fileMode)
}

// readLegacyObservation reads one legacy file and insists on understanding it.
func readLegacyObservation(path string) (*Observation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not be read: %w", err)
	}

	var item StoredItem
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, fmt.Errorf("is not valid stored-item JSON: %w", err)
	}
	if item.ID == "" {
		return nil, errors.New("has no id, so it is not something the legacy store wrote")
	}

	dataBytes, err := json.Marshal(item.Data)
	if err != nil {
		return nil, fmt.Errorf("its data field could not be re-encoded: %w", err)
	}
	var obs Observation
	if err := json.Unmarshal(dataBytes, &obs); err != nil {
		return nil, fmt.Errorf("its data field is not an observation: %w", err)
	}
	if obs.ID == "" {
		return nil, errors.New("the observation inside it has no id")
	}
	if obs.ID != item.ID {
		return nil, fmt.Errorf("the file's id %q and the observation's id %q disagree", item.ID, obs.ID)
	}
	return &obs, nil
}

// persistAndVerify writes one observation to SQLCipher and reads it back out.
//
// The read-back is the entire safety argument for deleting the plaintext. A
// successful INSERT means the database accepted the statement, not that the
// observation survived the trip through the schema — a column the serializer
// forgot, a type that does not round-trip, a trigger that rewrote something.
// Nothing here trusts an ID match: it compares content, and it compares the
// embedding vector separately because the vector lives in its own table and its
// insert is deliberately non-fatal.
func persistAndVerify(dest legacyDest, obs *Observation) error {
	existing, err := dest.GetObservation(obs.ID)
	switch {
	case err == nil && existing != nil:
		// Already in the database. Same content means an earlier run did this
		// and the plaintext is redundant; different content means two different
		// observations are claiming one id, and overwriting one with the other
		// would destroy whichever is not in this file.
		if !sameObservation(existing, obs) {
			return fmt.Errorf(
				"id %s is already in the encrypted database with different content — migrating this file would overwrite it",
				obs.ID)
		}
		return verifyVector(dest, obs)
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("the encrypted database could not be checked for id %s: %w", obs.ID, err)
	}

	// observations.session_id is a foreign key into sessions, and a legacy JSON
	// observation references a session that has never existed as a row — the
	// live capture path calls EnsureSession before saving, and the old
	// migration did not. Without this, every observation carrying a sessionId
	// fails on "FOREIGN KEY constraint failed", which is how the previous
	// migration came to report "Migrated 0 observations" and rename the
	// directory anyway. EnsureSession is INSERT OR IGNORE, so a session that
	// already exists keeps the row it has; creating the row preserves the
	// reference, where dropping the session id to make the insert succeed would
	// quietly lose it.
	if obs.Core.SessionID != "" {
		if err := dest.EnsureSession(obs.Core.SessionID, obs.Core.Project, obs.Core.CreatedAt.Unix()); err != nil {
			return fmt.Errorf("its session %s could not be recorded in the encrypted database: %w", obs.Core.SessionID, err)
		}
	}

	if err := dest.SaveObservation(obs); err != nil {
		return fmt.Errorf("could not be written to the encrypted database: %w", err)
	}

	stored, err := dest.GetObservation(obs.ID)
	if err != nil {
		return fmt.Errorf("was written to the encrypted database but could not be read back: %w", err)
	}
	if !sameObservation(stored, obs) {
		return fmt.Errorf("what the encrypted database returns for id %s does not match what was written", obs.ID)
	}
	return verifyVector(dest, obs)
}

// verifyVector checks the embedding actually landed in the sqlite-vec table.
//
// SaveObservation logs a warning and carries on when the vector insert fails,
// so an observation can be fully present in the observations table with no
// vector at all. That is fine for a live capture — search degrades to FTS — and
// not fine as grounds for deleting the file the vector came from.
//
// An observation with no vector of its own has nothing to verify; anything the
// database happens to hold for that id is not something the plaintext can lose.
func verifyVector(dest legacyDest, obs *Observation) error {
	if len(obs.Embedding.Vector) == 0 {
		return nil
	}

	stored, err := dest.GetObservationVector(obs.ID)
	if err != nil {
		return fmt.Errorf("its embedding could not be read back from the encrypted database: %w", err)
	}
	if len(stored) == 0 {
		return fmt.Errorf("its %d-dimension embedding is not in the encrypted database — the vector insert did not take", len(obs.Embedding.Vector))
	}
	if len(stored) != len(obs.Embedding.Vector) {
		return fmt.Errorf("its embedding came back with %d dimensions, not the %d that were written", len(stored), len(obs.Embedding.Vector))
	}
	for i := range stored {
		if stored[i] != obs.Embedding.Vector[i] {
			return fmt.Errorf("its embedding differs from what was written, first at dimension %d", i)
		}
	}
	return nil
}

// sameObservation reports whether two observations carry the same content.
//
// Embedding.Vector is the one field excluded here, and it is not excluded from
// verification: GetObservation does not populate it, because vectors live in a
// separate virtual table, so it is checked by verifyVector against that table
// instead.
//
// Timestamps are compared exactly. They can be, since SaveObservation writes
// RFC3339Nano; before that it wrote RFC3339 and truncated every observation to
// the second, which made an exact comparison impossible and a lossless deletion
// with it.
func sameObservation(a, b *Observation) bool {
	return canonicalObservation(a) == canonicalObservation(b)
}

func canonicalObservation(obs *Observation) string {
	c := *obs
	c.Embedding.Vector = nil
	out, err := json.Marshal(c)
	if err != nil {
		// Unreachable for a struct that came out of json.Unmarshal. If it ever
		// happens, an unequal sentinel is the safe answer: it keeps the
		// plaintext instead of deleting it.
		return fmt.Sprintf("uncomparable:%s:%v", obs.ID, err)
	}
	return string(out)
}
