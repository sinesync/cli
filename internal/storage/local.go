package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sinesync/cli/internal/config"
)

// Modes for everything LocalStorage writes. Observations are the user's
// transcripts in plaintext — the whole reason the encrypted backend exists — so
// on a shared or multi-user machine the difference between 0644 and 0600 is the
// difference between private notes and readable ones. 0700 on the directory
// matters as much: it is what stops another user listing the observation IDs
// even when they cannot open the files.
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// writeFilePrivate writes data to path at mode, whether or not path exists,
// without ever putting the existing contents of path at risk.
//
// os.WriteFile is not enough on its own: its mode argument applies only when it
// creates the file, and is masked by the umask even then, so an observation
// rewritten into a file an older build created at 0644 would keep 0644 forever.
//
// Getting the mode right by opening the target and chmod'ing it is not enough
// either, and that is the harder mistake. Any sequence that truncates the
// target first has a window where a later failure — the chmod, the write, the
// process dying — leaves the user with an empty file where an observation used
// to be. Correct permissions are not worth losing data for.
//
// So the new content is built in a temporary file beside the target, brought to
// the right mode there, flushed, and moved into place with a rename. The target
// holds either its old contents or its new ones and never anything in between,
// and rename replaces the destination's mode with the temporary file's, which
// is what forces 0600 onto a permissive file that already exists.
func writeFilePrivate(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sinesync-tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// Every failure from here removes the temporary file and leaves the target
	// untouched.
	abort := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}

	// CreateTemp already creates at 0600, but only the umask stands between
	// that and something looser if it ever changes. Say it explicitly.
	if err := tmp.Chmod(mode); err != nil {
		return abort(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return abort(err)
	}
	// Flush before the rename, so a crash cannot leave the target pointing at a
	// file whose contents never reached the disk.
	if err := tmp.Sync(); err != nil {
		return abort(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// Checksum calculates SHA256 checksum of data
func Checksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// StoredItem represents an item in local storage
type StoredItem struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
}

// LocalStorage handles file-based storage
type LocalStorage struct {
	baseDir string
}

// NewLocalStorage creates a new local storage instance
func NewLocalStorage() *LocalStorage {
	return &LocalStorage{
		baseDir: config.DataDir(),
	}
}

// ensureDir ensures a directory exists, and that it is private.
//
// The Chmod is not redundant with MkdirAll. MkdirAll masks its mode with the
// umask on the directories it creates, and leaves the mode of one that already
// exists completely alone — so a data dir made by an older build at 0755 would
// stay world-readable no matter how many times this ran. Chmod is idempotent,
// which makes every call a repair.
func (s *LocalStorage) ensureDir(itemType string) (string, error) {
	dir := filepath.Join(s.baseDir, itemType)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return "", err
	}
	return dir, nil
}

// Save stores an item
func (s *LocalStorage) Save(itemType string, id string, data interface{}) error {
	dir, err := s.ensureDir(itemType)
	if err != nil {
		return err
	}

	now := time.Now()
	item := StoredItem{
		ID:        id,
		Type:      itemType,
		Data:      data,
		CreatedAt: now,
		UpdatedAt: now,
	}

	bytes, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}

	return writeFilePrivate(filepath.Join(dir, id+".json"), bytes, fileMode)
}

// Get retrieves an item by ID
func (s *LocalStorage) Get(itemType, id string) (*StoredItem, error) {
	dir := filepath.Join(s.baseDir, itemType)
	path := filepath.Join(dir, id+".json")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var item StoredItem
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, err
	}

	return &item, nil
}

// Exists checks if an item exists by type and ID
func (s *LocalStorage) Exists(itemType, id string) (bool, error) {
	dir := filepath.Join(s.baseDir, itemType)
	path := filepath.Join(dir, id+".json")
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// List returns all items of a type
func (s *LocalStorage) List(itemType string) ([]StoredItem, error) {
	dir := filepath.Join(s.baseDir, itemType)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var items []StoredItem
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		var item StoredItem
		if err := json.Unmarshal(data, &item); err != nil {
			continue
		}

		items = append(items, item)
	}

	// Sort by UpdatedAt descending
	sort.Slice(items, func(i, j int) bool {
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})

	return items, nil
}

// Delete removes an item
func (s *LocalStorage) Delete(itemType, id string) error {
	dir := filepath.Join(s.baseDir, itemType)
	path := filepath.Join(dir, id+".json")
	return os.Remove(path)
}

// sourceIndex caches source IDs for fast duplicate detection
var sourceIndex map[string]bool
var sourceIndexLoaded bool

// ExistsBySource checks if an observation exists by source adapter, machine, and ID
func (s *LocalStorage) ExistsBySource(adapter, machine, sourceID string) (bool, error) {
	// Build index on first call
	if !sourceIndexLoaded {
		s.buildSourceIndex()
	}

	key := adapter + ":" + machine + ":" + sourceID
	return sourceIndex[key], nil
}

// buildSourceIndex loads all source IDs into memory for fast lookup
func (s *LocalStorage) buildSourceIndex() {
	sourceIndex = make(map[string]bool)
	sourceIndexLoaded = true

	items, err := s.List("observation")
	if err != nil {
		return
	}

	for _, item := range items {
		dataBytes, _ := json.Marshal(item.Data)
		var obs Observation
		if err := json.Unmarshal(dataBytes, &obs); err == nil {
			if obs.Source.Adapter != "" && obs.Source.ID != "" {
				key := obs.Source.Adapter + ":" + obs.Source.Machine + ":" + obs.Source.ID
				sourceIndex[key] = true
			}
		}
	}
}

// InvalidateSourceIndex clears the index (call after imports)
func (s *LocalStorage) InvalidateSourceIndex() {
	sourceIndexLoaded = false
	sourceIndex = nil
}

// AddToSourceIndex adds a new entry without full rebuild
func (s *LocalStorage) AddToSourceIndex(adapter, machine, sourceID string) {
	if sourceIndex == nil {
		sourceIndex = make(map[string]bool)
	}
	key := adapter + ":" + machine + ":" + sourceID
	sourceIndex[key] = true
}

// GetStatus returns storage statistics
func (s *LocalStorage) GetStatus() (itemCount int, storageBytes int64, err error) {
	err = filepath.Walk(s.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Ignore errors
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			itemCount++
			storageBytes += info.Size()
		}
		return nil
	})
	return
}

// SaveObservation saves an observation
func (s *LocalStorage) SaveObservation(obs *Observation) error {
	// Update source index
	if obs.Source.Adapter != "" && obs.Source.ID != "" {
		s.AddToSourceIndex(obs.Source.Adapter, obs.Source.Machine, obs.Source.ID)
	}
	return s.Save("observation", obs.ID, obs)
}

// GetObservation retrieves an observation by ID
func (s *LocalStorage) GetObservation(id string) (*Observation, error) {
	item, err := s.Get("observation", id)
	if err != nil {
		return nil, err
	}

	dataBytes, _ := json.Marshal(item.Data)
	var obs Observation
	if err := json.Unmarshal(dataBytes, &obs); err != nil {
		return nil, err
	}

	return &obs, nil
}

// ListObservations returns all observations
func (s *LocalStorage) ListObservations() ([]Observation, error) {
	items, err := s.List("observation")
	if err != nil {
		return nil, err
	}

	var observations []Observation
	for _, item := range items {
		dataBytes, _ := json.Marshal(item.Data)
		var obs Observation
		if err := json.Unmarshal(dataBytes, &obs); err == nil {
			observations = append(observations, obs)
		}
	}

	// Sort by CreatedAt descending
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Core.CreatedAt.After(observations[j].Core.CreatedAt)
	})

	return observations, nil
}

// DeleteObservation deletes an observation by ID
func (s *LocalStorage) DeleteObservation(id string) error {
	return s.Delete("observation", id)
}

// Close is a no-op for file-based storage
func (s *LocalStorage) Close() error {
	return nil
}

// ObservationExists checks if an observation exists by source
func (s *LocalStorage) ObservationExists(obs *Observation) (bool, error) {
	if obs.Source.Adapter != "" && obs.Source.ID != "" {
		return s.ExistsBySource(obs.Source.Adapter, obs.Source.Machine, obs.Source.ID)
	}
	return false, nil
}
