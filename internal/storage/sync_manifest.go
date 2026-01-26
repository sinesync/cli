package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miclip/sinesync/internal/config"
)

// LocalUploadState tracks what we've uploaded for an item
type LocalUploadState struct {
	Checksum  string    `json:"checksum"`  // checksum of encrypted data we uploaded
	UpdatedAt time.Time `json:"updatedAt"` // observation's UpdatedAt when we encrypted
}

// SyncManifest tracks which observations are synced to cloud
type SyncManifest struct {
	LastSync        time.Time                   `json:"lastSync"`
	Items           map[string]string           `json:"items"`           // id -> checksum (current cloud state)
	SeenIDs         map[string]bool             `json:"seenIds"`         // all IDs ever seen from cloud
	PendingDeletes  map[string]bool             `json:"pendingDeletes"`  // explicit deletes to sync to cloud
	ManifestVersion int                         `json:"manifestVersion"` // version from server for cache invalidation
	LocalUploads    map[string]LocalUploadState `json:"localUploads"`    // id -> our uploaded state
	mu              sync.RWMutex
}

// GetManifestVersion returns the cached manifest version
func (m *SyncManifest) GetManifestVersion() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ManifestVersion
}

// SetManifestVersion updates the cached manifest version
func (m *SyncManifest) SetManifestVersion(version int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ManifestVersion = version
}

var (
	manifest     *SyncManifest
	manifestOnce sync.Once
)

func syncManifestPath() string {
	return filepath.Join(config.DataDir(), "sync-manifest.json")
}

// GetSyncManifest returns the cached sync manifest (singleton)
func GetSyncManifest() *SyncManifest {
	manifestOnce.Do(func() {
		manifest = &SyncManifest{
			Items:          make(map[string]string),
			SeenIDs:        make(map[string]bool),
			PendingDeletes: make(map[string]bool),
			LocalUploads:   make(map[string]LocalUploadState),
		}
		manifest.Load()
	})
	return manifest
}

// Load reads the manifest from disk
func (m *SyncManifest) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(syncManifestPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, m)
}

// Save writes the manifest to disk
func (m *SyncManifest) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if err := os.MkdirAll(config.DataDir(), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(syncManifestPath(), data, 0644)
}

// IsSynced checks if an observation is synced with matching checksum
func (m *SyncManifest) IsSynced(id, checksum string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if cloudChecksum, exists := m.Items[id]; exists {
		return cloudChecksum == checksum
	}
	return false
}

// MarkSynced marks an observation as synced
func (m *SyncManifest) MarkSynced(id, checksum string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Items == nil {
		m.Items = make(map[string]string)
	}
	m.Items[id] = checksum
}

// UpdateFromCloud updates manifest from cloud manifest response
func (m *SyncManifest) UpdateFromCloud(items map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Items = items
	m.LastSync = time.Now()
}

// GetSyncedCount returns the number of synced items
func (m *SyncManifest) GetSyncedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.Items)
}

// GetLastSync returns the last sync time
func (m *SyncManifest) GetLastSync() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.LastSync
}

// MarkSeen marks an ID as seen (we've encountered it from cloud)
func (m *SyncManifest) MarkSeen(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.SeenIDs == nil {
		m.SeenIDs = make(map[string]bool)
	}
	m.SeenIDs[id] = true
}

// IsSeen checks if we've ever seen this ID from cloud
func (m *SyncManifest) IsSeen(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.SeenIDs == nil {
		return false
	}
	return m.SeenIDs[id]
}

// MarkSeenBatch marks multiple IDs as seen
func (m *SyncManifest) MarkSeenBatch(ids []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.SeenIDs == nil {
		m.SeenIDs = make(map[string]bool)
	}
	for _, id := range ids {
		m.SeenIDs[id] = true
	}
}

// RemoveFromSeen removes an ID from seen list (after confirmed cloud deletion)
func (m *SyncManifest) RemoveFromSeen(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.SeenIDs, id)
	delete(m.Items, id)
	delete(m.PendingDeletes, id)
	delete(m.LocalUploads, id)
}

// MarkPendingDelete marks an item for deletion from cloud on next sync
func (m *SyncManifest) MarkPendingDelete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.PendingDeletes == nil {
		m.PendingDeletes = make(map[string]bool)
	}
	m.PendingDeletes[id] = true
}

// GetPendingDeletes returns IDs that should be deleted from cloud
func (m *SyncManifest) GetPendingDeletes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.PendingDeletes))
	for id := range m.PendingDeletes {
		result = append(result, id)
	}
	return result
}

// ClearPendingDelete removes an item from pending deletes after successful deletion
func (m *SyncManifest) ClearPendingDelete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.PendingDeletes, id)
}

// GetLocalUpload returns the cached upload state for an item
func (m *SyncManifest) GetLocalUpload(id string) (LocalUploadState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.LocalUploads == nil {
		return LocalUploadState{}, false
	}
	state, exists := m.LocalUploads[id]
	return state, exists
}

// SetLocalUpload stores the upload state after successful upload
func (m *SyncManifest) SetLocalUpload(id string, checksum string, updatedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.LocalUploads == nil {
		m.LocalUploads = make(map[string]LocalUploadState)
	}
	m.LocalUploads[id] = LocalUploadState{
		Checksum:  checksum,
		UpdatedAt: updatedAt,
	}
}

// ClearLocalUpload removes local upload state (e.g., after deletion)
func (m *SyncManifest) ClearLocalUpload(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.LocalUploads, id)
}
