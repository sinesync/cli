package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miclip/sinesync/internal/config"
)

// SyncManifest tracks which observations are synced to cloud
type SyncManifest struct {
	LastSync time.Time         `json:"lastSync"`
	Items    map[string]string `json:"items"` // id -> checksum
	mu       sync.RWMutex
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
			Items: make(map[string]string),
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
