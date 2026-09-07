package daemon

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sinesync/cli/internal/adapters"
	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/embeddings"
	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/httputil"
	"github.com/sinesync/cli/internal/keychain"
	"github.com/sinesync/cli/internal/storage"
	"github.com/sinesync/cli/internal/vaultroute"
)

func init() {
	// Register embedder factory to avoid import cycle in adapters package
	// Use GetProvider for singleton - ONNX can only be initialized once
	adapters.RegisterEmbedder(func() (adapters.EmbedderInterface, error) {
		return embeddings.GetProvider()
	})
}

const (
	SyncInterval   = 10 * time.Minute
	DefaultAPIBase = "https://api.sinesync.ai/v1"
)

// LocalVaultConfig stores vault configuration locally
type localVaultConfig struct {
	Vaults []localVault `json:"vaults"`
}

type localVault struct {
	VaultID           string   `json:"vaultId"`
	Name              string   `json:"name"`
	EncryptedVaultKey string   `json:"encryptedVaultKey"`
	Projects          []string `json:"projects"`
	IsDefault         bool     `json:"isDefault"`
}

func localVaultConfigPath() string {
	return filepath.Join(config.ConfigDir(), "vaults.json")
}

func loadLocalVaultConfig() (*localVaultConfig, error) {
	data, err := os.ReadFile(localVaultConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &localVaultConfig{Vaults: make([]localVault, 0)}, nil
		}
		return nil, err
	}

	var cfg localVaultConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func getDefaultVaultID() (string, error) {
	cfg, err := vaultroute.Load()
	if err != nil {
		return "", err
	}
	if id := cfg.DefaultVaultID(); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("no default vault configured")
}

// getVaultIDForObservation returns the vault ID for an observation based on its project
func getVaultIDForObservation(project string, defaultVaultID string) string {
	// One implementation, shared with the CLI. Two copies deciding where a
	// user's data goes is the sort of agreement that holds until it does not.
	return vaultroute.ForProject(project, defaultVaultID)
}

// getVaultName returns the vault name for a given vault ID
func getVaultName(vaultID string) string {
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return vaultID[:8] // Return truncated ID as fallback
	}

	for _, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			return v.Name
		}
	}

	return vaultID[:8]
}

// getVaultKey returns the decrypted vault key for a given vault ID
// Returns nil if no vault key is available (falls back to user's derived key)
func getVaultKey(vaultID string, encMgr *encryption.Manager) []byte {
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return nil
	}

	for _, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			if v.EncryptedVaultKey == "" {
				return nil
			}
			key, err := encMgr.DecryptVaultKey(v.EncryptedVaultKey)
			if err != nil {
				log.Printf("[sync] Failed to decrypt vault key for %s: %v", v.Name, err)
				return nil
			}
			return key
		}
	}

	return nil
}

// SyncManager handles background cloud sync
type SyncManager struct {
	backend        storage.StorageBackend
	apiBase        string
	mode           string // "standalone" or "adapter"
	stopChan       chan struct{}
	wg             sync.WaitGroup
	mu             sync.Mutex
	lastSync       time.Time
	lastError      string
	syncing        bool
	accountDeleted bool

	// Adaptive sync state
	consecutiveEmpty int
	activityChan     chan struct{}

	// Backfill state
	backfillMu        sync.Mutex
	backfillRunning   bool
	backfillProgress  int
	backfillTotal     int
	backfillStartTime time.Time
}

// NewSyncManager creates a new sync manager
func NewSyncManager(backend storage.StorageBackend, mode string) *SyncManager {
	apiBase := os.Getenv("SINESYNC_API_URL")
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}

	return &SyncManager{
		backend:      backend,
		apiBase:      apiBase,
		mode:         mode,
		stopChan:     make(chan struct{}),
		activityChan: make(chan struct{}, 1),
	}
}

// Start begins background sync
func (m *SyncManager) Start() {
	m.wg.Add(1)
	go m.syncLoop()
	log.Printf("[sync] Background sync started (interval: %v)", SyncInterval)
}

// Stop halts background sync
func (m *SyncManager) Stop() {
	close(m.stopChan)
	m.wg.Wait()
	log.Printf("[sync] Background sync stopped")
}

// NotifyActivity signals that local data has changed (observation captured, deleted, etc.)
// This triggers a debounced sync and resets the adaptive backoff.
func (m *SyncManager) NotifyActivity() {
	// Non-blocking send to wake the sync loop
	select {
	case m.activityChan <- struct{}{}:
	default:
	}
}

// calculateInterval returns the sync interval based on consecutive empty syncs.
// Derives all intervals from SyncInterval so the schedule stays consistent
// if the base constant is ever changed.
func calculateInterval(consecutiveEmpty int) time.Duration {
	maxInterval := 6 * SyncInterval // 60m with default 10m base

	var interval time.Duration
	switch {
	case consecutiveEmpty <= 1:
		interval = SyncInterval
	case consecutiveEmpty == 2:
		interval = 2 * SyncInterval
	case consecutiveEmpty == 3:
		interval = 3 * SyncInterval
	default:
		interval = maxInterval
	}

	if interval > maxInterval {
		interval = maxInterval
	}
	return interval
}

// Status returns current sync status
func (m *SyncManager) Status() (syncing bool, lastSync time.Time, lastError string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncing, m.lastSync, m.lastError
}

// TriggerSync triggers an immediate sync
func (m *SyncManager) TriggerSync() {
	go m.doSync()
}

func (m *SyncManager) syncLoop() {
	defer m.wg.Done()

	// Initial sync after short delay
	select {
	case <-time.After(30 * time.Second):
		m.doSync()
		m.mu.Lock()
		deleted := m.accountDeleted
		m.mu.Unlock()
		if deleted {
			return
		}
	case <-m.stopChan:
		return
	}

	for {
		m.mu.Lock()
		interval := calculateInterval(m.consecutiveEmpty)
		m.mu.Unlock()

		timer := time.NewTimer(interval)

		select {
		case <-timer.C:
			m.doSync()
			m.mu.Lock()
			deleted := m.accountDeleted
			m.mu.Unlock()
			if deleted {
				return
			}

		case <-m.activityChan:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			log.Printf("[sync] Activity detected, syncing 30s after last activity...")
			// Debounce: wait 30s of inactivity to batch rapid captures into one sync
			debounce := time.NewTimer(30 * time.Second)
		activityDebounce:
			for {
				select {
				case <-m.activityChan:
					// New activity: reset debounce timer
					if !debounce.Stop() {
						select {
						case <-debounce.C:
						default:
						}
					}
					debounce.Reset(30 * time.Second)
				case <-debounce.C:
					// 30s of quiet: perform a single sync for this burst
					m.mu.Lock()
					m.consecutiveEmpty = 0
					m.mu.Unlock()
					m.doSync()
					m.mu.Lock()
					deleted := m.accountDeleted
					m.mu.Unlock()
					if deleted {
						return
					}
					break activityDebounce
				case <-m.stopChan:
					debounce.Stop()
					return
				}
			}

		case <-m.stopChan:
			timer.Stop()
			return
		}
	}
}

func (m *SyncManager) doSync() {
	m.mu.Lock()
	if m.syncing || m.accountDeleted {
		m.mu.Unlock()
		return
	}
	m.syncing = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.syncing = false
		m.mu.Unlock()

		// Run claude-mem backfills only in adapter mode
		if m.mode == "adapter" {
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				m.backfillClaudeMemExport()
				m.backfillChromaEmbeddings()
			}()
		}
	}()

	token, err := m.getAuthToken()
	if err != nil {
		m.setError(fmt.Sprintf("not authenticated: %v", err))
		return
	}

	log.Printf("[sync] Starting sync...")
	start := time.Now()

	pushed, pulled, err := m.sync(token)
	if err != nil {
		// Check if it's a 401 error - try to refresh token
		if isUnauthorizedError(err) {
			if isAccountDeletedError(err) {
				m.setError("Your account has been deleted. Local data is preserved.")
				log.Printf("[sync] Account deleted. Stopping sync. Local data is preserved.")
				m.mu.Lock()
				m.accountDeleted = true
				m.mu.Unlock()
				return
			}

			log.Printf("[sync] Token expired, attempting refresh...")
			newToken, refreshErr := m.refreshAccessToken()
			if refreshErr != nil {
				if isAccountDeletedError(refreshErr) {
					m.setError("Your account has been deleted. Local data is preserved.")
					log.Printf("[sync] Account deleted. Stopping sync. Local data is preserved.")
					m.mu.Lock()
					m.accountDeleted = true
					m.mu.Unlock()
					return
				}
				m.setError(fmt.Sprintf("token refresh failed: %v", refreshErr))
				log.Printf("[sync] Token refresh failed: %v", refreshErr)
				return
			}

			// Retry sync with new token
			pushed, pulled, err = m.sync(newToken)
			if err != nil {
				m.setError(err.Error())
				log.Printf("[sync] Failed after token refresh: %v", err)
				return
			}
		} else {
			m.setError(err.Error())
			log.Printf("[sync] Failed: %v", err)
			return
		}
	}

	m.mu.Lock()
	m.lastSync = time.Now()
	m.lastError = ""
	if pushed == 0 && pulled == 0 {
		m.consecutiveEmpty++
		nextInterval := calculateInterval(m.consecutiveEmpty)
		m.mu.Unlock()
		log.Printf("[sync] Complete: pushed=0, pulled=0, duration=%v, next=%v (idle:%d)",
			time.Since(start).Round(time.Millisecond), nextInterval, m.consecutiveEmpty)
	} else {
		m.consecutiveEmpty = 0
		m.mu.Unlock()
		log.Printf("[sync] Complete: pushed=%d, pulled=%d, duration=%v, next=%v (active)",
			pushed, pulled, time.Since(start).Round(time.Millisecond), SyncInterval)
	}
}

func isUnauthorizedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") || strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "Unauthorized")
}

func isAccountDeletedError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Prefer structured detection: server errors include JSON body with "code" field
	if i := strings.Index(msg, "{"); i != -1 {
		var payload struct {
			Code string `json:"code"`
		}
		if json.Unmarshal([]byte(msg[i:]), &payload) == nil && payload.Code == "ACCOUNT_DELETED" {
			return true
		}
	}
	return strings.Contains(msg, "ACCOUNT_DELETED")
}

func (m *SyncManager) setError(err string) {
	m.mu.Lock()
	m.lastError = err
	m.mu.Unlock()
}

func (m *SyncManager) getAuthToken() (string, error) {

	// Check keyring first (preferred secure storage)
	if token, err := keychain.Get("token"); err == nil && token != "" {
		return token, nil
	}
	if deviceToken, err := keychain.Get("deviceToken"); err == nil && deviceToken != "" {
		return deviceToken, nil
	}

	// Fallback to JSON file
	authPath := filepath.Join(config.ConfigDir(), "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return "", fmt.Errorf("not logged in")
	}

	var auth struct {
		DeviceToken string `json:"deviceToken"`
		Token       string `json:"token"`
	}
	if err := json.Unmarshal(data, &auth); err != nil {
		return "", err
	}

	if auth.DeviceToken != "" {
		return auth.DeviceToken, nil
	}
	if auth.Token != "" {
		return auth.Token, nil
	}

	return "", fmt.Errorf("no token found")
}

func (m *SyncManager) getRefreshToken() (string, error) {

	// Check keyring first
	if refreshToken, err := keychain.Get("refreshToken"); err == nil && refreshToken != "" {
		return refreshToken, nil
	}

	// Fallback to JSON file
	authPath := filepath.Join(config.ConfigDir(), "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return "", fmt.Errorf("no refresh token found")
	}

	var auth struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.Unmarshal(data, &auth); err != nil {
		return "", err
	}

	if auth.RefreshToken != "" {
		return auth.RefreshToken, nil
	}

	return "", fmt.Errorf("no refresh token found")
}

func (m *SyncManager) refreshAccessToken() (string, error) {
	refreshToken, err := m.getRefreshToken()
	if err != nil {
		return "", fmt.Errorf("no refresh token: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	reqBody, _ := json.Marshal(map[string]string{
		"refreshToken": refreshToken,
	})

	req, err := http.NewRequest("POST", m.apiBase+"/auth/refresh", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("refresh failed: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode refresh response: %w", err)
	}

	// Store new token in keyring
	if err := keychain.Set("token", result.Token); err != nil {
		// Also update auth.json as fallback
		m.updateStoredToken(result.Token)
	}

	// Store rotated refresh token if provided
	if result.RefreshToken != "" {
		if err := keychain.Set("refreshToken", result.RefreshToken); err != nil {
			log.Printf("[sync] Warning: failed to store rotated refresh token in keyring — user will need to re-login")
		}
	}

	log.Printf("[sync] Token refreshed successfully")
	return result.Token, nil
}

func (m *SyncManager) updateStoredToken(token string) {
	authPath := filepath.Join(config.ConfigDir(), "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return
	}

	var auth map[string]interface{}
	if err := json.Unmarshal(data, &auth); err != nil {
		return
	}

	// Update the token (could be "token" or "deviceToken" depending on auth method)
	if _, ok := auth["deviceToken"]; ok {
		auth["deviceToken"] = token
	} else {
		auth["token"] = token
	}

	newData, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		return
	}

	os.WriteFile(authPath, newData, 0600)
}

func (m *SyncManager) sync(token string) (pushed, pulled int, err error) {
	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return 0, 0, fmt.Errorf("encryption key not available - please login again")
	}

	// Get default vault ID (fallback for projects not assigned to a vault)
	defaultVaultID, err := getDefaultVaultID()
	if err != nil {
		return 0, 0, fmt.Errorf("no vault configured - run 'sinesync vault sync' first: %w", err)
	}

	syncManifest := storage.GetSyncManifest()

	// Check if we have pending operations that require manifest
	hasPendingDeletes := len(syncManifest.GetPendingDeletes()) > 0

	// Check manifest metadata first (cheap - 1 API call)
	meta, err := m.getManifestMeta(token)
	if err != nil {
		return 0, 0, fmt.Errorf("get manifest meta: %w", err)
	}

	// Compare with cached version
	cachedVersion := syncManifest.GetManifestVersion()
	manifestChanged := meta.ManifestVersion != cachedVersion

	var manifest *manifestResponse
	var cloudItems map[string]string

	// Only download full manifest if changed or we need it for operations
	if manifestChanged || hasPendingDeletes {
		manifest, err = m.getCloudManifestCached(token)
		if err != nil {
			return 0, 0, fmt.Errorf("get manifest: %w", err)
		}

		cloudItems = make(map[string]string)
		for _, item := range manifest.Items {
			cloudItems[item.ID] = item.Checksum
		}

		// Update cached version
		syncManifest.SetManifestVersion(meta.ManifestVersion)
	} else {
		// No changes - use cached items from local manifest
		log.Printf("[sync] Manifest unchanged (version %d), using cache", cachedVersion)
		cloudItems = syncManifest.Items
		manifest = &manifestResponse{
			Items:      make([]manifestItem, 0, len(cloudItems)),
			TotalCount: len(cloudItems),
		}
		for id, checksum := range cloudItems {
			manifest.Items = append(manifest.Items, manifestItem{ID: id, Checksum: checksum})
		}
	}

	// Get local observations
	observations, err := m.backend.ListObservations()
	if err != nil {
		return 0, 0, fmt.Errorf("list observations: %w", err)
	}

	// Determine which items need to be pushed
	// Use cached checksums when observation hasn't changed
	localItems := make(map[string]string)
	var toPush []encryptedObsItem

	for _, obs := range observations {
		var checksum string
		var encrypted []byte

		// Check if we have a cached upload state for this item
		if cached, exists := syncManifest.GetLocalUpload(obs.ID); exists {
			// Check if observation changed since we last encrypted it
			if cached.UpdatedAt.Equal(obs.Core.UpdatedAt) {
				// Unchanged - use cached checksum
				checksum = cached.Checksum
				localItems[obs.ID] = checksum

				// Check if cloud has it with same checksum
				if cloudChecksum, inCloud := cloudItems[obs.ID]; inCloud && cloudChecksum == checksum {
					// Already synced, skip
					continue
				}
				// Need to re-encrypt for upload (cloud doesn't have it or has different version)
			}
		}

		// Determine which vault this observation belongs to
		vaultID := getVaultIDForObservation(obs.Core.Project, defaultVaultID)

		// Need to encrypt (either no cache, changed, or need to upload)
		if checksum == "" {
			var err error
			// Use vault key if available, otherwise fall back to user's derived key
			vaultKey := getVaultKey(vaultID, encMgr)
			if vaultKey != nil {
				encrypted, err = encMgr.EncryptObservationWithKey(&obs, vaultKey)
			} else {
				encrypted, err = encMgr.EncryptObservation(&obs)
			}
			if err != nil {
				log.Printf("[sync] Encrypt error for %s: %v", obs.ID, err)
				continue
			}
			checksum = storage.Checksum(encrypted)[:16]
			localItems[obs.ID] = checksum
		} else if encrypted == nil {
			// Have checksum but need encrypted data for upload
			var err error
			// Use vault key if available, otherwise fall back to user's derived key
			vaultKey := getVaultKey(vaultID, encMgr)
			if vaultKey != nil {
				encrypted, err = encMgr.EncryptObservationWithKey(&obs, vaultKey)
			} else {
				encrypted, err = encMgr.EncryptObservation(&obs)
			}
			if err != nil {
				log.Printf("[sync] Encrypt error for %s: %v", obs.ID, err)
				continue
			}
			// Recalculate checksum since encryption produces different ciphertext
			checksum = storage.Checksum(encrypted)[:16]
			localItems[obs.ID] = checksum
		}

		// Check if needs push
		cloudChecksum, inCloud := cloudItems[obs.ID]
		if !inCloud {
			// Cloud doesn't have it at all — must push
			toPush = append(toPush, encryptedObsItem{
				obs:       obs,
				encrypted: encrypted,
				checksum:  checksum,
				vaultID:   vaultID,
			})
		} else if cloudChecksum != checksum {
			// Checksums differ — only push if observation was locally modified since last upload.
			// Re-encryption produces different ciphertext (random nonce), so checksum mismatches
			// are expected even when the underlying data hasn't changed.
			if cached, hasCached := syncManifest.GetLocalUpload(obs.ID); hasCached {
				if !cached.UpdatedAt.Equal(obs.Core.UpdatedAt) {
					// Observation was modified since last upload — push update
					toPush = append(toPush, encryptedObsItem{
						obs:       obs,
						encrypted: encrypted,
						checksum:  checksum,
						vaultID:   vaultID,
					})
				}
				// else: checksum differs only due to re-encryption nonce, skip
			} else {
				// No cached upload state — this is likely a pulled item we haven't tracked yet.
				// Record cloud checksum to prevent future re-push attempts.
				syncManifest.SetLocalUpload(obs.ID, cloudChecksum, obs.Core.UpdatedAt)
			}
		}
	}

	// syncManifest already obtained at start of sync function

	// Determine what to pull
	// Only pull items we haven't seen before (new from another device)
	var toPull []manifestItem
	for _, item := range manifest.Items {
		if _, exists := localItems[item.ID]; !exists {
			// Cloud has it, we don't have it locally
			if !syncManifest.IsSeen(item.ID) {
				// Never seen - new from another device, pull it
				toPull = append(toPull, item)
			}
			// If we've seen it before but don't have it locally,
			// it could be: (1) explicitly deleted via dashboard, or (2) cleared during troubleshooting
			// We only sync explicit deletes (from pendingDeletes), not inferred deletions
		}
	}

	// Get explicit pending deletes (only items deleted through dashboard)
	toDeleteFromCloud := syncManifest.GetPendingDeletes()

	// Detect items deleted from cloud by other devices
	// If we have it locally, we've seen it before, but it's no longer in cloud → deleted by another device
	var toDeleteLocally []string
	for _, obs := range observations {
		if _, inCloud := cloudItems[obs.ID]; !inCloud {
			// Not in cloud - was it ever there?
			if syncManifest.IsSeen(obs.ID) {
				// We've seen it in cloud before, now it's gone → deleted by another device
				toDeleteLocally = append(toDeleteLocally, obs.ID)
			}
		}
	}

	// Mark items we already have locally as seen (they don't need to be pulled)
	for id := range localItems {
		syncManifest.MarkSeen(id)
	}

	// Group items by vault for logging
	vaultCounts := make(map[string]int)
	for _, item := range toPush {
		vaultCounts[item.vaultID]++
	}
	if len(vaultCounts) > 0 {
		var vaultInfo []string
		for vaultID, count := range vaultCounts {
			vaultInfo = append(vaultInfo, fmt.Sprintf("%s: %d", getVaultName(vaultID), count))
		}
		log.Printf("[sync] Pushing to vaults: %s", strings.Join(vaultInfo, ", "))
	}

	// Push in batches
	batchSize := 50
	for i := 0; i < len(toPush); i += batchSize {
		end := i + batchSize
		if end > len(toPush) {
			end = len(toPush)
		}
		batch := toPush[i:end]

		n, uploadedItems, err := m.pushBatchEncrypted(token, batch)
		if err != nil {
			// If 401, return immediately so doSync can refresh token and retry
			if isUnauthorizedError(err) {
				// Save what we have so far
				syncManifest.Save()
				return pushed, pulled, err
			}
			log.Printf("[sync] Push batch error: %v", err)
		}
		pushed += n

		// Cache successful uploads
		for _, item := range uploadedItems {
			syncManifest.SetLocalUpload(item.id, item.checksum, item.updatedAt)
		}

		// Delay between batches to reduce sustained backend load
		if i+batchSize < len(toPush) {
			time.Sleep(1 * time.Second)
		}
	}

	// Pull items in batches
	pullBatchSize := 50
	for i := 0; i < len(toPull); i += pullBatchSize {
		end := i + pullBatchSize
		if end > len(toPull) {
			end = len(toPull)
		}
		batch := toPull[i:end]

		n, err := m.pullBatch(token, batch, encMgr, syncManifest)
		if err != nil {
			if isUnauthorizedError(err) {
				syncManifest.Save()
				return pushed, pulled, err
			}
			log.Printf("[sync] Pull batch error: %v", err)
		}
		pulled += n
	}

	// Delete items from cloud that were explicitly deleted locally (via dashboard)
	deleted := 0
	for _, id := range toDeleteFromCloud {
		if err := m.deleteFromCloud(token, id); err != nil {
			if isUnauthorizedError(err) {
				syncManifest.Save()
				return pushed, pulled, err
			}
			log.Printf("[sync] Delete error for %s: %v", id, err)
			continue
		}
		// Clear from pending deletes and seen list after successful cloud deletion
		syncManifest.ClearPendingDelete(id)
		syncManifest.RemoveFromSeen(id)
		deleted++
	}
	if deleted > 0 {
		log.Printf("[sync] Deleted %d items from cloud", deleted)
	}

	// Delete local items that were deleted from cloud by other devices
	deletedLocal := 0
	for _, id := range toDeleteLocally {
		if err := m.deleteLocally(id); err != nil {
			log.Printf("[sync] Local delete error for %s: %v", id, err)
			continue
		}
		syncManifest.RemoveFromSeen(id)
		deletedLocal++
	}
	if deletedLocal > 0 {
		log.Printf("[sync] Deleted %d items locally (synced from other devices)", deletedLocal)
	}

	// Update sync manifest with current cloud state
	syncManifest.UpdateFromCloud(cloudItems)
	syncManifest.Save()

	return pushed, pulled, nil
}

type manifestItem struct {
	ID        string `json:"id"`
	Checksum  string `json:"checksum"`
	SizeBytes int64  `json:"sizeBytes"`
}

type manifestResponse struct {
	Items      []manifestItem `json:"items"`
	Cursor     string         `json:"cursor,omitempty"`
	TotalCount int            `json:"totalCount"`
}

func (m *SyncManager) getCloudManifest(token string) (*manifestResponse, error) {
	var allItems []manifestItem
	cursor := ""
	totalCount := 0

	client := &http.Client{Timeout: 30 * time.Second}

	for {
		u := m.apiBase + "/sync/manifest?limit=100"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
		}

		var page manifestResponse
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		allItems = append(allItems, page.Items...)
		totalCount = page.TotalCount

		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}

	return &manifestResponse{
		Items:      allItems,
		TotalCount: totalCount,
	}, nil
}

// encryptedObs is defined in sync function scope, redeclare here for pushBatchEncrypted
type encryptedObsItem struct {
	obs       storage.Observation
	encrypted []byte
	checksum  string
	vaultID   string
}

type manifestMeta struct {
	ItemCount       int    `json:"itemCount"`
	LastUpdated     string `json:"lastUpdated"`
	TotalSizeBytes  int64  `json:"totalSizeBytes"`
	ManifestVersion int    `json:"manifestVersion"`
}

func (m *SyncManager) getManifestMeta(token string) (*manifestMeta, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", m.apiBase+"/sync/manifest/meta", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := httputil.CheckUpdateRequired(resp); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var meta manifestMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func (m *SyncManager) getCloudManifestCached(token string) (*manifestResponse, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	// Get signed URL for manifest download
	req, err := http.NewRequest("GET", m.apiBase+"/sync/manifest/download", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := httputil.CheckUpdateRequired(resp); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get manifest URL failed %d: %s", resp.StatusCode, string(body))
	}

	var urlResp struct {
		URL       string `json:"url"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
		return nil, err
	}

	// Download the gzipped manifest
	dlResp, err := client.Get(urlResp.URL)
	if err != nil {
		return nil, fmt.Errorf("download manifest: %w", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest download failed: %d", dlResp.StatusCode)
	}

	// Decompress gzip
	gzReader, err := gzip.NewReader(dlResp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Parse JSON
	var manifest struct {
		UserID      string         `json:"userId"`
		GeneratedAt string         `json:"generatedAt"`
		ItemCount   int            `json:"itemCount"`
		Items       []manifestItem `json:"items"`
	}
	if err := json.NewDecoder(gzReader).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	return &manifestResponse{
		Items:      manifest.Items,
		TotalCount: manifest.ItemCount,
	}, nil
}

type uploadedItem struct {
	id        string
	checksum  string
	updatedAt time.Time
}

func (m *SyncManager) pushBatchEncrypted(token string, batch []encryptedObsItem) (int, []uploadedItem, error) {
	// Prepare items for URL request
	type itemReq struct {
		ID        string `json:"id"`
		VaultID   string `json:"vaultId"`
		Type      string `json:"type"`
		SizeBytes int    `json:"sizeBytes"`
		Checksum  string `json:"checksum"`
	}

	items := make([]itemReq, 0, len(batch))
	itemData := make(map[string][]byte)
	itemMeta := make(map[string]encryptedObsItem) // Track metadata for cache

	for _, item := range batch {
		items = append(items, itemReq{
			ID:        item.obs.ID,
			VaultID:   item.vaultID, // Use per-item vaultID
			Type:      "memory",
			SizeBytes: len(item.encrypted),
			Checksum:  item.checksum,
		})
		itemData[item.obs.ID] = item.encrypted
		itemMeta[item.obs.ID] = item
	}

	// Get upload URLs with retry for rate limiting
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)

	client := &http.Client{Timeout: 60 * time.Second}

	var resp *http.Response
	var err error
	for retries := 0; retries < 3; retries++ {
		req, _ := http.NewRequest("POST", m.apiBase+"/sync/upload-urls", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(req)

		resp, err = client.Do(req)
		if err != nil {
			return 0, nil, err
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			backoff := time.Duration(1<<retries) * time.Second // 1s, 2s, 4s
			log.Printf("[sync] Rate limited, waiting %v...", backoff)
			time.Sleep(backoff)
			continue
		}
		break
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return 0, nil, fmt.Errorf("get URLs failed %d: %s", resp.StatusCode, string(respBody))
	}
	defer resp.Body.Close()

	var urlResp struct {
		Items []struct {
			ID        string `json:"id"`
			UploadURL string `json:"uploadUrl"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
		return 0, nil, fmt.Errorf("decode upload URLs response: %w", err)
	}

	// Upload encrypted data to GCS
	type confirmItem struct {
		id       string
		checksum string
	}
	var confirmItems []confirmItem
	var confirmBodies []map[string]interface{}

	for _, urlItem := range urlResp.Items {
		data := itemData[urlItem.ID]
		if data == nil {
			continue
		}

		uploadReq, _ := http.NewRequest("PUT", urlItem.UploadURL, bytes.NewReader(data))
		uploadReq.Header.Set("Content-Type", "application/octet-stream")

		uploadResp, err := client.Do(uploadReq)
		if err != nil {
			continue
		}
		uploadResp.Body.Close()

		if uploadResp.StatusCode == http.StatusOK || uploadResp.StatusCode == http.StatusCreated {
			checksum := storage.Checksum(data)[:16]
			confirmItems = append(confirmItems, confirmItem{id: urlItem.ID, checksum: checksum})
			// Use per-item vaultID from metadata
			meta := itemMeta[urlItem.ID]
			confirmBodies = append(confirmBodies, map[string]interface{}{
				"id":        urlItem.ID,
				"vaultId":   meta.vaultID,
				"type":      "memory",
				"sizeBytes": len(data),
				"checksum":  checksum,
			})
		}
	}

	if len(confirmItems) == 0 {
		return 0, nil, nil
	}

	// Confirm uploads
	confirmBody := map[string]interface{}{"items": confirmBodies}
	confirmBytes, _ := json.Marshal(confirmBody)

	confirmReq, _ := http.NewRequest("POST", m.apiBase+"/sync/confirm-uploads", bytes.NewReader(confirmBytes))
	confirmReq.Header.Set("Content-Type", "application/json")
	confirmReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(confirmReq)

	confirmResp, err := client.Do(confirmReq)
	if err != nil {
		return 0, nil, err
	}
	defer confirmResp.Body.Close()

	if confirmResp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("confirm failed")
	}

	var confirmResult struct {
		Items []struct {
			Success bool `json:"success"`
		} `json:"items"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmResult); err != nil {
		return 0, nil, fmt.Errorf("decode confirm response: %w", err)
	}

	// Build list of successfully uploaded items
	var uploaded []uploadedItem
	count := 0
	for i, result := range confirmResult.Items {
		if result.Success && i < len(confirmItems) {
			count++
			ci := confirmItems[i]
			if meta, ok := itemMeta[ci.id]; ok {
				uploaded = append(uploaded, uploadedItem{
					id:        ci.id,
					checksum:  ci.checksum,
					updatedAt: meta.obs.Core.UpdatedAt,
				})
			}
		}
	}

	return count, uploaded, nil
}

// standardizeEmbedding ensures an observation's embedding is compatible with the local model.
// Re-embeds if metadata is missing, unknown, or from a different model/tokenizer.
func standardizeEmbedding(obs *storage.Observation) {
	if obs.Embedding.IsCompatibleWith(embeddings.ModelName, embeddings.TokenizerType, embeddings.Dimensions) {
		return
	}

	embedder, err := embeddings.GetProvider()
	if err != nil {
		log.Printf("[embed] WARNING: embedder unavailable for %s: %v", obs.ID, err)
		return
	}
	if !embedder.IsReady() {
		log.Printf("[embed] WARNING: embedder not ready, skipping %s", obs.ID)
		return
	}

	text := obs.TextForEmbedding()
	vector, err := embedder.Embed(text)
	if err != nil {
		log.Printf("[embed] WARNING: failed to embed %s: %v", obs.ID, err)
		return
	}

	obs.Embedding.Vector = vector
	obs.Embedding.Model = embeddings.ModelName
	obs.Embedding.Tokenizer = embedder.TokenizerType()
	obs.Embedding.Dims = embeddings.Dimensions
}

// exportToClaudeMemWithEmbedding exports an observation to claude-mem with embedding
// Returns error if embedding or export fails - no fallback to export without embedding
// This ensures observations are never in claude-mem SQLite without ChromaDB entry
func exportToClaudeMemWithEmbedding(ctx context.Context, obs *storage.Observation) error {
	if !adapters.IsClaudeMemInstalled() {
		return nil
	}

	adapter, err := adapters.NewClaudeMemAdapter(false)
	if err != nil || adapter == nil {
		return fmt.Errorf("failed to create adapter: %w", err)
	}
	defer adapter.Close()

	// Get adapter's embedding config
	adapterConfig := adapter.GetEmbeddingConfig()
	if adapterConfig == nil {
		return fmt.Errorf("adapter has no embedding config")
	}

	// Check if observation's embedding is compatible with adapter
	if obs.Embedding.IsCompatibleWith(adapterConfig.Model, adapterConfig.Tokenizer, adapterConfig.Dims) {
		// Embedding matches - use existing
		return adapter.ExportWithEmbedding(ctx, obs)
	}

	// Embedding missing or incompatible - must re-embed
	embedder, err := embeddings.GetProvider()
	if err != nil {
		return fmt.Errorf("embedding provider unavailable: %w", err)
	}

	// Generate text for embedding
	text := obs.Core.Title
	if obs.Core.Content != "" {
		text += "\n" + obs.Core.Content
	}

	// Generate new embedding
	vector, err := embedder.Embed(text)
	if err != nil {
		return fmt.Errorf("failed to generate embedding: %w", err)
	}

	// Update observation with new embedding metadata
	obs.Embedding.Vector = vector
	obs.Embedding.Model = embeddings.ModelName
	obs.Embedding.Tokenizer = embedder.TokenizerType()
	obs.Embedding.Dims = embeddings.Dimensions

	// Export with embedding
	return adapter.ExportWithEmbedding(ctx, obs)
}

func (m *SyncManager) pullItemEncrypted(token string, id string, expectedChecksum string, encMgr *encryption.Manager) error {
	client := &http.Client{Timeout: 60 * time.Second}

	// Get download URL (checksum comes from manifest, not this API call)
	req, _ := http.NewRequest("GET", m.apiBase+"/sync/download-url/"+url.PathEscape(id), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get download URL failed: %d", resp.StatusCode)
	}

	var urlResp struct {
		DownloadURL string `json:"downloadUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
		return fmt.Errorf("decode download URL response: %w", err)
	}

	// Download encrypted data from GCS
	dlReq, _ := http.NewRequest("GET", urlResp.DownloadURL, nil)
	dlResp, err := client.Do(dlReq)
	if err != nil {
		return err
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %d", dlResp.StatusCode)
	}

	encryptedData, err := io.ReadAll(dlResp.Body)
	if err != nil {
		return err
	}

	// Note: Checksum verification skipped - decryption success is the real validation
	// Historical data may have mismatched checksums due to manifest/GCS inconsistencies

	// Try to decrypt with vault keys first, then fall back to user's derived key
	var obs *storage.Observation

	// Try each vault key
	cfg, _ := loadLocalVaultConfig()
	if cfg != nil {
		for _, v := range cfg.Vaults {
			if v.EncryptedVaultKey == "" {
				continue
			}
			vaultKey, err := encMgr.DecryptVaultKey(v.EncryptedVaultKey)
			if err != nil {
				continue
			}
			obs, err = encMgr.DecryptObservationWithKey(encryptedData, vaultKey)
			if err == nil {
				// Successfully decrypted with this vault key
				break
			}
		}
	}

	// Fall back to user's derived key if vault keys didn't work
	if obs == nil {
		var err error
		obs, err = encMgr.DecryptObservation(encryptedData)
		if err != nil {
			return fmt.Errorf("decrypt failed: %w", err)
		}
	}

	// Clear session_id for pulled observations — the referenced session
	// exists on the source device, not locally, and would violate the FK constraint
	obs.Core.SessionID = ""

	// Save to local storage
	if err := m.backend.SaveObservation(obs); err != nil {
		return err
	}

	// Export to claude-mem with re-embedding if needed
	ctx := context.Background()
	if err := exportToClaudeMemWithEmbedding(ctx, obs); err != nil {
		log.Printf("[sync] Failed to export to claude-mem: %v", err)
	}

	return nil
}

// pullBatch fetches download URLs for multiple items in one API call, then downloads them
func (m *SyncManager) pullBatch(token string, items []manifestItem, encMgr *encryption.Manager, syncManifest *storage.SyncManifest) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}

	client := &http.Client{Timeout: 120 * time.Second}

	// Build request for batch download URLs
	itemIDs := make([]string, len(items))
	itemMap := make(map[string]manifestItem)
	for i, item := range items {
		itemIDs[i] = item.ID
		itemMap[item.ID] = item
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"items": itemIDs,
	})

	req, _ := http.NewRequest("POST", m.apiBase+"/sync/download-urls", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("batch download-urls failed %d: %s", resp.StatusCode, string(body))
	}

	var urlResp struct {
		Items []struct {
			ID          string `json:"id"`
			DownloadURL string `json:"downloadUrl"`
			Error       string `json:"error,omitempty"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
		return 0, fmt.Errorf("decode batch download-urls: %w", err)
	}

	// Download each item using the signed URLs
	pulled := 0
	for _, urlItem := range urlResp.Items {
		if urlItem.Error != "" {
			log.Printf("[sync] Download URL error for %s: %s", urlItem.ID, urlItem.Error)
			continue
		}

		manifestItem := itemMap[urlItem.ID]
		updatedAt, err := m.downloadAndProcess(urlItem.DownloadURL, urlItem.ID, manifestItem.Checksum, encMgr)
		if err != nil {
			log.Printf("[sync] Pull error for %s: %v", urlItem.ID, err)
			continue
		}

		pulled++
		syncManifest.MarkSeen(urlItem.ID)
		// Record the cloud checksum so we don't re-push this item.
		// Re-encryption produces different ciphertexts (random nonce), so without
		// this the local checksum would never match the cloud checksum.
		syncManifest.SetLocalUpload(urlItem.ID, manifestItem.Checksum, updatedAt)
	}

	return pulled, nil
}

// downloadAndProcess downloads encrypted data from a signed URL and processes it.
// Returns the observation's UpdatedAt time on success for sync manifest tracking.
func (m *SyncManager) downloadAndProcess(downloadURL, id, expectedChecksum string, encMgr *encryption.Manager) (time.Time, error) {
	var zero time.Time
	client := &http.Client{Timeout: 60 * time.Second}

	dlReq, _ := http.NewRequest("GET", downloadURL, nil)
	dlResp, err := client.Do(dlReq)
	if err != nil {
		return zero, err
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("download failed: %d", dlResp.StatusCode)
	}

	encryptedData, err := io.ReadAll(dlResp.Body)
	if err != nil {
		return zero, err
	}

	// Note: Checksum verification skipped - decryption success is the real validation
	// Historical data may have mismatched checksums due to manifest/GCS inconsistencies

	// Try to decrypt with vault keys first, then fall back to user's derived key
	var obs *storage.Observation

	cfg, _ := loadLocalVaultConfig()
	if cfg != nil {
		for _, v := range cfg.Vaults {
			if v.EncryptedVaultKey == "" {
				continue
			}
			vaultKey, err := encMgr.DecryptVaultKey(v.EncryptedVaultKey)
			if err != nil {
				continue
			}
			obs, err = encMgr.DecryptObservationWithKey(encryptedData, vaultKey)
			if err == nil {
				break
			}
		}
	}

	if obs == nil {
		var err error
		obs, err = encMgr.DecryptObservation(encryptedData)
		if err != nil {
			return zero, fmt.Errorf("decrypt failed: %w", err)
		}
	}

	// Bind the ciphertext to the record we asked for.
	//
	// Every observation is encrypted under the same AAD string
	// (encryption.AADObservation), so authentication proves only "some
	// observation of this account, under this key" — not WHICH one. Nothing in
	// the sealed bytes names the id. A malicious or compromised server can
	// therefore answer a request for one id with a different, older, or
	// previously deleted ciphertext: GCM verifies, decryption succeeds, and the
	// client stores content it never asked for. Checksum verification is
	// deliberately skipped above, so it does not catch this either.
	//
	// The decrypted body does carry its own id, and the server cannot forge that
	// without the key. Comparing it to the id we requested closes the
	// substitution without changing the format or breaking existing ciphertexts
	// — which making the id part of the AAD would do, since every record already
	// stored was sealed under the constant string.
	if obs.ID != id {
		return zero, fmt.Errorf(
			"refusing observation %q returned for request %q: the server answered with a different record",
			obs.ID, id)
	}

	// Standardize embedding for local search compatibility
	standardizeEmbedding(obs)

	// Clear session_id for pulled observations — the referenced session
	// exists on the source device, not locally, and would violate the FK constraint
	obs.Core.SessionID = ""

	// Save to local storage
	if err := m.backend.SaveObservation(obs); err != nil {
		return zero, err
	}

	// Export to claude-mem with re-embedding if needed
	ctx := context.Background()
	if err := exportToClaudeMemWithEmbedding(ctx, obs); err != nil {
		log.Printf("[sync] Failed to export to claude-mem: %v", err)
	}

	return obs.Core.UpdatedAt, nil
}

func (m *SyncManager) deleteFromCloud(token string, id string) error {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("DELETE", m.apiBase+"/sync/item/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

func (m *SyncManager) deleteLocally(id string) error {
	// Get observation first to get project/title for claude-mem deletion
	obs, err := m.backend.GetObservation(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Already deleted or doesn't exist - that's fine
			return nil
		}
		return fmt.Errorf("failed to get observation %s: %w", id, err)
	}

	// Delete from local sinesync storage
	if err := m.backend.DeleteObservation(id); err != nil {
		return fmt.Errorf("delete from storage: %w", err)
	}

	// Delete from claude-mem if it exists there
	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(false)
		if err == nil && adapter != nil {
			defer adapter.Close()
			ctx := context.Background()

			// Try deleting by source ID first (if it came from claude-mem)
			if obs.Source.Adapter == adapters.ClaudeMemAdapterName && obs.Source.ID != "" {
				adapter.DeleteBySourceID(ctx, obs.Source.ID)
			} else {
				// Fall back to project+title match
				adapter.DeleteByProjectAndTitle(ctx, obs.Core.Project, obs.Core.Title)
			}
		}
	}

	log.Printf("[sync] Deleted locally: %s (project: %s)", id, obs.Core.Project)
	return nil
}

// BackfillStatus returns the current backfill state
func (m *SyncManager) BackfillStatus() (running bool, progress, total int, elapsed time.Duration) {
	m.backfillMu.Lock()
	defer m.backfillMu.Unlock()
	if m.backfillRunning {
		elapsed = time.Since(m.backfillStartTime)
	}
	return m.backfillRunning, m.backfillProgress, m.backfillTotal, elapsed
}

// backfillClaudeMemExport exports local sinesync observations that aren't in claude-mem yet
// This handles observations that were pulled before the export-on-pull feature was added
func (m *SyncManager) backfillClaudeMemExport() {
	if !adapters.IsClaudeMemInstalled() {
		return
	}

	// Prevent concurrent backfill runs (shares mutex with embedding backfill)
	m.backfillMu.Lock()
	if m.backfillRunning {
		m.backfillMu.Unlock()
		return
	}
	m.backfillRunning = true
	m.backfillProgress = 0
	m.backfillTotal = 0
	m.backfillStartTime = time.Now()
	m.backfillMu.Unlock()

	defer func() {
		m.backfillMu.Lock()
		m.backfillRunning = false
		m.backfillMu.Unlock()
	}()

	// Get all local observations
	observations, err := m.backend.ListObservations()
	if err != nil {
		log.Printf("[export-backfill] Failed to list observations: %v", err)
		return
	}

	adapter, err := adapters.NewClaudeMemAdapter(false)
	if err != nil || adapter == nil {
		return
	}
	defer adapter.Close()

	// Find observations not in claude-mem
	var toExport []storage.Observation
	ctx := context.Background()
	for _, obs := range observations {
		exists, _ := adapter.Exists(ctx, &obs)
		if !exists {
			toExport = append(toExport, obs)
		}
	}

	if len(toExport) == 0 {
		return
	}

	m.backfillMu.Lock()
	m.backfillTotal = len(toExport)
	m.backfillMu.Unlock()

	log.Printf("[export-backfill] Starting: %d observations to export to claude-mem", len(toExport))
	start := time.Now()
	exported := 0
	errors := 0

	for i, obs := range toExport {
		obsCopy := obs // avoid closure issues
		if err := exportToClaudeMemWithEmbedding(ctx, &obsCopy); err != nil {
			errors++
			if errors <= 3 {
				log.Printf("[export-backfill] Error exporting %s: %v", obs.ID, err)
			}
		} else {
			exported++
		}

		m.backfillMu.Lock()
		m.backfillProgress = i + 1
		m.backfillMu.Unlock()

		// Log progress every 500
		if (i+1)%500 == 0 {
			elapsed := time.Since(start)
			rate := float64(i+1) / elapsed.Seconds()
			log.Printf("[export-backfill] Progress: %d/%d (%.0f/sec)", i+1, len(toExport), rate)
		}
	}

	log.Printf("[export-backfill] Complete: %d exported, %d errors in %v", exported, errors, time.Since(start).Round(time.Second))
}

// backfillChromaEmbeddings generates embeddings for claude-mem observations that don't have ChromaDB entries
// Runs continuously until backlog is cleared
func (m *SyncManager) backfillChromaEmbeddings() {
	// Prevent concurrent backfill runs
	m.backfillMu.Lock()
	if m.backfillRunning {
		m.backfillMu.Unlock()
		return
	}
	m.backfillRunning = true
	m.backfillProgress = 0
	m.backfillTotal = 0
	m.backfillStartTime = time.Now()
	m.backfillMu.Unlock()

	defer func() {
		m.backfillMu.Lock()
		m.backfillRunning = false
		m.backfillMu.Unlock()
	}()

	if !adapters.IsClaudeMemInstalled() {
		return
	}

	adapter, err := adapters.NewClaudeMemAdapter(false)
	if err != nil || adapter == nil {
		return
	}
	defer adapter.Close()

	// Get initial backlog count
	backlog := adapter.GetEmbeddingBacklog()
	if backlog == 0 {
		return
	}

	m.backfillMu.Lock()
	m.backfillTotal = backlog
	m.backfillMu.Unlock()

	log.Printf("[backfill] Starting: %d observations need embeddings", backlog)
	start := time.Now()
	totalProcessed := 0

	// Process in batches until done
	const batchSize = 200
	for {
		processed, err := adapter.BackfillEmbeddings(batchSize)
		if err != nil {
			// Silently handle SQLITE_BUSY - will retry on next cycle
			if !strings.Contains(err.Error(), "SQLITE_BUSY") && !strings.Contains(err.Error(), "database is locked") {
				log.Printf("[backfill] Error: %v", err)
			}
			break
		}

		if processed == 0 {
			break // Done
		}

		totalProcessed += processed

		m.backfillMu.Lock()
		m.backfillProgress = totalProcessed
		m.backfillMu.Unlock()

		// Log progress every 1000 (less noisy)
		if totalProcessed%1000 < batchSize {
			elapsed := time.Since(start)
			rate := float64(totalProcessed) / elapsed.Seconds()
			remaining := backlog - totalProcessed
			if remaining < 0 {
				remaining = 0
			}
			log.Printf("[backfill] Progress: %d/%d (%.0f/sec, %d remaining)", totalProcessed, backlog, rate, remaining)
		}
	}

	if totalProcessed > 0 {
		log.Printf("[backfill] Complete: %d embeddings in %v", totalProcessed, time.Since(start).Round(time.Second))
	}
}
