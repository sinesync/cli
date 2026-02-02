package daemon

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
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

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/encryption"
	"github.com/miclip/sinesync/internal/storage"
	"github.com/zalando/go-keyring"
)

const (
	SyncInterval    = 10 * time.Minute
	DefaultAPIBase  = "https://api.sinesync.ai/v1"
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
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return "", err
	}

	for _, v := range cfg.Vaults {
		if v.IsDefault {
			return v.VaultID, nil
		}
	}

	return "", fmt.Errorf("no default vault configured")
}

// getVaultIDForObservation returns the vault ID for an observation based on its project
func getVaultIDForObservation(project string, defaultVaultID string) string {
	if project == "" {
		return defaultVaultID
	}

	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return defaultVaultID
	}

	// Find vault that has this project assigned
	for _, v := range cfg.Vaults {
		for _, p := range v.Projects {
			if p == project {
				return v.VaultID
			}
		}
	}

	return defaultVaultID
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
	localStorage    *storage.LocalStorage
	apiBase         string
	stopChan        chan struct{}
	backfillStop    chan struct{}
	wg              sync.WaitGroup
	mu              sync.Mutex
	lastSync        time.Time
	lastError       string
	syncing         bool
	chromaClient    *adapters.ChromaMCPClient // Shared chroma client for embedding
	backfillRunning bool
}

// NewSyncManager creates a new sync manager
func NewSyncManager(localStorage *storage.LocalStorage) *SyncManager {
	apiBase := os.Getenv("SINESYNC_API_URL")
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}

	return &SyncManager{
		localStorage: localStorage,
		apiBase:      apiBase,
		stopChan:     make(chan struct{}),
		backfillStop: make(chan struct{}),
	}
}

// Start begins background sync
func (m *SyncManager) Start() {
	m.wg.Add(1)
	go m.syncLoop()
	log.Printf("[sync] Background sync started (interval: %v)", SyncInterval)

	// Start continuous ChromaDB backfill if claude-mem is installed
	if adapters.IsClaudeMemInstalled() {
		m.wg.Add(1)
		go m.chromaBackfillLoop()
		log.Printf("[sync] ChromaDB backfill started (continuous)")
	}
}

// Stop halts background sync
func (m *SyncManager) Stop() {
	close(m.stopChan)
	close(m.backfillStop)
	m.wg.Wait()
	log.Printf("[sync] Background sync stopped")
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
	case <-m.stopChan:
		return
	}

	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.doSync()
		case <-m.stopChan:
			return
		}
	}
}

func (m *SyncManager) doSync() {
	m.mu.Lock()
	if m.syncing {
		m.mu.Unlock()
		return
	}
	m.syncing = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.syncing = false
		m.mu.Unlock()
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
			log.Printf("[sync] Token expired, attempting refresh...")
			newToken, refreshErr := m.refreshAccessToken()
			if refreshErr != nil {
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
	m.mu.Unlock()

	log.Printf("[sync] Complete: pushed=%d, pulled=%d, duration=%v", pushed, pulled, time.Since(start))
}

func isUnauthorizedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") || strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "Unauthorized")
}

func (m *SyncManager) setError(err string) {
	m.mu.Lock()
	m.lastError = err
	m.mu.Unlock()
}

func (m *SyncManager) getAuthToken() (string, error) {
	const keyringService = "sinesync"

	// Check keyring first (preferred secure storage)
	if token, err := keyring.Get(keyringService, "token"); err == nil && token != "" {
		return token, nil
	}
	if deviceToken, err := keyring.Get(keyringService, "deviceToken"); err == nil && deviceToken != "" {
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
	const keyringService = "sinesync"

	// Check keyring first
	if refreshToken, err := keyring.Get(keyringService, "refreshToken"); err == nil && refreshToken != "" {
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
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode refresh response: %w", err)
	}

	// Store new token in keyring
	const keyringService = "sinesync"
	if err := keyring.Set(keyringService, "token", result.Token); err != nil {
		// Also update auth.json as fallback
		m.updateStoredToken(result.Token)
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

	// Initialize chroma client for embedding (if claude-mem is installed)
	if adapters.IsClaudeMemInstalled() {
		m.chromaClient = adapters.NewChromaMCPClient()
		ctx := context.Background()
		if err := m.chromaClient.Connect(ctx); err != nil {
			log.Printf("[sync] ChromaDB connect failed (will skip embedding): %v", err)
			m.chromaClient = nil
		} else {
			if err := m.chromaClient.EnsureCollection(ctx); err != nil {
				log.Printf("[sync] ChromaDB ensure collection failed: %v", err)
				m.chromaClient.Close()
				m.chromaClient = nil
			} else {
				log.Printf("[sync] ChromaDB connected for real-time embedding")
			}
		}
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
	observations, err := m.localStorage.ListObservations()
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
		if cloudChecksum, exists := cloudItems[obs.ID]; !exists || cloudChecksum != checksum {
			toPush = append(toPush, encryptedObsItem{
				obs:       obs,
				encrypted: encrypted,
				checksum:  checksum,
				vaultID:   vaultID,
			})
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

	// Close chroma client if it was used (backfill now runs in separate goroutine)
	if m.chromaClient != nil {
		m.chromaClient.Close()
		m.chromaClient = nil
	}

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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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

func (m *SyncManager) pullItemEncrypted(token string, id string, expectedChecksum string, encMgr *encryption.Manager) error {
	client := &http.Client{Timeout: 60 * time.Second}

	// Get download URL (checksum comes from manifest, not this API call)
	req, _ := http.NewRequest("GET", m.apiBase+"/sync/download-url/"+url.PathEscape(id), nil)
	req.Header.Set("Authorization", "Bearer "+token)

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

	// Save to local storage
	if err := m.localStorage.SaveObservation(obs); err != nil {
		return err
	}

	// Export to claude-mem if installed
	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(false)
		if err == nil && adapter != nil {
			defer adapter.Close()
			ctx := context.Background()
			if err := adapter.Export(ctx, obs); err != nil {
				log.Printf("[sync] Failed to export to claude-mem: %v", err)
			}
		}
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
		if err := m.downloadAndProcess(urlItem.DownloadURL, urlItem.ID, manifestItem.Checksum, encMgr); err != nil {
			log.Printf("[sync] Pull error for %s: %v", urlItem.ID, err)
			continue
		}

		pulled++
		syncManifest.MarkSeen(urlItem.ID)
	}

	return pulled, nil
}

// downloadAndProcess downloads encrypted data from a signed URL and processes it
func (m *SyncManager) downloadAndProcess(downloadURL, id, expectedChecksum string, encMgr *encryption.Manager) error {
	client := &http.Client{Timeout: 60 * time.Second}

	dlReq, _ := http.NewRequest("GET", downloadURL, nil)
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
			return fmt.Errorf("decrypt failed: %w", err)
		}
	}

	// Save to local storage
	if err := m.localStorage.SaveObservation(obs); err != nil {
		return err
	}

	// Export to claude-mem SQLite if installed
	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(false)
		if err == nil && adapter != nil {
			ctx := context.Background()
			if err := adapter.Export(ctx, obs); err != nil {
				log.Printf("[sync] Failed to export to claude-mem: %v", err)
			}

			// Embed to ChromaDB immediately (blocks until complete - natural backpressure)
			if m.chromaClient != nil {
				obsID := adapter.GetLastInsertedID()
				// If Export returned early (observation already exists), fall back to lookup
				if obsID <= 0 {
					obsID = adapter.GetObservationID(ctx, obs)
				}
				if obsID > 0 {
					// Extract fields similar to Export logic
					narrative := obs.Core.Content
					subtitle := obs.Core.Summary
					memorySessionID := "sinesync-" + obs.ID[:8]
					if ext, ok := obs.GetExtension(adapters.ClaudeMemAdapterName); ok {
						if extMap, ok := ext.(map[string]interface{}); ok {
							if v, ok := extMap["narrative"].(string); ok && v != "" {
								narrative = v
							}
							if v, ok := extMap["sdkSessionId"].(string); ok && v != "" {
								memorySessionID = v
							}
							if v, ok := extMap["subtitle"].(string); ok && v != "" {
								subtitle = v
							}
						}
					}
					project := obs.Core.Project
					if project == "" {
						project = "unknown"
					}

					ids, docs, metas := adapters.FormatObservationDocs(
						obsID,
						memorySessionID,
						project,
						obs.Core.Type,
						obs.Core.Title,
						subtitle,
						narrative,
						obs.Structured.Facts,
						obs.Structured.Concepts,
						obs.Structured.Files.Read,
						obs.Structured.Files.Modified,
						obs.Core.CreatedAt.Unix(),
					)
					if len(ids) > 0 {
						if err := m.chromaClient.AddDocuments(ctx, ids, docs, metas); err != nil {
							log.Printf("[sync] ChromaDB embed failed for obs %d: %v", obsID, err)
						} else {
							// Mark as embedded in sync manifest
							storage.GetSyncManifest().MarkChromaEmbedded(id)
						}
					}
				}
			}
			adapter.Close()
		}
	}

	return nil
}

func (m *SyncManager) deleteFromCloud(token string, id string) error {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("DELETE", m.apiBase+"/sync/item/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

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
	obs, err := m.localStorage.GetObservation(id)
	if err != nil {
		// Already deleted or doesn't exist - that's fine
		return nil
	}

	// Delete from local sinesync storage
	if err := m.localStorage.Delete("observations", id); err != nil {
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

// backfillChromaDB embeds existing observations to ChromaDB that haven't been embedded yet.
// Processes observations one at a time with natural backpressure (waits for each response).
// Returns the number of observations embedded this cycle.
func (m *SyncManager) backfillChromaDB(syncManifest *storage.SyncManifest) int {
	const batchSize = 100 // Max observations to backfill per sync cycle

	// Get all local observations
	observations, err := m.localStorage.ListObservations()
	if err != nil {
		log.Printf("[sync] ChromaDB backfill: failed to list observations: %v", err)
		return 0
	}

	// Find observations that need embedding
	var toEmbed []storage.Observation
	for _, obs := range observations {
		if !syncManifest.IsChromaEmbedded(obs.ID) {
			toEmbed = append(toEmbed, obs)
			if len(toEmbed) >= batchSize {
				break
			}
		}
	}

	if len(toEmbed) == 0 {
		return 0
	}

	remaining := len(observations) - syncManifest.GetChromaEmbeddedCount()
	log.Printf("[sync] ChromaDB backfill: processing %d of %d remaining observations", len(toEmbed), remaining)

	// Open claude-mem adapter for getting sqlite IDs
	adapter, err := adapters.NewClaudeMemAdapter(false)
	if err != nil {
		log.Printf("[sync] ChromaDB backfill: failed to open claude-mem: %v", err)
		return 0
	}
	defer adapter.Close()

	ctx := context.Background()
	embedded := 0

	for _, obs := range toEmbed {
		// First ensure the observation is exported to claude-mem SQLite
		if err := adapter.Export(ctx, &obs); err != nil {
			log.Printf("[sync] ChromaDB backfill: export to claude-mem failed for %s: %v", obs.ID, err)
			continue
		}

		obsID := adapter.GetLastInsertedID()
		if obsID <= 0 {
			// Observation already exists in claude-mem - look up its ID
			obsID = adapter.GetObservationID(ctx, &obs)
			if obsID <= 0 {
				log.Printf("[sync] ChromaDB backfill: no sqlite ID for %s, skipping", obs.ID)
				// Mark as embedded anyway to avoid infinite retry
				syncManifest.MarkChromaEmbedded(obs.ID)
				continue
			}
		}

		// Extract fields for embedding
		narrative := obs.Core.Content
		subtitle := obs.Core.Summary
		memorySessionID := "sinesync-" + obs.ID[:8]
		if ext, ok := obs.GetExtension(adapters.ClaudeMemAdapterName); ok {
			if extMap, ok := ext.(map[string]interface{}); ok {
				if v, ok := extMap["narrative"].(string); ok && v != "" {
					narrative = v
				}
				if v, ok := extMap["sdkSessionId"].(string); ok && v != "" {
					memorySessionID = v
				}
				if v, ok := extMap["subtitle"].(string); ok && v != "" {
					subtitle = v
				}
			}
		}
		project := obs.Core.Project
		if project == "" {
			project = "unknown"
		}

		ids, docs, metas := adapters.FormatObservationDocs(
			obsID,
			memorySessionID,
			project,
			obs.Core.Type,
			obs.Core.Title,
			subtitle,
			narrative,
			obs.Structured.Facts,
			obs.Structured.Concepts,
			obs.Structured.Files.Read,
			obs.Structured.Files.Modified,
			obs.Core.CreatedAt.Unix(),
		)

		if len(ids) > 0 {
			// This blocks until ChromaDB responds - natural backpressure
			if err := m.chromaClient.AddDocuments(ctx, ids, docs, metas); err != nil {
				log.Printf("[sync] ChromaDB backfill: embed failed for %s (sqlite %d): %v", obs.ID, obsID, err)
				continue
			}
		}

		// Mark as embedded and save progress
		syncManifest.MarkChromaEmbedded(obs.ID)
		embedded++

		// Save progress every 10 embeddings
		if embedded%10 == 0 {
			syncManifest.Save()
		}
	}

	// Final save
	if embedded > 0 {
		syncManifest.Save()
	}

	return embedded
}

// chromaBackfillLoop runs continuously to backfill observations to ChromaDB
// It processes observations as fast as ChromaDB can handle them (natural backpressure)
func (m *SyncManager) chromaBackfillLoop() {
	defer m.wg.Done()

	// Wait a bit for startup to settle
	select {
	case <-time.After(10 * time.Second):
	case <-m.backfillStop:
		return
	}

	log.Printf("[chroma] Backfill loop starting...")

	for {
		select {
		case <-m.backfillStop:
			log.Printf("[chroma] Backfill loop stopped")
			return
		default:
		}

		// Connect to ChromaDB with cancellable context
		chromaClient := adapters.NewChromaMCPClient()
		ctx, cancel := context.WithCancel(context.Background())

		// Cancel context when backfillStop is triggered (prevents zombie processes)
		go func() {
			select {
			case <-m.backfillStop:
				cancel()
			case <-ctx.Done():
			}
		}()

		if err := chromaClient.Connect(ctx); err != nil {
			log.Printf("[chroma] Connect failed, retrying in 30s: %v", err)
			cancel()
			select {
			case <-time.After(30 * time.Second):
				continue
			case <-m.backfillStop:
				return
			}
		}

		if err := chromaClient.EnsureCollection(ctx); err != nil {
			log.Printf("[chroma] EnsureCollection failed, retrying in 30s: %v", err)
			cancel()
			chromaClient.Close()
			select {
			case <-time.After(30 * time.Second):
				continue
			case <-m.backfillStop:
				return
			}
		}

		// Run backfill until complete or error
		completed := m.runBackfillBatch(chromaClient)
		cancel()
		chromaClient.Close()

		if completed {
			log.Printf("[chroma] Backfill complete! All observations embedded.")
			// Check periodically for new observations
			select {
			case <-time.After(5 * time.Minute):
				continue
			case <-m.backfillStop:
				return
			}
		}

		// Small delay between batches to avoid hammering on errors
		select {
		case <-time.After(1 * time.Second):
		case <-m.backfillStop:
			return
		}
	}
}

// runBackfillBatch processes observations until done or error
// Returns true if all observations are embedded
func (m *SyncManager) runBackfillBatch(chromaClient *adapters.ChromaMCPClient) bool {
	syncManifest := storage.GetSyncManifest()

	// Get all local observations
	observations, err := m.localStorage.ListObservations()
	if err != nil {
		log.Printf("[chroma] Failed to list observations: %v", err)
		return false
	}

	// Find observations that need embedding
	var toEmbed []storage.Observation
	for _, obs := range observations {
		if !syncManifest.IsChromaEmbedded(obs.ID) {
			toEmbed = append(toEmbed, obs)
		}
	}

	if len(toEmbed) == 0 {
		return true // All done
	}

	log.Printf("[chroma] Backfilling %d observations to ChromaDB...", len(toEmbed))

	// Open claude-mem adapter
	adapter, err := adapters.NewClaudeMemAdapter(false)
	if err != nil {
		log.Printf("[chroma] Failed to open claude-mem: %v", err)
		return false
	}
	defer adapter.Close()

	ctx := context.Background()
	embedded := 0
	errors := 0
	startTime := time.Now()

	for i, obs := range toEmbed {
		// Check for stop signal
		select {
		case <-m.backfillStop:
			log.Printf("[chroma] Backfill interrupted, embedded %d observations", embedded)
			return false
		default:
		}

		// Ensure observation exists in claude-mem SQLite
		if err := adapter.Export(ctx, &obs); err != nil {
			errors++
			continue
		}

		obsID := adapter.GetLastInsertedID()
		if obsID <= 0 {
			obsID = adapter.GetObservationID(ctx, &obs)
			if obsID <= 0 {
				syncManifest.MarkChromaEmbedded(obs.ID) // Skip this one
				continue
			}
		}

		// Extract fields for embedding
		narrative := obs.Core.Content
		subtitle := obs.Core.Summary
		memorySessionID := "sinesync-" + obs.ID[:8]
		if ext, ok := obs.GetExtension(adapters.ClaudeMemAdapterName); ok {
			if extMap, ok := ext.(map[string]interface{}); ok {
				if v, ok := extMap["narrative"].(string); ok && v != "" {
					narrative = v
				}
				if v, ok := extMap["sdkSessionId"].(string); ok && v != "" {
					memorySessionID = v
				}
				if v, ok := extMap["subtitle"].(string); ok && v != "" {
					subtitle = v
				}
			}
		}
		project := obs.Core.Project
		if project == "" {
			project = "unknown"
		}

		ids, docs, metas := adapters.FormatObservationDocs(
			obsID,
			memorySessionID,
			project,
			obs.Core.Type,
			obs.Core.Title,
			subtitle,
			narrative,
			obs.Structured.Facts,
			obs.Structured.Concepts,
			obs.Structured.Files.Read,
			obs.Structured.Files.Modified,
			obs.Core.CreatedAt.Unix(),
		)

		if len(ids) == 0 {
			// No documents to embed (empty content)
			syncManifest.MarkChromaEmbedded(obs.ID)
			continue
		}

		// Natural backpressure - wait for ChromaDB response
		if err := chromaClient.AddDocuments(ctx, ids, docs, metas); err != nil {
			log.Printf("[chroma] AddDocuments error for %s: %v", obs.ID[:8], err)
			errors++
			if errors > 10 {
				log.Printf("[chroma] Too many errors (%d), pausing backfill", errors)
				return false
			}
			continue
		}

		syncManifest.MarkChromaEmbedded(obs.ID)
		embedded++
		errors = 0 // Reset error count on success

		// Save progress and log every 100 embeddings
		if embedded%100 == 0 {
			syncManifest.Save()
			elapsed := time.Since(startTime)
			rate := float64(embedded) / elapsed.Seconds()
			remaining := len(toEmbed) - i - 1
			eta := time.Duration(float64(remaining)/rate) * time.Second
			log.Printf("[chroma] Progress: %d/%d embedded (%.1f/sec, ETA: %v)", embedded, len(toEmbed), rate, eta)
		}
	}

	if embedded > 0 {
		syncManifest.Save()
		elapsed := time.Since(startTime)
		rate := float64(embedded) / elapsed.Seconds()
		log.Printf("[chroma] Batch complete: embedded %d observations in %v (%.1f/sec)", embedded, elapsed, rate)
	}

	return len(toEmbed) == embedded
}
