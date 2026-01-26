package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/encryption"
	"github.com/miclip/sinesync/internal/storage"
	"github.com/zalando/go-keyring"
)

const (
	SyncInterval    = 10 * time.Minute
	DefaultAPIBase  = "https://api.sinesync.ai/v1"
)

// SyncManager handles background cloud sync
type SyncManager struct {
	localStorage *storage.LocalStorage
	apiBase      string
	stopChan     chan struct{}
	wg           sync.WaitGroup
	mu           sync.Mutex
	lastSync     time.Time
	lastError    string
	syncing      bool
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
		m.setError(err.Error())
		log.Printf("[sync] Failed: %v", err)
		return
	}

	m.mu.Lock()
	m.lastSync = time.Now()
	m.lastError = ""
	m.mu.Unlock()

	log.Printf("[sync] Complete: pushed=%d, pulled=%d, duration=%v", pushed, pulled, time.Since(start))
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

func (m *SyncManager) sync(token string) (pushed, pulled int, err error) {
	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return 0, 0, fmt.Errorf("encryption key not available - please login again")
	}

	// Get cloud manifest
	manifest, err := m.getCloudManifest(token)
	if err != nil {
		return 0, 0, fmt.Errorf("get manifest: %w", err)
	}

	cloudItems := make(map[string]string)
	for _, item := range manifest.Items {
		cloudItems[item.ID] = item.Checksum
	}

	// Get local observations
	observations, err := m.localStorage.ListObservations()
	if err != nil {
		return 0, 0, fmt.Errorf("list observations: %w", err)
	}

	// Encrypt observations and compute checksums
	var encryptedItems []encryptedObsItem

	localItems := make(map[string]string)
	for _, obs := range observations {
		encrypted, err := encMgr.EncryptObservation(&obs)
		if err != nil {
			log.Printf("[sync] Encrypt error for %s: %v", obs.ID, err)
			continue
		}
		// Checksum is based on encrypted data
		checksum := storage.Checksum(encrypted)[:16]
		localItems[obs.ID] = checksum
		encryptedItems = append(encryptedItems, encryptedObsItem{
			obs:       obs,
			encrypted: encrypted,
			checksum:  checksum,
		})
	}

	// Find items to push
	var toPush []encryptedObsItem
	for _, item := range encryptedItems {
		if cloudChecksum, exists := cloudItems[item.obs.ID]; !exists || cloudChecksum != item.checksum {
			toPush = append(toPush, item)
		}
	}

	// Find items to pull
	var toPull []manifestItem
	for _, item := range manifest.Items {
		if _, exists := localItems[item.ID]; !exists {
			toPull = append(toPull, item)
		}
	}

	// Push in batches
	batchSize := 50
	for i := 0; i < len(toPush); i += batchSize {
		end := i + batchSize
		if end > len(toPush) {
			end = len(toPush)
		}
		batch := toPush[i:end]

		n, err := m.pushBatchEncrypted(token, batch)
		if err != nil {
			log.Printf("[sync] Push batch error: %v", err)
		}
		pushed += n
	}

	// Pull items
	for _, item := range toPull {
		if err := m.pullItemEncrypted(token, item.ID, encMgr); err != nil {
			log.Printf("[sync] Pull error for %s: %v", item.ID, err)
			continue
		}
		pulled++
	}

	// Update sync manifest
	syncManifest := storage.GetSyncManifest()
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
}

func (m *SyncManager) pushBatchEncrypted(token string, batch []encryptedObsItem) (int, error) {
	// Prepare items for URL request
	type itemReq struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		SizeBytes int    `json:"sizeBytes"`
		Checksum  string `json:"checksum"`
	}

	items := make([]itemReq, 0, len(batch))
	itemData := make(map[string][]byte)

	for _, item := range batch {
		items = append(items, itemReq{
			ID:        item.obs.ID,
			Type:      "memory",
			SizeBytes: len(item.encrypted),
			Checksum:  item.checksum,
		})
		itemData[item.obs.ID] = item.encrypted
	}

	// Get upload URLs
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)

	client := &http.Client{Timeout: 60 * time.Second}
	req, _ := http.NewRequest("POST", m.apiBase+"/sync/upload-urls", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("get URLs failed %d: %s", resp.StatusCode, string(respBody))
	}

	var urlResp struct {
		Items []struct {
			ID        string `json:"id"`
			UploadURL string `json:"uploadUrl"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
		return 0, fmt.Errorf("decode upload URLs response: %w", err)
	}

	// Upload encrypted data to GCS
	var confirmItems []map[string]interface{}
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
			confirmItems = append(confirmItems, map[string]interface{}{
				"id":        urlItem.ID,
				"type":      "memory",
				"sizeBytes": len(data),
				"checksum":  storage.Checksum(data)[:16],
			})
		}
	}

	if len(confirmItems) == 0 {
		return 0, nil
	}

	// Confirm uploads
	confirmBody := map[string]interface{}{"items": confirmItems}
	confirmBytes, _ := json.Marshal(confirmBody)

	confirmReq, _ := http.NewRequest("POST", m.apiBase+"/sync/confirm-uploads", bytes.NewReader(confirmBytes))
	confirmReq.Header.Set("Content-Type", "application/json")
	confirmReq.Header.Set("Authorization", "Bearer "+token)

	confirmResp, err := client.Do(confirmReq)
	if err != nil {
		return 0, err
	}
	defer confirmResp.Body.Close()

	if confirmResp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("confirm failed")
	}

	var confirmResult struct {
		Items []struct {
			Success bool `json:"success"`
		} `json:"items"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmResult); err != nil {
		return 0, fmt.Errorf("decode confirm response: %w", err)
	}

	count := 0
	for _, item := range confirmResult.Items {
		if item.Success {
			count++
		}
	}

	return count, nil
}

func (m *SyncManager) pullItemEncrypted(token string, id string, encMgr *encryption.Manager) error {
	client := &http.Client{Timeout: 60 * time.Second}

	// Get download URL
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
		Checksum    string `json:"checksum"`
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

	// Verify checksum (of encrypted data)
	if storage.Checksum(encryptedData)[:16] != urlResp.Checksum {
		return fmt.Errorf("checksum mismatch")
	}

	// Decrypt observation
	obs, err := encMgr.DecryptObservation(encryptedData)
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}

	return m.localStorage.SaveObservation(obs)
}
