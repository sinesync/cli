package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/embeddings"
	"github.com/miclip/sinesync/internal/encryption"
	"github.com/miclip/sinesync/internal/storage"
	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync observations with cloud",
	Long: `Sync observations between local storage and sine~sync cloud.

Running 'sync' without subcommands performs bidirectional sync (push then pull).

Subcommands:
  push     Push local observations to cloud only
  pull     Pull observations from cloud only
  status   Show sync status`,
	RunE: runSync,
}

var syncPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push local observations to cloud",
	RunE:  runSyncPush,
}

var syncPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull observations from cloud to local",
	RunE:  runSyncPull,
}

var syncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sync status",
	RunE:  runSyncStatus,
}

func init() {
	syncCmd.AddCommand(syncPushCmd)
	syncCmd.AddCommand(syncPullCmd)
	syncCmd.AddCommand(syncStatusCmd)
	rootCmd.AddCommand(syncCmd)
}

func runSync(cmd *cobra.Command, args []string) error {
	token, err := getAuthToken()
	if err != nil {
		return err
	}

	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return fmt.Errorf("encryption key not available - please login again")
	}

	// Get default vault ID (fallback for projects not assigned to a vault)
	defaultVaultID, err := GetDefaultVaultID()
	if err != nil {
		return fmt.Errorf("no vault configured - run 'sinesync vault sync' first: %w", err)
	}

	apiBase := getAPIBase()
	localStorage := storage.NewLocalStorage()

	// Get cloud manifest once for both operations
	fmt.Println("Fetching cloud manifest...")
	manifest, err := withTokenRefresh(apiBase, &token, func(t string) (*manifestResponse, error) {
		return getCloudManifest(apiBase, t)
	})
	if err != nil {
		return fmt.Errorf("failed to get cloud manifest: %w", err)
	}

	cloudItems := make(map[string]string) // id -> checksum
	for _, item := range manifest.Items {
		cloudItems[item.ID] = item.Checksum
	}

	// Load local observations
	fmt.Println("Loading local observations...")
	observations, err := localStorage.ListObservations()
	if err != nil {
		return fmt.Errorf("failed to load local observations: %w", err)
	}

	// Check which observations need pushing (using cached checksums when possible)
	fmt.Println("Checking observations...")
	var pending []pendingItem
	localItems := make(map[string]string) // id -> checksum
	syncManifest := storage.GetSyncManifest()

	for _, obs := range observations {
		var checksum string
		var encrypted []byte

		// Check if we have a cached upload state for this observation
		if cached, exists := syncManifest.GetLocalUpload(obs.ID); exists {
			// Use cached checksum if observation hasn't changed
			obsUpdatedAt := obs.Core.UpdatedAt
			if !obsUpdatedAt.After(cached.UpdatedAt) {
				checksum = cached.Checksum
				localItems[obs.ID] = checksum
				// Check if cloud has same checksum - skip if synced
				if cloudChecksum, ok := cloudItems[obs.ID]; ok && cloudChecksum == checksum {
					continue
				}
				// Need to re-encrypt for push (cloud doesn't have it or checksum differs)
				var err error
				encrypted, err = encMgr.EncryptObservation(&obs)
				if err != nil {
					fmt.Printf("  Warning: failed to encrypt %s: %v\n", obs.ID, err)
					continue
				}
				// Route to project's vault or default
				obsVaultID := getVaultIDForObservation(obs.Core.Project, defaultVaultID)
				pending = append(pending, pendingItem{obs: obs, data: encrypted, checksum: checksum, vaultID: obsVaultID})
				continue
			}
		}

		// No cache or observation changed - encrypt and compute new checksum
		var err error
		encrypted, err = encMgr.EncryptObservation(&obs)
		if err != nil {
			fmt.Printf("  Warning: failed to encrypt %s: %v\n", obs.ID, err)
			continue
		}
		checksum = storage.Checksum(encrypted)[:16]
		localItems[obs.ID] = checksum

		// Check if needs pushing
		if cloudChecksum, ok := cloudItems[obs.ID]; ok && cloudChecksum == checksum {
			continue
		}
		// Route to project's vault or default
		obsVaultID := getVaultIDForObservation(obs.Core.Project, defaultVaultID)
		pending = append(pending, pendingItem{obs: obs, data: encrypted, checksum: checksum, vaultID: obsVaultID})
	}

	fmt.Printf("Local: %d items, Cloud: %d items\n", len(localItems), len(cloudItems))
	fmt.Println()

	pushSkipped := len(observations) - len(pending)

	// Show per-vault breakdown
	if len(pending) > 0 {
		vaultCounts := make(map[string]int)
		for _, item := range pending {
			vaultCounts[item.vaultID]++
		}
		if len(vaultCounts) > 1 {
			fmt.Println("Routing by vault:")
			cfg, _ := loadLocalVaultConfig()
			for vaultID, count := range vaultCounts {
				vaultName := vaultID[:8] + "..."
				if cfg != nil {
					for _, v := range cfg.Vaults {
						if v.VaultID == vaultID {
							vaultName = v.Name
							break
						}
					}
				}
				fmt.Printf("  %s: %d items\n", vaultName, count)
			}
			fmt.Println()
		}
	}

	fmt.Printf("Pushing to cloud: %d items to upload, %d already synced\n", len(pending), pushSkipped)

	// Push in batches
	pushed := 0
	pushErrors := 0
	var lastPushError string
	batchSize := 50

	for i := 0; i < len(pending); i += batchSize {
		end := i + batchSize
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[i:end]

		// Get upload URLs for batch
		urls, err := getUploadUrlsBatchEncrypted(apiBase, token, batch)
		if err != nil {
			pushErrors += len(batch)
			lastPushError = fmt.Sprintf("get URLs batch: %v", err)
			if pushErrors == len(batch) {
				fmt.Printf("\n  First error: %s\n", lastPushError)
			}
			continue
		}

		// Upload items in parallel
		type uploadResult struct {
			index    int
			id       string
			dataSize int
			checksum string
			vaultID  string
			err      error
		}
		results := make(chan uploadResult, len(batch))

		for j, item := range batch {
			if j >= len(urls) {
				results <- uploadResult{index: j, err: fmt.Errorf("no URL")}
				continue
			}
			go func(idx int, url string, data []byte, id, checksum, vaultID string) {
				err := uploadToGCS(url, data)
				results <- uploadResult{index: idx, id: id, dataSize: len(data), checksum: checksum, vaultID: vaultID, err: err}
			}(j, urls[j].UploadURL, item.data, urls[j].ID, item.checksum, item.vaultID)
		}

		// Collect results
		var confirmItems []map[string]interface{}
		for range batch {
			res := <-results
			if res.err != nil {
				pushErrors++
				lastPushError = fmt.Sprintf("upload: %v", res.err)
				continue
			}
			confirmItem := map[string]interface{}{
				"id":        res.id,
				"vaultId":   res.vaultID,
				"type":      "memory",
				"sizeBytes": res.dataSize,
				"checksum":  res.checksum,
			}
			confirmItems = append(confirmItems, confirmItem)
		}

		// Confirm uploads in batch
		if len(confirmItems) > 0 {
			confirmed, err := confirmUploadsBatch(apiBase, token, confirmItems)
			if err != nil {
				pushErrors += len(confirmItems)
				lastPushError = fmt.Sprintf("confirm batch: %v", err)
			} else {
				for _, c := range confirmed {
					if c.Success {
						pushed++
					} else {
						pushErrors++
						lastPushError = fmt.Sprintf("confirm %s: %s", c.ID, c.Error)
					}
				}
			}
		}

		fmt.Printf("\r  Progress: %d/%d (pushed: %d, errors: %d)", end, len(pending), pushed, pushErrors)
	}
	fmt.Printf("\r  Progress: %d/%d (pushed: %d, errors: %d)       \n", len(pending), len(pending), pushed, pushErrors)

	// Pull: cloud items not in local
	fmt.Println("Pulling from cloud...")
	pulled := 0
	pullSkipped := 0
	pullErrors := 0
	var lastPullError string

	for i, item := range manifest.Items {
		if _, exists := localItems[item.ID]; exists {
			pullSkipped++
			continue
		}

		encryptedData, err := pullFromCloud(apiBase, token, item.ID)
		if err != nil {
			pullErrors++
			lastPullError = fmt.Sprintf("pull %s: %v", item.ID, err)
			if pullErrors == 1 {
				fmt.Printf("\n  First error: %s\n", lastPullError)
			}
			continue
		}

		// Decrypt observation
		obs, err := encMgr.DecryptObservation(encryptedData)
		if err != nil {
			pullErrors++
			lastPullError = fmt.Sprintf("decrypt %s: %v", item.ID, err)
			if pullErrors == 1 {
				fmt.Printf("\n  First error: %s\n", lastPullError)
			}
			continue
		}

		if err := localStorage.SaveObservation(obs); err != nil {
			pullErrors++
			lastPullError = fmt.Sprintf("save %s: %v", item.ID, err)
			if pullErrors == 1 {
				fmt.Printf("\n  First error: %s\n", lastPullError)
			}
			continue
		}

		// Export to claude-mem with re-embedding if needed
		ctx := context.Background()
		if err := exportToClaudeMemWithEmbedding(ctx, obs); err != nil {
			log.Printf("[sync] Failed to export to claude-mem: %v", err)
		}

		pulled++

		if (pulled+pullSkipped)%100 == 0 {
			fmt.Printf("\r  Progress: %d/%d (pulled: %d, skipped: %d, errors: %d)", i+1, len(manifest.Items), pulled, pullSkipped, pullErrors)
		}
	}
	fmt.Printf("\r  Progress: %d/%d (pulled: %d, skipped: %d, errors: %d)\n", len(manifest.Items), len(manifest.Items), pulled, pullSkipped, pullErrors)

	// Update and save sync manifest
	syncManifest.UpdateFromCloud(cloudItems)
	// Add newly pushed items and cache their upload state
	for _, item := range pending {
		syncManifest.MarkSynced(item.obs.ID, item.checksum)
		syncManifest.SetLocalUpload(item.obs.ID, item.checksum, item.obs.Core.UpdatedAt)
	}
	if err := syncManifest.Save(); err != nil {
		fmt.Printf("  Warning: failed to save sync manifest: %v\n", err)
	}

	// Summary
	fmt.Println()
	fmt.Println("Sync complete:")
	fmt.Printf("  Pushed: %d (skipped: %d)\n", pushed, pushSkipped)
	fmt.Printf("  Pulled: %d (skipped: %d)\n", pulled, pullSkipped)
	fmt.Printf("  Total synced: %d\n", syncManifest.GetSyncedCount())
	if pushErrors > 0 || pullErrors > 0 {
		fmt.Printf("  Errors: %d push, %d pull\n", pushErrors, pullErrors)
		if lastPushError != "" {
			fmt.Printf("  Last push error: %s\n", lastPushError)
		}
		if lastPullError != "" {
			fmt.Printf("  Last pull error: %s\n", lastPullError)
		}
	}

	return nil
}

func runSyncPush(cmd *cobra.Command, args []string) error {
	token, err := getAuthToken()
	if err != nil {
		return err
	}

	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return fmt.Errorf("encryption key not available - please login again")
	}

	// Get default vault ID (fallback for projects not assigned to a vault)
	defaultVaultID, err := GetDefaultVaultID()
	if err != nil {
		return fmt.Errorf("no vault configured - run 'sinesync vault sync' first: %w", err)
	}

	apiBase := getAPIBase()
	localStorage := storage.NewLocalStorage()

	fmt.Println("Loading local observations...")
	observations, err := localStorage.ListObservations()
	if err != nil {
		return fmt.Errorf("failed to load local observations: %w", err)
	}
	fmt.Printf("Found %d local observations\n", len(observations))

	// Get cloud manifest to see what's already synced
	fmt.Println("Fetching cloud manifest...")
	manifest, err := withTokenRefresh(apiBase, &token, func(t string) (*manifestResponse, error) {
		return getCloudManifest(apiBase, t)
	})
	if err != nil {
		return fmt.Errorf("failed to get cloud manifest: %w", err)
	}

	cloudItems := make(map[string]string) // id -> checksum
	for _, item := range manifest.Items {
		cloudItems[item.ID] = item.Checksum
	}
	fmt.Printf("Cloud has %d items\n", len(cloudItems))

	// Push observations not in cloud or with different checksum
	pushed := 0
	skipped := 0
	errors := 0
	var lastError string

	for i, obs := range observations {
		if (i+1)%100 == 0 || i+1 == len(observations) {
			fmt.Printf("\rProcessing: %d/%d (pushed: %d, skipped: %d, errors: %d)", i+1, len(observations), pushed, skipped, errors)
		}

		// Encrypt observation
		encrypted, err := encMgr.EncryptObservation(&obs)
		if err != nil {
			errors++
			lastError = fmt.Sprintf("encrypt error: %v", err)
			continue
		}

		// Calculate checksum of encrypted data
		localChecksum := storage.Checksum(encrypted)[:16]

		// Check if already in cloud with same checksum
		if cloudChecksum, exists := cloudItems[obs.ID]; exists && cloudChecksum == localChecksum {
			skipped++
			continue
		}

		// Route to project's vault or default
		obsVaultID := getVaultIDForObservation(obs.Core.Project, defaultVaultID)

		// Push encrypted data to cloud
		err = pushToCloud(apiBase, token, obs.ID, "memory", obsVaultID, encrypted)
		if err != nil {
			errors++
			lastError = fmt.Sprintf("push %s: %v", obs.ID, err)
			continue
		}
		pushed++
	}

	fmt.Println() // New line after progress
	fmt.Println()
	fmt.Println("Push complete:")
	fmt.Printf("  Pushed: %d\n", pushed)
	fmt.Printf("  Skipped (already synced): %d\n", skipped)
	if errors > 0 {
		fmt.Printf("  Errors: %d\n", errors)
		fmt.Printf("  Last error: %s\n", lastError)
	}

	return nil
}

func runSyncPull(cmd *cobra.Command, args []string) error {
	token, err := getAuthToken()
	if err != nil {
		return err
	}

	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return fmt.Errorf("encryption key not available - please login again")
	}

	apiBase := getAPIBase()
	localStorage := storage.NewLocalStorage()

	fmt.Println("Fetching cloud manifest...")
	manifest, err := withTokenRefresh(apiBase, &token, func(t string) (*manifestResponse, error) {
		return getCloudManifest(apiBase, t)
	})
	if err != nil {
		return fmt.Errorf("failed to get cloud manifest: %w", err)
	}
	fmt.Printf("Cloud has %d items\n", len(manifest.Items))

	// Check what's already local
	fmt.Println("Checking local storage...")
	pulled := 0
	skipped := 0
	errors := 0

	for i, item := range manifest.Items {
		if (i+1)%100 == 0 || i+1 == len(manifest.Items) {
			fmt.Printf("\rProcessing: %d/%d (pulled: %d, skipped: %d, errors: %d)", i+1, len(manifest.Items), pulled, skipped, errors)
		}

		// Check if already exists locally
		exists, _ := localStorage.Exists("observation", item.ID)
		if exists {
			skipped++
			continue
		}

		// Pull encrypted data from cloud
		encryptedData, err := pullFromCloud(apiBase, token, item.ID)
		if err != nil {
			errors++
			continue
		}

		// Decrypt observation
		obs, err := encMgr.DecryptObservation(encryptedData)
		if err != nil {
			errors++
			continue
		}

		// Save locally
		if err := localStorage.SaveObservation(obs); err != nil {
			errors++
			continue
		}

		// Export to claude-mem with re-embedding if needed
		ctx := context.Background()
		if err := exportToClaudeMemWithEmbedding(ctx, obs); err != nil {
			// Log error but don't count as failure - observation is still saved locally
			log.Printf("[sync] Failed to export to claude-mem: %v", err)
		}

		pulled++
	}

	fmt.Println() // New line after progress
	fmt.Println()
	fmt.Println("Pull complete:")
	fmt.Printf("  Pulled: %d\n", pulled)
	fmt.Printf("  Skipped (already local): %d\n", skipped)
	if errors > 0 {
		fmt.Printf("  Errors: %d\n", errors)
	}

	return nil
}

func runSyncStatus(cmd *cobra.Command, args []string) error {
	token, err := getAuthToken()
	if err != nil {
		return err
	}

	apiBase := getAPIBase()

	fmt.Println("Fetching sync status...")

	status, err := withTokenRefresh(apiBase, &token, func(t string) (*syncStatus, error) {
		return fetchSyncStatus(apiBase, t)
	})
	if err != nil {
		return fmt.Errorf("failed to fetch status: %w", err)
	}

	fmt.Println()
	fmt.Println("Cloud sync status:")
	fmt.Printf("  Items: %d\n", status.ItemCount)
	fmt.Printf("  Storage: %s / %s\n", formatBytes(status.StorageUsedBytes), formatBytes(status.StorageLimitBytes))
	fmt.Printf("  Devices: %d\n", status.DeviceCount)
	if status.LastSync != nil {
		fmt.Printf("  Last sync: %s\n", *status.LastSync)
	} else {
		fmt.Println("  Last sync: never")
	}

	return nil
}

type syncStatus struct {
	LastSync          *string `json:"lastSync"`
	ItemCount         int     `json:"itemCount"`
	StorageUsedBytes  int64   `json:"storageUsedBytes"`
	StorageLimitBytes int64   `json:"storageLimitBytes"`
	DeviceCount       int     `json:"deviceCount"`
}

func fetchSyncStatus(apiBase, token string) (*syncStatus, error) {
	req, err := http.NewRequest("GET", apiBase+"/sync/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var status syncStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}

// withTokenRefresh wraps an API call with automatic token refresh on 401.
// Returns the (possibly refreshed) token and the result of the last call.
func withTokenRefresh[T any](apiBase string, token *string, fn func(string) (T, error)) (T, error) {
	result, err := fn(*token)
	if err != nil && isUnauthorizedError(err) {
		fmt.Println("Token expired, refreshing...")
		newToken, refreshErr := refreshAccessToken(apiBase)
		if refreshErr != nil {
			var zero T
			return zero, fmt.Errorf("token expired and refresh failed: %w\nRun 'sinesync login' to re-authenticate", refreshErr)
		}
		*token = newToken
		time.Sleep(2 * time.Second) // brief pause to avoid rate limiting
		return fn(newToken)
	}
	return result, err
}

// Cloud API helpers

type manifestItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Checksum  string `json:"checksum"`
	SizeBytes int64  `json:"sizeBytes"`
	UpdatedAt string `json:"updatedAt"`
}

type manifestResponse struct {
	Items          []manifestItem `json:"items"`
	Cursor         string         `json:"cursor,omitempty"`
	TotalCount     int            `json:"totalCount"`
	TotalSizeBytes int64          `json:"totalSizeBytes"`
}

func getCloudManifest(apiBase, token string) (*manifestResponse, error) {
	var allItems []manifestItem
	cursor := ""
	totalCount := 0
	totalSizeBytes := int64(0)

	for {
		u := apiBase + "/sync/manifest?limit=100"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}

		var resp *http.Response
		var err error
		client := &http.Client{Timeout: 30 * time.Second}

		// Retry with exponential backoff
		for retry := 0; retry < 5; retry++ {
			req, reqErr := http.NewRequest("GET", u, nil)
			if reqErr != nil {
				return nil, reqErr
			}
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err = client.Do(req)
			if err != nil {
				return nil, err
			}

			if resp.StatusCode == 429 {
				resp.Body.Close()
				backoff := time.Duration(1<<retry) * time.Second
				time.Sleep(backoff)
				continue
			}
			break
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
		totalSizeBytes = page.TotalSizeBytes

		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}

	return &manifestResponse{
		Items:          allItems,
		TotalCount:     totalCount,
		TotalSizeBytes: totalSizeBytes,
	}, nil
}

type uploadURLResponse struct {
	ID        string `json:"id"`
	UploadURL string `json:"uploadUrl"`
	ExpiresAt string `json:"expiresAt"`
}

type confirmResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type pendingItem struct {
	obs      storage.Observation
	data     []byte
	checksum string
	vaultID  string
}

func getUploadUrlsBatch(apiBase, token string, items []pendingItem) ([]uploadURLResponse, error) {
	reqItems := make([]map[string]interface{}, len(items))
	for i, item := range items {
		reqItem := map[string]interface{}{
			"id":        item.obs.ID,
			"vaultId":   item.vaultID,
			"type":      "memory",
			"sizeBytes": len(item.data),
			"checksum":  item.checksum,
		}
		reqItems[i] = reqItem
	}

	body := map[string]interface{}{"items": reqItems}
	bodyBytes, _ := json.Marshal(body)
	client := &http.Client{Timeout: 60 * time.Second}

	var resp *http.Response
	var err error

	// Retry with exponential backoff
	for retry := 0; retry < 5; retry++ {
		req, reqErr := http.NewRequest("POST", apiBase+"/sync/upload-urls", bytes.NewReader(bodyBytes))
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			backoff := time.Duration(1<<retry) * time.Second
			time.Sleep(backoff)
			continue
		}
		break
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get upload URLs failed %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Items []uploadURLResponse `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Items, nil
}

// getUploadUrlsBatchEncrypted is identical to getUploadUrlsBatch - the pendingItem already contains encrypted data
func getUploadUrlsBatchEncrypted(apiBase, token string, items []pendingItem) ([]uploadURLResponse, error) {
	return getUploadUrlsBatch(apiBase, token, items)
}

func uploadToGCS(uploadURL string, data []byte) error {
	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GCS upload returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func confirmUploadsBatch(apiBase, token string, items []map[string]interface{}) ([]confirmResult, error) {
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)
	client := &http.Client{Timeout: 60 * time.Second}

	var resp *http.Response
	var err error

	// Retry with exponential backoff
	for retry := 0; retry < 5; retry++ {
		req, reqErr := http.NewRequest("POST", apiBase+"/sync/confirm-uploads", bytes.NewReader(bodyBytes))
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			backoff := time.Duration(1<<retry) * time.Second
			time.Sleep(backoff)
			continue
		}
		break
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("confirm uploads failed %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Items []confirmResult `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Items, nil
}

func pushToCloud(apiBase, token, id, itemType, vaultID string, data []byte) error {
	checksum := storage.Checksum(data)[:16]

	// Step 1: Request presigned upload URL
	uploadReq := map[string]interface{}{
		"id":        id,
		"vaultId":   vaultID,
		"type":      itemType,
		"sizeBytes": len(data),
		"checksum":  checksum,
	}
	uploadReqBytes, _ := json.Marshal(uploadReq)

	req, err := http.NewRequest("POST", apiBase+"/sync/upload-url", bytes.NewReader(uploadReqBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("get upload URL failed %d: %s", resp.StatusCode, string(respBody))
	}

	var uploadResp struct {
		ID        string `json:"id"`
		UploadURL string `json:"uploadUrl"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return fmt.Errorf("decode upload URL response: %w", err)
	}

	// Step 2: Upload directly to Cloud Storage
	uploadReq2, err := http.NewRequest("PUT", uploadResp.UploadURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	uploadReq2.Header.Set("Content-Type", "application/octet-stream")

	resp2, err := client.Do(uploadReq2)
	if err != nil {
		return fmt.Errorf("direct upload failed: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp2.Body)
		return fmt.Errorf("cloud storage upload returned %d: %s", resp2.StatusCode, string(respBody))
	}

	// Step 3: Confirm upload with API
	confirmReq := map[string]interface{}{
		"id":        uploadResp.ID,
		"vaultId":   vaultID,
		"type":      itemType,
		"sizeBytes": len(data),
		"checksum":  checksum,
	}
	confirmReqBytes, _ := json.Marshal(confirmReq)

	req3, err := http.NewRequest("POST", apiBase+"/sync/confirm-upload", bytes.NewReader(confirmReqBytes))
	if err != nil {
		return err
	}
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+token)

	resp3, err := client.Do(req3)
	if err != nil {
		return fmt.Errorf("confirm upload failed: %w", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp3.Body)
		return fmt.Errorf("confirm upload returned %d: %s", resp3.StatusCode, string(respBody))
	}

	return nil
}

func pullFromCloud(apiBase, token, id string) ([]byte, error) {
	// Step 1: Request presigned download URL
	u := apiBase + "/sync/download-url/" + url.PathEscape(id)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get download URL failed %d: %s", resp.StatusCode, string(body))
	}

	var downloadResp struct {
		ID          string `json:"id"`
		DownloadURL string `json:"downloadUrl"`
		ExpiresAt   string `json:"expiresAt"`
		SizeBytes   int64  `json:"sizeBytes"`
		Checksum    string `json:"checksum"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&downloadResp); err != nil {
		return nil, fmt.Errorf("decode download URL response: %w", err)
	}

	// Step 2: Download directly from Cloud Storage
	req2, err := http.NewRequest("GET", downloadResp.DownloadURL, nil)
	if err != nil {
		return nil, err
	}

	resp2, err := client.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("direct download failed: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		return nil, fmt.Errorf("cloud storage download returned %d: %s", resp2.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp2.Body)
	if err != nil {
		return nil, fmt.Errorf("read download body: %w", err)
	}

	// Verify checksum
	actualChecksum := storage.Checksum(data)[:16]
	if actualChecksum != downloadResp.Checksum {
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", downloadResp.Checksum, actualChecksum)
	}

	return data, nil
}

// getVaultIDForObservation returns the vault ID for an observation based on its project
// Falls back to defaultVaultID if project is not assigned to a vault
func getVaultIDForObservation(project string, defaultVaultID string) string {
	if project == "" {
		return defaultVaultID
	}

	vaultID, err := GetVaultForProject(project)
	if err != nil || vaultID == "" {
		return defaultVaultID
	}
	return vaultID
}

// exportToClaudeMemWithEmbedding exports an observation to claude-mem, re-embedding if needed
// Returns error if export fails, nil on success or if claude-mem is not installed
func exportToClaudeMemWithEmbedding(ctx context.Context, obs *storage.Observation) error {
	if !adapters.IsClaudeMemInstalled() {
		return nil
	}

	adapter, err := adapters.NewClaudeMemAdapter(false)
	if err != nil || adapter == nil {
		return err
	}
	defer adapter.Close()

	// Get adapter's embedding config (ClaudeMemAdapter implements EmbeddingAwareAdapter)
	adapterConfig := adapter.GetEmbeddingConfig()
	if adapterConfig == nil {
		// No embedding config, use regular export
		return adapter.Export(ctx, obs)
	}

	// Check if observation's embedding is compatible
	if obs.Embedding.IsCompatibleWith(adapterConfig.Model, adapterConfig.Tokenizer, adapterConfig.Dims) {
		// Embedding is compatible, export with embedding
		return adapter.ExportWithEmbedding(ctx, obs)
	}

	// Embedding is incompatible or missing - need to re-embed
	embedder, err := embeddings.GetProvider()
	if err != nil {
		log.Printf("[sync] Embedding provider unavailable, using regular export: %v", err)
		return adapter.Export(ctx, obs)
	}
	// Don't close singleton provider

	// Generate text for embedding
	text := obs.Core.Title
	if obs.Core.Content != "" {
		text += "\n" + obs.Core.Content
	}

	// Generate new embedding
	vector, err := embedder.Embed(text)
	if err != nil {
		log.Printf("[sync] Failed to generate embedding, using regular export: %v", err)
		return adapter.Export(ctx, obs)
	}

	// Update observation with new embedding metadata
	obs.Embedding.Vector = vector
	obs.Embedding.Model = embeddings.ModelName
	obs.Embedding.Tokenizer = embedder.TokenizerType()
	obs.Embedding.Dims = embeddings.Dimensions

	// Now export with embedding
	return adapter.ExportWithEmbedding(ctx, obs)
}
