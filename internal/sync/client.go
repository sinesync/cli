package sync

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/crypto"
	"github.com/miclip/sinesync/internal/httputil"
	"github.com/miclip/sinesync/internal/storage"
)

const (
	DefaultAPIBase = "https://api.sinesync.ai/v1"
	AAD            = "sinesync-observation-v1"
)

// ManifestItem represents an item in the sync manifest
type ManifestItem struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Checksum  string `json:"checksum"`
	Size      int    `json:"size"`
	Project   string `json:"project,omitempty"`
}

// SyncResult contains the result of a sync operation
type SyncResult struct {
	Pushed  int      `json:"pushed"`
	Pulled  int      `json:"pulled"`
	Skipped int      `json:"skipped"`
	Errors  []string `json:"errors"`
}

// Client handles sync with the cloud backend
type Client struct {
	apiBase       string
	encryptionKey []byte
	deviceID      string
	authToken     string
	httpClient    *http.Client
	config        *config.Config
}

// NewClient creates a new sync client
func NewClient(encryptionKey []byte, deviceID string) *Client {
	apiBase := os.Getenv("SINESYNC_API_URL")
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}

	cfg, _ := config.Load()

	return &Client{
		apiBase:       apiBase,
		encryptionKey: encryptionKey,
		deviceID:      deviceID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		config: cfg,
	}
}

// SetAuthToken sets the authentication token
func (c *Client) SetAuthToken(token string) {
	c.authToken = token
}

// prepareForUpload compresses and encrypts an observation
func (c *Client) prepareForUpload(obs *storage.Observation) ([]byte, string, error) {
	// Serialize to JSON
	jsonData, err := json.Marshal(obs)
	if err != nil {
		return nil, "", err
	}

	// Compress
	var compressed bytes.Buffer
	gzWriter := gzip.NewWriter(&compressed)
	if _, err := gzWriter.Write(jsonData); err != nil {
		return nil, "", err
	}
	if err := gzWriter.Close(); err != nil {
		return nil, "", err
	}

	// Encrypt
	encrypted, err := crypto.Encrypt(compressed.Bytes(), c.encryptionKey, AAD)
	if err != nil {
		return nil, "", err
	}

	// Compute checksum of encrypted data (matches CLI/daemon convention)
	hash := sha256.Sum256(encrypted)
	checksum := hex.EncodeToString(hash[:8])

	return encrypted, checksum, nil
}

// processDownload decrypts and decompresses an observation
func (c *Client) processDownload(encrypted []byte) (*storage.Observation, error) {
	// Decrypt
	compressed, err := crypto.Decrypt(encrypted, c.encryptionKey, AAD)
	if err != nil {
		return nil, err
	}

	// Decompress
	gzReader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	jsonData, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, err
	}

	// Parse
	var obs storage.Observation
	if err := json.Unmarshal(jsonData, &obs); err != nil {
		return nil, err
	}

	return &obs, nil
}

// GetManifest retrieves the server manifest
func (c *Client) GetManifest() ([]ManifestItem, error) {
	req, err := http.NewRequest("GET", c.apiBase+"/sync/manifest", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("X-Device-ID", c.deviceID)
	httputil.SetClientHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := httputil.CheckUpdateRequired(resp); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var result struct {
		Items []ManifestItem `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Items, nil
}

// Push uploads an observation to the server
func (c *Client) Push(obs *storage.Observation) error {
	// Check project filter
	if c.config != nil && !c.config.ShouldSyncProject(obs.Core.Project) {
		return nil // Skip excluded project
	}

	encrypted, checksum, err := c.prepareForUpload(obs)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.apiBase+"/sync/push", bytes.NewReader(encrypted))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Device-ID", c.deviceID)
	httputil.SetClientHeaders(req)
	req.Header.Set("X-Item-ID", obs.ID)
	req.Header.Set("X-Timestamp", obs.Core.UpdatedAt.Format(time.RFC3339))
	req.Header.Set("X-Checksum", checksum)
	req.Header.Set("X-Size", fmt.Sprintf("%d", len(encrypted)))
	if obs.Core.Project != "" {
		req.Header.Set("X-Project", obs.Core.Project)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := httputil.CheckUpdateRequired(resp); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	return nil
}

// Pull downloads an observation from the server
func (c *Client) Pull(id string) (*storage.Observation, error) {
	req, err := http.NewRequest("GET", c.apiBase+"/sync/pull/"+id, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("X-Device-ID", c.deviceID)
	httputil.SetClientHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := httputil.CheckUpdateRequired(resp); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	encrypted, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return c.processDownload(encrypted)
}

// Sync performs a full sync operation
func (c *Client) Sync(localStorage *storage.LocalStorage) (*SyncResult, error) {
	result := &SyncResult{}

	// Get server manifest
	serverManifest, err := c.GetManifest()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to get manifest: %v", err))
		return result, nil
	}

	serverIDs := make(map[string]ManifestItem)
	for _, item := range serverManifest {
		serverIDs[item.ID] = item
	}

	// Get local observations
	localObs, err := localStorage.ListObservations()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to list local: %v", err))
		return result, nil
	}

	localIDs := make(map[string]storage.Observation)
	for _, obs := range localObs {
		localIDs[obs.ID] = obs
	}

	// Push local items server doesn't have
	for _, obs := range localObs {
		if _, exists := serverIDs[obs.ID]; !exists {
			if err := c.Push(&obs); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Push %s: %v", obs.ID, err))
			} else {
				result.Pushed++
			}
		}
	}

	// Pull items we don't have
	for _, item := range serverManifest {
		if _, exists := localIDs[item.ID]; !exists {
			// Check project filter
			if c.config != nil && item.Project != "" && !c.config.ShouldSyncProject(item.Project) {
				result.Skipped++
				continue
			}

			obs, err := c.Pull(item.ID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Pull %s: %v", item.ID, err))
				continue
			}

			// Double-check project filter after decryption
			if c.config != nil && !c.config.ShouldSyncProject(obs.Core.Project) {
				result.Skipped++
				continue
			}

			if err := localStorage.SaveObservation(obs); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Save %s: %v", item.ID, err))
			} else {
				result.Pulled++
			}
		}
	}

	return result, nil
}

// GetStatus retrieves sync status from the server
func (c *Client) GetStatus() (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", c.apiBase+"/sync/status", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("X-Device-ID", c.deviceID)
	httputil.SetClientHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := httputil.CheckUpdateRequired(resp); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
