package backends

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/miclip/sinesync/internal/config"
)

const (
	DefaultSinesyncAPI = "https://api.sinesync.ai/api/v1"
)

// SinesyncProvider stores data in the managed sinesync cloud service
type SinesyncProvider struct {
	apiBase    string
	authToken  string
	vaultID    string
	httpClient *http.Client
}

func (p *SinesyncProvider) Name() string {
	return "sinesync"
}

func (p *SinesyncProvider) Init(ctx context.Context, cfg *config.Backend) error {
	p.apiBase = os.Getenv("SINESYNC_API_URL")
	if p.apiBase == "" {
		p.apiBase = DefaultSinesyncAPI
	}

	p.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	// Auth token would be loaded from keychain in real implementation
	p.authToken = os.Getenv("SINESYNC_AUTH_TOKEN")

	return nil
}

func (p *SinesyncProvider) SetAuthToken(token string) {
	p.authToken = token
}

func (p *SinesyncProvider) SetVaultID(vaultID string) {
	p.vaultID = vaultID
}

func (p *SinesyncProvider) Push(ctx context.Context, id string, data []byte, meta Metadata) error {
	url := fmt.Sprintf("%s/vaults/%s/items/%s", p.apiBase, p.vaultID, id)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.authToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Checksum", meta.Checksum)
	req.Header.Set("X-Project", meta.Project)
	req.Header.Set("X-Device-ID", meta.DeviceID)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *SinesyncProvider) Pull(ctx context.Context, id string) ([]byte, error) {
	url := fmt.Sprintf("%s/vaults/%s/items/%s", p.apiBase, p.vaultID, id)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.authToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("item not found: %s", id)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (p *SinesyncProvider) Delete(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/vaults/%s/items/%s", p.apiBase, p.vaultID, id)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.authToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (p *SinesyncProvider) GetManifest(ctx context.Context) ([]ManifestItem, error) {
	url := fmt.Sprintf("%s/vaults/%s/manifest", p.apiBase, p.vaultID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.authToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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

func (p *SinesyncProvider) GetMetadata(ctx context.Context, id string) (*Metadata, error) {
	url := fmt.Sprintf("%s/vaults/%s/items/%s/meta", p.apiBase, p.vaultID, id)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.authToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var meta Metadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func (p *SinesyncProvider) Close() error {
	return nil
}
