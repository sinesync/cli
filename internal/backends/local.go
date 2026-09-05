package backends

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sinesync/cli/internal/config"
)

// LocalProvider stores data on the local filesystem
// Useful for testing or self-hosted scenarios (e.g., NAS, shared drive)
type LocalProvider struct {
	basePath string
}

func (p *LocalProvider) Name() string {
	return "local"
}

func (p *LocalProvider) Init(ctx context.Context, cfg *config.Backend) error {
	if cfg.Path == "" {
		return fmt.Errorf("local backend requires 'path' configuration")
	}

	p.basePath = cfg.Path

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Join(p.basePath, "data"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(p.basePath, "meta"), 0755); err != nil {
		return err
	}

	return nil
}

func (p *LocalProvider) Push(ctx context.Context, id string, data []byte, meta Metadata) error {
	// Write encrypted data
	dataPath := filepath.Join(p.basePath, "data", id+".enc")
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Write metadata
	metaPath := filepath.Join(p.basePath, "meta", id+".json")
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	if err := os.WriteFile(metaPath, metaBytes, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	return nil
}

func (p *LocalProvider) Pull(ctx context.Context, id string) ([]byte, error) {
	dataPath := filepath.Join(p.basePath, "data", id+".enc")
	data, err := os.ReadFile(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("item not found: %s", id)
		}
		return nil, err
	}
	return data, nil
}

func (p *LocalProvider) Delete(ctx context.Context, id string) error {
	dataPath := filepath.Join(p.basePath, "data", id+".enc")
	metaPath := filepath.Join(p.basePath, "meta", id+".json")

	os.Remove(dataPath)
	os.Remove(metaPath)

	return nil
}

func (p *LocalProvider) GetManifest(ctx context.Context) ([]ManifestItem, error) {
	metaDir := filepath.Join(p.basePath, "meta")
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var items []ManifestItem
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		meta, err := p.readMetadata(entry.Name())
		if err != nil {
			continue
		}

		items = append(items, ManifestItem{
			ID:        meta.ID,
			Checksum:  meta.Checksum,
			Size:      meta.Size,
			Project:   meta.Project,
			UpdatedAt: meta.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			DeviceID:  meta.DeviceID,
		})
	}

	return items, nil
}

func (p *LocalProvider) GetMetadata(ctx context.Context, id string) (*Metadata, error) {
	return p.readMetadata(id + ".json")
}

func (p *LocalProvider) readMetadata(filename string) (*Metadata, error) {
	metaPath := filepath.Join(p.basePath, "meta", filename)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func (p *LocalProvider) Close() error {
	return nil
}
