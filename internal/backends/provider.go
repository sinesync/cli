package backends

import (
	"context"
	"fmt"
	"time"

	"github.com/sinesync/cli/internal/config"
)

// Metadata represents item metadata stored alongside encrypted content
type Metadata struct {
	ID        string    `json:"id"`
	VaultID   string    `json:"vaultId"`
	Checksum  string    `json:"checksum"`
	Size      int64     `json:"size"`
	Project   string    `json:"project,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	DeviceID  string    `json:"deviceId"`
}

// ManifestItem represents an item in the sync manifest
type ManifestItem struct {
	ID        string `json:"id"`
	Checksum  string `json:"checksum"`
	Size      int64  `json:"size"`
	Project   string `json:"project,omitempty"`
	UpdatedAt string `json:"updatedAt"`
	DeviceID  string `json:"deviceId,omitempty"`
}

// Provider is the interface all storage backends must implement
type Provider interface {
	// Name returns the provider name
	Name() string

	// Init initializes the provider with configuration
	Init(ctx context.Context, cfg *config.Backend) error

	// Push uploads encrypted data
	Push(ctx context.Context, id string, data []byte, meta Metadata) error

	// Pull downloads encrypted data
	Pull(ctx context.Context, id string) ([]byte, error)

	// Delete removes an item
	Delete(ctx context.Context, id string) error

	// GetManifest returns the list of all items
	GetManifest(ctx context.Context) ([]ManifestItem, error)

	// GetMetadata returns metadata for a single item
	GetMetadata(ctx context.Context, id string) (*Metadata, error)

	// Close cleans up resources
	Close() error
}

// Registry of available providers
var providers = make(map[string]func() Provider)

// Register registers a provider factory
func Register(name string, factory func() Provider) {
	providers[name] = factory
}

// New creates a provider by name
func New(name string) (Provider, error) {
	factory, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown backend provider: %s", name)
	}
	return factory(), nil
}

// NewFromConfig creates a provider from backend config
func NewFromConfig(ctx context.Context, cfg *config.Backend) (Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("backend config is nil")
	}

	provider, err := New(cfg.Type)
	if err != nil {
		return nil, err
	}

	if err := provider.Init(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to init backend: %w", err)
	}

	return provider, nil
}

// ListProviders returns names of available providers
func ListProviders() []string {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	return names
}

func init() {
	// Register built-in providers
	Register("local", func() Provider { return &LocalProvider{} })
	Register("s3", func() Provider { return &S3Provider{} })
	Register("sinesync", func() Provider { return &SinesyncProvider{} })
}
