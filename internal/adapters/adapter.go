package adapters

import (
	"context"

	"github.com/miclip/sinesync/internal/storage"
)

// Adapter defines the interface for memory tool integrations
// Each adapter translates between its native format and sinesync's canonical format
type Adapter interface {
	// Name returns the adapter identifier (e.g., "claude-mem", "mem0")
	Name() string

	// IsAvailable checks if the adapter's backing store is accessible
	IsAvailable() bool

	// Import reads observations from the adapter since the given epoch
	// Returns observations in sinesync canonical format
	// Adapter-specific data should be preserved in Extensions[adapter.Name()]
	Import(ctx context.Context, sinceEpoch int64) ([]storage.Observation, error)

	// Export writes an observation to the adapter's backing store
	// Should use Extensions[adapter.Name()] if present for lossless round-trip
	// Otherwise, maps from Core/Structured fields
	Export(ctx context.Context, obs *storage.Observation) error

	// Exists checks if an observation already exists (for deduplication)
	// Typically checks by project + title or source ID
	Exists(ctx context.Context, obs *storage.Observation) (bool, error)

	// GetProjects returns available projects with counts
	GetProjects(ctx context.Context) ([]ProjectInfo, error)

	// Close releases any resources
	Close() error
}

// ProjectInfo holds project statistics
type ProjectInfo struct {
	Name         string `json:"name"`
	Count        int    `json:"count"`
	LastActivity string `json:"lastActivity,omitempty"`
}

// Registry holds available adapters
type Registry struct {
	adapters map[string]Adapter
}

// NewRegistry creates a new adapter registry
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[string]Adapter),
	}
}

// Register adds an adapter to the registry
func (r *Registry) Register(adapter Adapter) {
	r.adapters[adapter.Name()] = adapter
}

// Get retrieves an adapter by name
func (r *Registry) Get(name string) (Adapter, bool) {
	a, ok := r.adapters[name]
	return a, ok
}

// Available returns all available adapters
func (r *Registry) Available() []Adapter {
	var result []Adapter
	for _, a := range r.adapters {
		if a.IsAvailable() {
			result = append(result, a)
		}
	}
	return result
}

// Close closes all adapters
func (r *Registry) Close() error {
	for _, a := range r.adapters {
		a.Close()
	}
	return nil
}

// DefaultRegistry creates a registry with all known adapters
func DefaultRegistry() *Registry {
	r := NewRegistry()

	// Register claude-mem if available
	if IsClaudeMemInstalled() {
		if adapter, err := NewClaudeMemAdapter(false); err == nil && adapter != nil {
			r.Register(adapter)
		}
	}

	// Future: register other adapters (mem0, etc.)

	return r
}
