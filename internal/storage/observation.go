package storage

import "time"

// Observation represents a memory in the sinesync-canonical format
// This structure is designed for cross-adapter compatibility while
// preserving adapter-specific data for lossless round-trips
type Observation struct {
	ID string `json:"id"`

	// Core fields - what sine~ app and AI context uses
	Core Core `json:"core"`

	// Structured data - common semantic fields
	Structured Structured `json:"structured,omitempty"`

	// User metadata - sinesync managed
	Meta Meta `json:"meta,omitempty"`

	// Embedding - sinesync generated
	Embedding EmbeddingData `json:"embedding,omitempty"`

	// Provenance - sync metadata
	Source Source `json:"source"`

	// Adapter-specific - for lossless round-trip
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// Core contains the essential fields for AI context and display
type Core struct {
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	Content   string    `json:"content,omitempty"` // Full narrative/details
	Type      string    `json:"type"`              // discovery, decision, bugfix, feature, refactor, change
	Project   string    `json:"project,omitempty"`
	SessionID string    `json:"sessionId,omitempty"` // Claude Code session ID
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Structured contains common semantic data many memory tools have
type Structured struct {
	Facts    []string `json:"facts,omitempty"`
	Concepts []string `json:"concepts,omitempty"`
	Files    Files    `json:"files,omitempty"`
	CodeRefs []string `json:"codeRefs,omitempty"` // file:line references
}

// Files tracks file interactions
type Files struct {
	Read     []string `json:"read,omitempty"`
	Modified []string `json:"modified,omitempty"`
}

// Meta contains user-managed metadata (syncs to cloud)
type Meta struct {
	Tags           []string `json:"tags,omitempty"`
	Classification string   `json:"classification,omitempty"` // public, team, private, sensitive
	Starred        bool     `json:"starred,omitempty"`
	Archived       bool     `json:"archived,omitempty"`
	Notes          string   `json:"notes,omitempty"`
	VaultID        string   `json:"vaultId,omitempty"`
}

// EmbeddingData contains the vector embedding with metadata
type EmbeddingData struct {
	Model     string    `json:"model,omitempty"`     // e.g., "all-MiniLM-L6-v2"
	Tokenizer string    `json:"tokenizer,omitempty"` // e.g., "wordpiece-hf" or "hash-simple"
	Dims      int       `json:"dims,omitempty"`      // e.g., 384
	Vector    []float32 `json:"vector,omitempty"`
}

// IsCompatibleWith checks if this embedding is compatible with target config
func (e *EmbeddingData) IsCompatibleWith(model, tokenizerType string, dims int) bool {
	// No metadata = old embedding, needs regeneration
	if e.Model == "" || e.Tokenizer == "" || e.Dims == 0 {
		return false
	}
	return e.Model == model && e.Tokenizer == tokenizerType && e.Dims == dims
}

// Source tracks where the observation came from
type Source struct {
	Adapter  string `json:"adapter"`            // claude-mem, mem0, sinesync, etc.
	ID       string `json:"id,omitempty"`       // Original ID in source system
	Machine  string `json:"machine,omitempty"`  // Machine hostname for cross-device dedup
	Epoch    int64  `json:"epoch,omitempty"`    // Creation timestamp for ordering
	Checksum string `json:"checksum,omitempty"` // For conflict detection
}

// Helper methods

// AllFiles returns combined read + modified files
func (s *Structured) AllFiles() []string {
	seen := make(map[string]bool)
	var result []string
	for _, f := range s.Files.Read {
		if !seen[f] {
			seen[f] = true
			result = append(result, f)
		}
	}
	for _, f := range s.Files.Modified {
		if !seen[f] {
			seen[f] = true
			result = append(result, f)
		}
	}
	return result
}

// TextForEmbedding returns the text to embed
func (o *Observation) TextForEmbedding() string {
	text := o.Core.Title
	if o.Core.Summary != "" {
		text += ". " + o.Core.Summary
	}
	return text
}

// HasTag checks if observation has a specific tag
func (o *Observation) HasTag(tag string) bool {
	for _, t := range o.Meta.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AddTag adds a tag if not already present
func (o *Observation) AddTag(tag string) {
	if !o.HasTag(tag) {
		o.Meta.Tags = append(o.Meta.Tags, tag)
	}
}

// SetExtension sets an adapter-specific extension
func (o *Observation) SetExtension(adapter string, data interface{}) {
	if o.Extensions == nil {
		o.Extensions = make(map[string]interface{})
	}
	o.Extensions[adapter] = data
}

// GetExtension gets an adapter-specific extension
func (o *Observation) GetExtension(adapter string) (interface{}, bool) {
	if o.Extensions == nil {
		return nil, false
	}
	data, ok := o.Extensions[adapter]
	return data, ok
}
