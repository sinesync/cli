package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/daemon"
	"github.com/miclip/sinesync/internal/embeddings"
	"github.com/miclip/sinesync/internal/storage"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "sinesync",
	SilenceUsage: true,
	Short:        "End-to-end encrypted cross-device sync for AI memories",
	Long: `sine~sync securely syncs your AI conversation memories across devices.

Features:
  - End-to-end encryption (zero-knowledge)
  - Local embeddings with all-MiniLM-L6-v2
  - Claude-mem integration
  - Project-based filtering`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(reembedCmd)
	rootCmd.AddCommand(dashboardCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(debugEmbedCmd)
	rootCmd.AddCommand(doctorCmd)
}

// Reembed command - regenerate embeddings with ONNX
var reembedCmd = &cobra.Command{
	Use:   "reembed",
	Short: "Regenerate embeddings using ONNX model",
	Long: `Regenerate embeddings for all observations using the ONNX model.

Use this after:
  - First installing the ONNX model
  - Importing observations that used fallback embeddings
  - Upgrading to a new embedding model`,
	RunE: runReembed,
}

func runReembed(cmd *cobra.Command, args []string) error {
	backend, err := storage.ResolveBackend()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer backend.Close()

	// Initialize embedder
	embedder, err := embeddings.NewProvider()
	if err != nil {
		return fmt.Errorf("failed to create embedder: %w", err)
	}
	defer embedder.Close()

	if !embedder.IsReady() {
		return fmt.Errorf("ONNX model not available - cannot reembed")
	}

	fmt.Printf("Using %s", embeddings.ModelName)
	if embedder.Accelerator() != embeddings.AcceleratorCPU {
		fmt.Printf(" (%s)", embedder.Accelerator())
	}
	fmt.Println()

	// Get all observations
	observations, err := backend.ListObservations()
	if err != nil {
		return fmt.Errorf("failed to list observations: %w", err)
	}

	fmt.Printf("Reembedding %d observations...\n", len(observations))

	updated := 0
	for i, obs := range observations {
		// Generate new embedding using the helper method
		textForEmbedding := obs.TextForEmbedding()
		embedding, err := embedder.Embed(textForEmbedding)
		if err != nil {
			continue
		}

		// Update observation with new embedding and metadata
		obs.Embedding.Vector = embedding
		obs.Embedding.Model = embeddings.ModelName
		obs.Embedding.Tokenizer = embedder.TokenizerType()
		obs.Embedding.Dims = embeddings.Dimensions
		obs.Core.UpdatedAt = time.Now()

		if err := backend.SaveObservation(&obs); err != nil {
			continue
		}
		updated++

		// Progress
		if (i+1)%100 == 0 || i+1 == len(observations) {
			fmt.Printf("\r  %d/%d", i+1, len(observations))
		}
	}

	fmt.Printf("\n✓ Updated %d observations with ONNX embeddings\n", updated)
	return nil
}

// Debug embed command
var debugEmbedCmd = &cobra.Command{
	Use:    "debug-embed [text]",
	Short:  "Test embedding generation",
	Hidden: true,
	Args:   cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		text := strings.Join(args, " ")

		// Enable verbose ONNX debugging
		embeddings.Verbose = true

		embedder, err := embeddings.NewProvider()
		if err != nil {
			return fmt.Errorf("provider error: %w", err)
		}
		defer embedder.Close()

		fmt.Printf("Provider ready: %v\n", embedder.IsReady())
		fmt.Printf("Accelerator: %v\n", embedder.Accelerator())
		fmt.Printf("Model path: %s\n", embedder.ModelPath())

		emb, err := embedder.Embed(text)
		if err != nil {
			return fmt.Errorf("embed error: %w", err)
		}

		// Count zeros (fallback has many, ONNX has few)
		zeros := 0
		for _, v := range emb {
			if v == 0 {
				zeros++
			}
		}

		fmt.Printf("\nText: %q\n", text)
		fmt.Printf("Dimensions: %d\n", len(emb))
		fmt.Printf("Zeros: %d (%.1f%%)\n", zeros, float64(zeros)/float64(len(emb))*100)
		fmt.Printf("First 10 values: %v\n", emb[:10])

		if zeros > 100 {
			fmt.Println("\n⚠️  High zero count indicates FALLBACK embeddings (hash-based)")
		} else {
			fmt.Println("\n✓ Low zero count indicates REAL ONNX embeddings")
		}

		return nil
	},
}

// Setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure sine~sync with Claude Code",
	RunE:  runSetup,
}

// Status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sync status",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("sine~sync status")
	fmt.Println("─────────────────────────────────────────")

	cfg, _ := config.Load()

	// Mode from config, fall back to auto-detect
	mode := cfg.Mode
	if mode == "" {
		if adapters.IsClaudeMemInstalled() {
			mode = "adapter"
		} else {
			mode = "standalone"
		}
	}

	if mode == "adapter" {
		fmt.Println("\nMode: adapter")
		fmt.Println("  • Memory tools: adapter")
		fmt.Println("  • Sync tools: sinesync")
	} else {
		fmt.Println("\nMode: standalone")
		fmt.Println("  • Memory + sync tools: sinesync")
	}

	// Adapter status
	if mode == "adapter" && adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			defer adapter.Close()
			ctx := context.Background()
			count, _ := adapter.GetObservationCount()
			projects, _ := adapter.GetProjects(ctx)
			fmt.Printf("\nClaude-mem:\n")
			fmt.Printf("  • Observations: %d\n", count)
			fmt.Printf("  • Projects: %d\n", len(projects))

			// Adapter sync stats
			if syncStats, err := adapter.GetSyncStats(); err == nil {
				fmt.Printf("\nAdapter sync:\n")
				fmt.Printf("  • Native (claude-mem): %d\n", syncStats.NativeInClaudeMem)
				fmt.Printf("  • Synced (from sinesync): %d\n", syncStats.ExportedToClaudeMem)
				if syncStats.ChromaAvailable {
					// Calculate embedding gap using unique observation count
					embeddingGap := count - syncStats.ChromaUniqueObservations
					if embeddingGap > 0 {
						fmt.Printf("  • ChromaDB embeddings: %d docs, %d observations (backlog: %d)\n",
							syncStats.ChromaEmbeddings, syncStats.ChromaUniqueObservations, embeddingGap)
					} else {
						fmt.Printf("  • ChromaDB embeddings: %d docs, %d observations\n",
							syncStats.ChromaEmbeddings, syncStats.ChromaUniqueObservations)
					}
				}
			}
		}
	}

	// Local storage — query daemon for memory.db stats in standalone mode
	if mode == "standalone" {
		gotStats := false
		info, err := daemon.EnsureRunning()
		if err == nil {
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/stats", info.Port))
			if err == nil {
				defer resp.Body.Close()
				var stats struct {
					TotalObservations int   `json:"totalObservations"`
					StorageBytes      int64 `json:"storageBytes"`
				}
				if json.NewDecoder(resp.Body).Decode(&stats) == nil {
					fmt.Printf("\nLocal storage:\n")
					fmt.Printf("  • Observations: %d\n", stats.TotalObservations)
					fmt.Printf("  • Storage: %s\n", formatBytes(stats.StorageBytes))
					gotStats = true
				}
			}
		}
		if !gotStats {
			fmt.Printf("\nLocal storage:\n")
			fmt.Printf("  • Daemon unavailable — run 'sinesync daemon start'\n")
		}
	} else {
		backend, err := storage.ResolveBackend()
		if err == nil {
			defer backend.Close()
			itemCount, storageBytes, _ := backend.GetStatus()
			fmt.Printf("\nLocal storage:\n")
			fmt.Printf("  • Observations: %d\n", itemCount)
			fmt.Printf("  • Storage: %s\n", formatBytes(storageBytes))
		} else {
			fmt.Printf("\nLocal storage:\n")
			fmt.Printf("  • Storage unavailable: %v\n", err)
		}
	}

	// Embeddings
	embedder, _ := embeddings.NewProvider()
	if embedder != nil && embedder.IsReady() {
		accel := embedder.Accelerator()
		if accel != embeddings.AcceleratorCPU {
			fmt.Printf("\nEmbeddings: %s (ONNX + %s)\n", embeddings.ModelName, accel)
		} else {
			fmt.Printf("\nEmbeddings: %s (ONNX)\n", embeddings.ModelName)
		}
		fmt.Printf("  • Model: %s\n", embedder.ModelPath())
	} else {
		fmt.Println("\nEmbeddings: fallback (hash-based)")
		fmt.Println("  • Download ONNX model for semantic search")
	}

	// Project filters
	if cfg.Sync != nil && len(cfg.Sync.ExcludeProjects) > 0 {
		fmt.Printf("\nFilters:\n")
		fmt.Printf("  • Excluded: %v\n", cfg.Sync.ExcludeProjects)
	}

	// Cloud sync
	authCfg, authErr := loadAuthConfig()
	if authErr == nil && authCfg != nil && authCfg.Token != "" {
		fmt.Println("\nCloud sync: enabled")
		fmt.Printf("  • User: %s\n", authCfg.Email)
		if authCfg.DeviceID != "" {
			fmt.Printf("  • Device ID: %s\n", authCfg.DeviceID)
		}
	} else {
		fmt.Println("\nCloud sync: not configured")
		fmt.Println("  • Run `sinesync login` to enable cloud sync")
	}

	fmt.Println()
	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Import command (claude-mem → sinesync)
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import observations from claude-mem into sinesync",
	Long: `Import observations from claude-mem database into sinesync local storage.

This command:
  - Reads observations from claude-mem SQLite database
  - Generates embeddings using ONNX model (or fallback)
  - Stores in sinesync local storage with deduplication
  - Respects project filters (exclude/include-only)

Can be called manually or via Claude Code SessionEnd hook.`,
	RunE: runImport,
}

func runImport(cmd *cobra.Command, args []string) error {
	// Import observations from claude-mem into sinesync local storage

	cfg, _ := config.Load()
	ctx := context.Background()

	// Only run if claude-mem mode
	if !adapters.IsClaudeMemInstalled() {
		return nil
	}

	adapter, err := adapters.NewClaudeMemAdapter(true)
	if err != nil || adapter == nil {
		return fmt.Errorf("failed to connect to claude-mem: %w", err)
	}
	defer adapter.Close()

	// Initialize local storage
	backend, err := storage.ResolveBackend()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer backend.Close()

	// Initialize embedder (silently)
	embedder, _ := embeddings.NewProvider()

	// Import all observations from adapter (returns canonical format)
	observations, err := adapter.Import(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to import observations: %w", err)
	}

	imported := 0
	skipped := 0
	filtered := 0

	for _, obs := range observations {
		// Check project filter
		if cfg != nil && cfg.Sync != nil && !cfg.ShouldSyncProject(obs.Core.Project) {
			filtered++
			continue
		}

		// Check if already imported (by source adapter + machine + ID)
		exists, _ := backend.ExistsBySource(obs.Source.Adapter, obs.Source.Machine, obs.Source.ID)
		if exists {
			skipped++
			continue
		}

		// Generate embedding with metadata
		textForEmbedding := obs.TextForEmbedding()
		if embedder != nil && embedder.IsReady() {
			embedding, err := embedder.Embed(textForEmbedding)
			if err == nil {
				obs.Embedding.Vector = embedding
				obs.Embedding.Model = embeddings.ModelName
				obs.Embedding.Tokenizer = embedder.TokenizerType()
				obs.Embedding.Dims = embeddings.Dimensions
			} else {
				fmt.Fprintf(os.Stderr, "[reembed] WARNING: embedding failed for %s: %v\n", obs.ID, err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[reembed] WARNING: embedder not available, skipping %s\n", obs.ID)
		}

		// Save to local storage
		if err := backend.SaveObservation(&obs); err != nil {
			continue
		}
		imported++
	}

	// Concise summary - only print if something happened
	if imported > 0 {
		fmt.Printf("Imported %d observations from claude-mem\n", imported)
	} else if filtered > 0 {
		fmt.Printf("claude-mem: %d filtered by project rules\n", filtered)
	}
	// Silent if nothing to import (all skipped as already existing)

	return nil
}

// Export command (sinesync → claude-mem)
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export observations from sinesync into claude-mem",
	Long: `Export observations from sinesync local storage back into claude-mem.

This command:
  - Reads observations from sinesync local storage
  - Writes non-claude-mem-sourced observations to claude-mem SQLite
  - Deduplicates by project + title
  - Makes cloud-synced memories searchable in claude-mem

Use case: After cloud sync brings memories from other devices, export
them to claude-mem so they appear in claude-mem's semantic search.

Can be called manually or via Claude Code SessionStart hook.

Flags:
  --force   Export all observations, including those originally from claude-mem`,
	RunE: runExport,
}

var exportForce bool

func init() {
	exportCmd.Flags().BoolVar(&exportForce, "force", false, "Export all observations, including those originally from claude-mem")
}

func runExport(cmd *cobra.Command, args []string) error {
	// Export observations from sinesync into claude-mem database
	// This makes cloud-synced memories available in claude-mem's search

	ctx := context.Background()

	if !adapters.IsClaudeMemInstalled() {
		return nil // Nothing to do if claude-mem isn't present
	}

	// Open claude-mem in write mode
	adapter, err := adapters.NewClaudeMemAdapter(false) // readonly=false
	if err != nil || adapter == nil {
		return fmt.Errorf("failed to connect to claude-mem: %w", err)
	}
	defer adapter.Close()

	// Get local observations
	backend, err := storage.ResolveBackend()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer backend.Close()
	observations, err := backend.ListObservations()
	if err != nil {
		return fmt.Errorf("failed to list local observations: %w", err)
	}

	written := 0
	skipped := 0

	for _, obs := range observations {
		// Only sync observations NOT from claude-mem (those are already there)
		// This syncs observations from: other devices, backend, manual imports
		// Unless --force is specified (e.g., after database reset)
		if !exportForce && obs.Source.Adapter == adapters.ClaudeMemAdapterName {
			continue
		}

		// Check if already exists in claude-mem using adapter's Exists method
		exists, _ := adapter.Exists(ctx, &obs)
		if exists {
			skipped++
			continue
		}

		// Export to claude-mem (adapter handles format conversion using Extensions)
		if err := adapter.Export(ctx, &obs); err != nil {
			continue
		}
		written++
	}

	_ = skipped // suppress unused variable warning

	if written > 0 {
		fmt.Fprintf(os.Stderr, "sine~sync: Wrote %d observations to claude-mem\n", written)
	}

	return nil
}
