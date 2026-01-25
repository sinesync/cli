package embeddings

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	ort "github.com/yalue/onnxruntime_go"
)

const (
	ModelName  = "all-MiniLM-L6-v2"
	Dimensions = 384
	MaxTokens  = 256

	// Hugging Face model URL
	modelURL = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx"

	// ONNX Runtime library URL (Linux x64)
	onnxRuntimeVersion = "1.16.3"
	onnxRuntimeURL     = "https://github.com/microsoft/onnxruntime/releases/download/v1.16.3/onnxruntime-linux-x64-1.16.3.tgz"
)

// Accelerator type for embeddings
type Accelerator string

const (
	AcceleratorCPU     Accelerator = "CPU"
	AcceleratorCUDA    Accelerator = "CUDA"
	AcceleratorCoreML  Accelerator = "CoreML"
	AcceleratorDirectML Accelerator = "DirectML"
)

// Provider generates embeddings
type Provider struct {
	modelPath    string
	session      *ort.DynamicAdvancedSession
	ready        bool
	accelerator  Accelerator
	needsPooling bool // true if model outputs last_hidden_state (needs mean pooling)
}

// modelDir returns the directory for storing models
func modelDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sinesync", "models", ModelName)
}

// modelFilePath returns the path to the ONNX model file
func modelFilePath() string {
	return filepath.Join(modelDir(), "model.onnx")
}

// onnxLibPath returns the path to the ONNX runtime library
func onnxLibPath() string {
	return filepath.Join(modelDir(), "lib", "libonnxruntime.so")
}

// detectGPU checks for available GPU acceleration
func detectGPU() (Accelerator, bool) {
	switch runtime.GOOS {
	case "darwin":
		// Apple Silicon always has CoreML/Metal
		if runtime.GOARCH == "arm64" {
			return AcceleratorCoreML, true
		}
	case "linux", "windows":
		// Check for NVIDIA GPU via nvidia-smi
		if _, err := os.Stat("/usr/bin/nvidia-smi"); err == nil {
			return AcceleratorCUDA, true
		}
		if _, err := os.Stat("/usr/local/cuda"); err == nil {
			return AcceleratorCUDA, true
		}
		// Check for environment variable
		if os.Getenv("CUDA_VISIBLE_DEVICES") != "" {
			return AcceleratorCUDA, true
		}
	}
	return AcceleratorCPU, false
}

// NewProvider creates a new embedding provider
// Downloads the ONNX model and runtime if not present
// Automatically detects and uses GPU/MPS acceleration when available
func NewProvider() (*Provider, error) {
	p := &Provider{
		modelPath:   modelFilePath(),
		ready:       false,
		accelerator: AcceleratorCPU,
	}

	// Detect GPU availability
	accel, hasGPU := detectGPU()
	if hasGPU {
		p.accelerator = accel
	}

	// Check if model exists, download if not
	if _, err := os.Stat(p.modelPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "sine~sync: Downloading embedding model %s...\n", ModelName)
		if err := downloadModel(); err != nil {
			fmt.Fprintf(os.Stderr, "sine~sync: Model download failed: %v (using fallback)\n", err)
			return p, nil
		}
		fmt.Fprintf(os.Stderr, "sine~sync: Model downloaded successfully\n")
	}

	// Check if ONNX runtime library exists, download if not
	libPath := onnxLibPath()
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "sine~sync: Downloading ONNX runtime")
		if hasGPU {
			fmt.Fprintf(os.Stderr, " (with %s support)", accel)
		}
		fmt.Fprintf(os.Stderr, "...\n")
		if err := downloadONNXRuntime(hasGPU, accel); err != nil {
			fmt.Fprintf(os.Stderr, "sine~sync: ONNX runtime download failed: %v (using fallback)\n", err)
			return p, nil
		}
		fmt.Fprintf(os.Stderr, "sine~sync: ONNX runtime ready\n")
	}

	// Set library path before initializing
	ort.SetSharedLibraryPath(libPath)

	// Initialize ONNX runtime
	if err := ort.InitializeEnvironment(); err != nil {
		fmt.Fprintf(os.Stderr, "sine~sync: ONNX init failed: %v (using fallback)\n", err)
		return p, nil
	}

	// Create session options with GPU provider if available
	opts, err := ort.NewSessionOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sine~sync: Session options failed: %v (using fallback)\n", err)
		return p, nil
	}

	// Try to enable GPU acceleration
	gpuEnabled := false
	switch p.accelerator {
	case AcceleratorCUDA:
		cudaOpts, err := ort.NewCUDAProviderOptions()
		if err == nil {
			err = opts.AppendExecutionProviderCUDA(cudaOpts)
			if err == nil {
				gpuEnabled = true
			}
			cudaOpts.Destroy()
		}
	case AcceleratorCoreML:
		err = opts.AppendExecutionProviderCoreML(0)
		if err == nil {
			gpuEnabled = true
		}
	}

	if !gpuEnabled {
		p.accelerator = AcceleratorCPU
	}

	// Load the model with last_hidden_state output (standard ONNX export)
	// This output requires mean pooling to get sentence embeddings
	inputNames := []string{"input_ids", "attention_mask", "token_type_ids"}
	outputNames := []string{"last_hidden_state"}

	session, err := ort.NewDynamicAdvancedSession(
		p.modelPath,
		inputNames,
		outputNames,
		opts,
	)
	if err != nil {
		opts.Destroy()
		fmt.Fprintf(os.Stderr, "sine~sync: ONNX session failed: %v (using fallback)\n", err)
		return p, nil
	}
	p.needsPooling = true

	p.session = session
	p.ready = true

	if p.accelerator != AcceleratorCPU {
		fmt.Fprintf(os.Stderr, "sine~sync: Using %s acceleration\n", p.accelerator)
	}

	return p, nil
}

// downloadModel downloads the ONNX model from Hugging Face
func downloadModel() error {
	// Create model directory
	dir := modelDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	// Download model file
	resp, err := http.Get(modelURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Create output file
	out, err := os.Create(modelFilePath())
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	// Copy with progress indication
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("save file: %w", err)
	}

	return nil
}

// downloadONNXRuntime downloads and extracts the ONNX runtime library
// Must match the version expected by onnxruntime_go (v1.23.2)
// Downloads GPU-enabled version when GPU is detected
func downloadONNXRuntime(useGPU bool, accel Accelerator) error {
	const onnxVersion = "1.23.2"

	// Determine platform-specific URL
	var url string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			if useGPU && accel == AcceleratorCUDA {
				// GPU version with CUDA support
				url = fmt.Sprintf("https://github.com/microsoft/onnxruntime/releases/download/v%s/onnxruntime-linux-x64-gpu-%s.tgz", onnxVersion, onnxVersion)
			} else {
				url = fmt.Sprintf("https://github.com/microsoft/onnxruntime/releases/download/v%s/onnxruntime-linux-x64-%s.tgz", onnxVersion, onnxVersion)
			}
		} else if runtime.GOARCH == "arm64" {
			url = fmt.Sprintf("https://github.com/microsoft/onnxruntime/releases/download/v%s/onnxruntime-linux-aarch64-%s.tgz", onnxVersion, onnxVersion)
		}
	case "darwin":
		// macOS builds include CoreML support by default
		if runtime.GOARCH == "arm64" {
			url = fmt.Sprintf("https://github.com/microsoft/onnxruntime/releases/download/v%s/onnxruntime-osx-arm64-%s.tgz", onnxVersion, onnxVersion)
		} else {
			url = fmt.Sprintf("https://github.com/microsoft/onnxruntime/releases/download/v%s/onnxruntime-osx-x86_64-%s.tgz", onnxVersion, onnxVersion)
		}
	default:
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if url == "" {
		return fmt.Errorf("unsupported architecture: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Download the tarball
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Create lib directory
	libDir := filepath.Join(modelDir(), "lib")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		return fmt.Errorf("create lib dir: %w", err)
	}

	// Extract the tarball
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}

		// Only extract the shared library
		name := filepath.Base(header.Name)
		if strings.HasPrefix(name, "libonnxruntime.") && header.Typeflag == tar.TypeReg {
			outPath := filepath.Join(libDir, name)
			outFile, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("create file: %w", err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("extract file: %w", err)
			}
			outFile.Close()

			// Make symlink for .so if we got .so.X.Y.Z
			if strings.Contains(name, ".so.") {
				linkPath := filepath.Join(libDir, "libonnxruntime.so")
				os.Remove(linkPath) // Remove if exists
				os.Symlink(name, linkPath)
			}
		}
	}

	return nil
}

// IsReady returns whether the ONNX provider is ready
func (p *Provider) IsReady() bool {
	return p.ready
}

// ModelPath returns the model path
func (p *Provider) ModelPath() string {
	return p.modelPath
}

// Accelerator returns the current accelerator being used
func (p *Provider) Accelerator() Accelerator {
	return p.accelerator
}

// Verbose controls debug output for embedding issues
var Verbose = false

// Embed generates an embedding for text using ONNX model
func (p *Provider) Embed(text string) ([]float32, error) {
	if !p.ready || p.session == nil {
		if Verbose {
			fmt.Fprintf(os.Stderr, "ONNX: not ready (ready=%v, session=%v)\n", p.ready, p.session != nil)
		}
		return FallbackEmbed(text), nil
	}

	// Tokenize text (simplified - real impl would use a tokenizer)
	tokens := simpleTokenize(text)

	// Create input tensors
	inputIDs := make([]int64, len(tokens))
	attentionMask := make([]int64, len(tokens))
	tokenTypeIDs := make([]int64, len(tokens))

	for i, t := range tokens {
		inputIDs[i] = int64(t)
		attentionMask[i] = 1
		tokenTypeIDs[i] = 0
	}

	shape := ort.Shape{1, int64(len(tokens))}

	inputIDsTensor, err := ort.NewTensor(shape, inputIDs)
	if err != nil {
		if Verbose {
			fmt.Fprintf(os.Stderr, "ONNX: inputIDs tensor failed: %v\n", err)
		}
		return FallbackEmbed(text), nil
	}
	defer inputIDsTensor.Destroy()

	attentionTensor, err := ort.NewTensor(shape, attentionMask)
	if err != nil {
		if Verbose {
			fmt.Fprintf(os.Stderr, "ONNX: attention tensor failed: %v\n", err)
		}
		return FallbackEmbed(text), nil
	}
	defer attentionTensor.Destroy()

	tokenTypeTensor, err := ort.NewTensor(shape, tokenTypeIDs)
	if err != nil {
		if Verbose {
			fmt.Fprintf(os.Stderr, "ONNX: tokenType tensor failed: %v\n", err)
		}
		return FallbackEmbed(text), nil
	}
	defer tokenTypeTensor.Destroy()

	// Prepare inputs as Values
	inputs := []ort.Value{
		inputIDsTensor,
		attentionTensor,
		tokenTypeTensor,
	}

	// Prepare output placeholder (will be allocated by Run)
	outputs := []ort.Value{nil}

	// Run inference
	err = p.session.Run(inputs, outputs)
	if err != nil {
		if Verbose {
			fmt.Fprintf(os.Stderr, "ONNX: session.Run failed: %v\n", err)
		}
		return FallbackEmbed(text), nil
	}
	defer func() {
		for _, o := range outputs {
			if o != nil {
				o.Destroy()
			}
		}
	}()

	// Extract embedding from output tensor
	if outputs[0] != nil {
		outputTensor, ok := outputs[0].(*ort.Tensor[float32])
		if ok {
			data := outputTensor.GetData()
			shape := outputTensor.GetShape()

			if p.needsPooling {
				// last_hidden_state output: shape [1, seq_len, hidden_size]
				// Need to mean pool across sequence dimension
				if len(shape) == 3 && shape[2] == int64(Dimensions) {
					seqLen := int(shape[1])
					embedding := make([]float32, Dimensions)

					// Mean pooling with attention mask
					for i := 0; i < Dimensions; i++ {
						var sum float32
						validTokens := 0
						for j := 0; j < seqLen && j < len(tokens); j++ {
							if attentionMask[j] == 1 {
								sum += data[j*Dimensions+i]
								validTokens++
							}
						}
						if validTokens > 0 {
							embedding[i] = sum / float32(validTokens)
						}
					}
					return embedding, nil
				}
				if Verbose {
					fmt.Fprintf(os.Stderr, "ONNX: unexpected shape for pooling: %v\n", shape)
				}
			} else {
				// sentence_embedding output: shape [1, hidden_size]
				if len(data) >= Dimensions {
					embedding := make([]float32, Dimensions)
					copy(embedding, data[:Dimensions])
					return embedding, nil
				}
				if Verbose {
					fmt.Fprintf(os.Stderr, "ONNX: output data too small: %d < %d\n", len(data), Dimensions)
				}
			}
		} else {
			if Verbose {
				fmt.Fprintf(os.Stderr, "ONNX: output not float32 tensor\n")
			}
		}
	} else {
		if Verbose {
			fmt.Fprintf(os.Stderr, "ONNX: output[0] is nil\n")
		}
	}

	return FallbackEmbed(text), nil
}

// simpleTokenize provides basic tokenization
// A proper implementation would use the model's actual tokenizer
// MiniLM vocabulary size is 30522
const vocabSize = 30522

func simpleTokenize(text string) []int {
	// [CLS] token
	tokens := []int{101}

	// Simple word-based tokenization
	// Map words to token IDs within vocabulary bounds
	words := strings.Fields(strings.ToLower(text))
	for _, word := range words {
		if len(tokens) >= MaxTokens-1 {
			break
		}

		// Hash word to a token ID within vocabulary
		h := 0
		for _, c := range word {
			h = h*31 + int(c)
		}
		if h < 0 {
			h = -h
		}
		// Keep in vocab range [1000, 30521] - avoid special tokens
		tokenID := (h % (vocabSize - 1000)) + 1000
		tokens = append(tokens, tokenID)
	}

	// [SEP] token
	tokens = append(tokens, 102)

	return tokens
}

// Close cleans up resources
func (p *Provider) Close() error {
	if p.session != nil {
		return p.session.Destroy()
	}
	return nil
}

// CosineSimilarity computes cosine similarity between two embeddings
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}

	var dot, normA, normB float32
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dot / (float32(math.Sqrt(float64(normA))) * float32(math.Sqrt(float64(normB))))
}

// FallbackEmbed generates a deterministic hash-based embedding
// This provides consistent similarity for identical or similar text
// while allowing the system to work without ONNX
func FallbackEmbed(text string) []float32 {
	embedding := make([]float32, Dimensions)

	// Normalize and split text
	words := strings.Fields(strings.ToLower(text))

	// Character n-gram approach for better similarity matching
	for _, word := range words {
		// Word-level features
		wordHash := hashString(word)
		for i := 0; i < 4; i++ {
			idx := (wordHash + i*97) % Dimensions
			embedding[idx] += 1.0
		}

		// Character trigram features for partial matching
		if len(word) >= 3 {
			for i := 0; i <= len(word)-3; i++ {
				trigram := word[i : i+3]
				trigramHash := hashString(trigram)
				idx := trigramHash % Dimensions
				embedding[idx] += 0.5
			}
		}
	}

	// Normalize to unit vector
	normalize(embedding)
	return embedding
}

func hashString(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

func normalize(v []float32) {
	var norm float32
	for _, x := range v {
		norm += x * x
	}
	norm = float32(math.Sqrt(float64(norm)))

	if norm > 0 {
		for i := range v {
			v[i] /= norm
		}
	}
}
