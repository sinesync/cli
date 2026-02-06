package embeddings

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode"

	ort "github.com/yalue/onnxruntime_go"
)

const (
	ModelName     = "all-MiniLM-L6-v2"
	TokenizerType = "wordpiece-hf"
	Dimensions    = 384
	MaxTokens     = 256

	// Hugging Face URLs
	modelURL = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx"
	vocabURL = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/vocab.txt"

	// Special token IDs (BERT vocab)
	clsTokenID = 101  // [CLS]
	sepTokenID = 102  // [SEP]
	unkTokenID = 100  // [UNK]
	padTokenID = 0    // [PAD]

	// ONNX Runtime library URL (Linux x64)
	onnxRuntimeVersion = "1.16.3"
	onnxRuntimeURL     = "https://github.com/microsoft/onnxruntime/releases/download/v1.16.3/onnxruntime-linux-x64-1.16.3.tgz"
)


// Accelerator type for embeddings
type Accelerator string

const (
	AcceleratorCPU      Accelerator = "CPU"
	AcceleratorCUDA     Accelerator = "CUDA"
	AcceleratorCoreML   Accelerator = "CoreML"
	AcceleratorDirectML Accelerator = "DirectML"
)

// WordPieceTokenizer implements BERT-style WordPiece tokenization
type WordPieceTokenizer struct {
	vocab    map[string]int // token -> id
	invVocab map[int]string // id -> token
}

// Provider generates embeddings
type Provider struct {
	modelPath    string
	vocabPath    string
	session      *ort.DynamicAdvancedSession
	tokenizer    *WordPieceTokenizer
	ready        bool
	accelerator  Accelerator
	needsPooling bool // true if model outputs last_hidden_state (needs mean pooling)
}

// Singleton instance - ONNX can only be initialized once per process
var (
	globalProvider     *Provider
	globalProviderOnce sync.Once
	globalProviderErr  error
)

// GetProvider returns the singleton embedding provider
// This is the preferred way to get an embedder as ONNX can only be initialized once
func GetProvider() (*Provider, error) {
	globalProviderOnce.Do(func() {
		globalProvider, globalProviderErr = newProviderInternal()
	})
	return globalProvider, globalProviderErr
}

// NewProvider creates or returns the singleton embedding provider
// For backwards compatibility - internally uses GetProvider()
func NewProvider() (*Provider, error) {
	return GetProvider()
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

// vocabFilePath returns the path to the vocab.txt file
func vocabFilePath() string {
	return filepath.Join(modelDir(), "vocab.txt")
}

// NewWordPieceTokenizer loads a WordPiece vocabulary from a vocab.txt file
func NewWordPieceTokenizer(vocabPath string) (*WordPieceTokenizer, error) {
	file, err := os.Open(vocabPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	vocab := make(map[string]int)
	invVocab := make(map[int]string)

	scanner := bufio.NewScanner(file)
	id := 0
	for scanner.Scan() {
		token := scanner.Text()
		vocab[token] = id
		invVocab[id] = token
		id++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &WordPieceTokenizer{vocab: vocab, invVocab: invVocab}, nil
}

// Tokenize converts text to token IDs using WordPiece algorithm
func (t *WordPieceTokenizer) Tokenize(text string) []int {
	// Normalize: lowercase and clean whitespace
	text = strings.ToLower(text)

	// Start with [CLS]
	tokens := []int{clsTokenID}

	// Split into words (basic whitespace tokenization)
	words := strings.Fields(text)

	for _, word := range words {
		if len(tokens) >= MaxTokens-1 {
			break
		}

		// Clean punctuation - split punctuation from words
		subwords := t.splitPunctuation(word)

		for _, subword := range subwords {
			if len(tokens) >= MaxTokens-1 {
				break
			}

			// Apply WordPiece to each subword
			wordTokens := t.wordPiece(subword)
			for _, tok := range wordTokens {
				if len(tokens) >= MaxTokens-1 {
					break
				}
				tokens = append(tokens, tok)
			}
		}
	}

	// End with [SEP]
	tokens = append(tokens, sepTokenID)

	return tokens
}

// splitPunctuation splits punctuation from words
func (t *WordPieceTokenizer) splitPunctuation(word string) []string {
	var result []string
	var current strings.Builder

	for _, r := range word {
		if unicode.IsPunct(r) {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			result = append(result, string(r))
		} else {
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

// wordPiece applies the WordPiece algorithm to a single word
func (t *WordPieceTokenizer) wordPiece(word string) []int {
	if len(word) == 0 {
		return nil
	}

	// Check if whole word is in vocab
	if id, ok := t.vocab[word]; ok {
		return []int{id}
	}

	var tokens []int
	start := 0

	for start < len(word) {
		end := len(word)
		foundToken := false

		for end > start {
			substr := word[start:end]
			if start > 0 {
				// Add ## prefix for subword tokens
				substr = "##" + substr
			}

			if id, ok := t.vocab[substr]; ok {
				tokens = append(tokens, id)
				foundToken = true
				break
			}
			end--
		}

		if !foundToken {
			// Character not in vocab, use [UNK]
			tokens = append(tokens, unkTokenID)
			start++
		} else {
			start = end
		}
	}

	return tokens
}

// onnxLibPath returns the path to the ONNX runtime library
func onnxLibPath() string {
	libName := "libonnxruntime.so"
	if runtime.GOOS == "darwin" {
		libName = "libonnxruntime.dylib"
	}
	return filepath.Join(modelDir(), "lib", libName)
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

// newProviderInternal creates the actual embedding provider
// Downloads the ONNX model, vocab, and runtime if not present
// Automatically detects and uses GPU/MPS acceleration when available
func newProviderInternal() (*Provider, error) {
	p := &Provider{
		modelPath:   modelFilePath(),
		vocabPath:   vocabFilePath(),
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

	// Check if vocab exists, download if not
	if _, err := os.Stat(p.vocabPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "sine~sync: Downloading vocab...\n")
		if err := downloadVocab(); err != nil {
			fmt.Fprintf(os.Stderr, "sine~sync: Vocab download failed: %v (using fallback)\n", err)
			return p, nil
		}
		fmt.Fprintf(os.Stderr, "sine~sync: Vocab ready\n")
	}

	// Initialize WordPiece tokenizer
	tk, err := NewWordPieceTokenizer(p.vocabPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sine~sync: Tokenizer init failed: %v (using fallback)\n", err)
		return p, nil
	}
	p.tokenizer = tk

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
		// Note: CoreML may print "Context leak detected, CoreAnalytics returned false"
		// This is harmless - it's an Apple internal diagnostic, not an error
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

// downloadVocab downloads the vocab.txt from Hugging Face
func downloadVocab() error {
	// Create model directory
	dir := modelDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	// Download vocab file
	resp, err := http.Get(vocabURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Create output file
	out, err := os.Create(vocabFilePath())
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

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

			// Make symlink for versioned libraries
			// Linux: libonnxruntime.so.1.23.2 -> libonnxruntime.so
			// macOS: libonnxruntime.1.23.2.dylib -> libonnxruntime.dylib
			if strings.Contains(name, ".so.") {
				linkPath := filepath.Join(libDir, "libonnxruntime.so")
				os.Remove(linkPath)
				os.Symlink(name, linkPath)
			} else if runtime.GOOS == "darwin" && strings.Contains(name, ".dylib") && name != "libonnxruntime.dylib" {
				linkPath := filepath.Join(libDir, "libonnxruntime.dylib")
				os.Remove(linkPath)
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
	if !p.ready || p.session == nil || p.tokenizer == nil {
		return nil, fmt.Errorf("ONNX not ready (ready=%v, session=%v, tokenizer=%v)", p.ready, p.session != nil, p.tokenizer != nil)
	}

	// Tokenize text using WordPiece tokenizer
	tokenIDs := p.tokenizer.Tokenize(text)

	// Create input tensors from tokenizer output
	seqLen := len(tokenIDs)
	inputIDs := make([]int64, seqLen)
	attentionMask := make([]int64, seqLen)
	tokenTypeIDs := make([]int64, seqLen)

	for i, t := range tokenIDs {
		inputIDs[i] = int64(t)
		attentionMask[i] = 1 // All tokens are valid
		tokenTypeIDs[i] = 0  // Single sequence
	}

	shape := ort.Shape{1, int64(seqLen)}

	inputIDsTensor, err := ort.NewTensor(shape, inputIDs)
	if err != nil {
		return nil, fmt.Errorf("inputIDs tensor: %w", err)
	}
	defer inputIDsTensor.Destroy()

	attentionTensor, err := ort.NewTensor(shape, attentionMask)
	if err != nil {
		return nil, fmt.Errorf("attention tensor: %w", err)
	}
	defer attentionTensor.Destroy()

	tokenTypeTensor, err := ort.NewTensor(shape, tokenTypeIDs)
	if err != nil {
		return nil, fmt.Errorf("tokenType tensor: %w", err)
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
		return nil, fmt.Errorf("session.Run: %w", err)
	}
	defer func() {
		for _, o := range outputs {
			if o != nil {
				o.Destroy()
			}
		}
	}()

	// Extract embedding from output tensor
	if outputs[0] == nil {
		return nil, fmt.Errorf("ONNX output is nil")
	}

	outputTensor, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return nil, fmt.Errorf("ONNX output is not float32 tensor")
	}

	data := outputTensor.GetData()
	outputShape := outputTensor.GetShape()

	if p.needsPooling {
		// last_hidden_state output: shape [1, seq_len, hidden_size]
		// Need to mean pool across sequence dimension
		if len(outputShape) != 3 || outputShape[2] != int64(Dimensions) {
			return nil, fmt.Errorf("unexpected shape for pooling: %v", outputShape)
		}
		poolSeqLen := int(outputShape[1])
		embedding := make([]float32, Dimensions)

		// Mean pooling with attention mask
		for i := 0; i < Dimensions; i++ {
			var sum float32
			validTokens := 0
			for j := 0; j < poolSeqLen && j < len(tokenIDs); j++ {
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

	// sentence_embedding output: shape [1, hidden_size]
	if len(data) < Dimensions {
		return nil, fmt.Errorf("output data too small: %d < %d", len(data), Dimensions)
	}
	embedding := make([]float32, Dimensions)
	copy(embedding, data[:Dimensions])
	return embedding, nil
}


// Close cleans up resources
func (p *Provider) Close() error {
	p.tokenizer = nil
	if p.session != nil {
		return p.session.Destroy()
	}
	return nil
}

// TokenizerType returns the tokenizer type used
func (p *Provider) TokenizerType() string {
	if p.tokenizer != nil {
		return TokenizerType
	}
	return "hash-simple"
}

// EmbedWithMetadata generates an embedding and returns it with full metadata
func (p *Provider) EmbedWithMetadata(text string) (vector []float32, model, tokenizerType string, dims int, err error) {
	vector, err = p.Embed(text)
	if err != nil {
		return nil, "", "", 0, err
	}
	return vector, ModelName, p.TokenizerType(), Dimensions, nil
}

// GetConfig returns the current embedding configuration
func (p *Provider) GetConfig() (model, tokenizerType string, dims int) {
	return ModelName, p.TokenizerType(), Dimensions
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
