package embeddings

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path"
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
	// Pinned to a REVISION, not to /resolve/main/. A branch pointer means the
	// upstream repository can change these files at any time with no compromise
	// involved, and model.onnx is parsed and executed by the ONNX runtime. The
	// digests below only mean something because the revision is fixed too:
	// pinning a hash against a moving target would just break on the next
	// upstream push.
	modelRevision = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"

	modelURL = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/" + modelRevision + "/onnx/model.onnx"
	vocabURL = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/" + modelRevision + "/vocab.txt"

	// SHA-256 of the two files at that revision, each cross-checked against
	// Hugging Face's own metadata rather than trusted from a single download:
	//   model.onnx is LFS-stored, and this matches the lfs.oid the tree API
	//     publishes for it (which IS the SHA-256).
	//   vocab.txt is a plain git blob, so the API gives only a SHA-1 oid —
	//     recomputing sha1("blob <size>\0" + content) over the download
	//     reproduces fb140275c155a9c7c5a3b3e0e77a9e839594a938, confirming the
	//     bytes these hashes were taken from are the ones upstream records.
	modelSHA256 = "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452"
	vocabSHA256 = "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3"

	// Special token IDs (BERT vocab)
	clsTokenID = 101 // [CLS]
	sepTokenID = 102 // [SEP]
	unkTokenID = 100 // [UNK]
	padTokenID = 0   // [PAD]

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
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(modelDir(), "lib", "libonnxruntime.dylib")
	case "windows":
		return filepath.Join(modelDir(), "lib", "onnxruntime.dll")
	default:
		return filepath.Join(modelDir(), "lib", "libonnxruntime.so")
	}
}

// detectGPU checks for available GPU acceleration
func detectGPU() (Accelerator, bool) {
	switch runtime.GOOS {
	case "darwin":
		// Apple Silicon always has CoreML/Metal
		if runtime.GOARCH == "arm64" {
			return AcceleratorCoreML, true
		}
	case "linux":
		// Check for NVIDIA GPU via nvidia-smi
		if _, err := os.Stat("/usr/bin/nvidia-smi"); err == nil {
			return AcceleratorCUDA, true
		}
		if _, err := os.Stat("/usr/local/cuda"); err == nil {
			return AcceleratorCUDA, true
		}
		if os.Getenv("CUDA_VISIBLE_DEVICES") != "" {
			return AcceleratorCUDA, true
		}
	case "windows":
		// Check for NVIDIA GPU via nvidia-smi on Windows
		if _, err := exec.LookPath("nvidia-smi"); err == nil {
			return AcceleratorCUDA, true
		}
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

	// On Windows, add the DLL's directory to the search path so transitive
	// dependencies (e.g. vcruntime) can be found when loading onnxruntime.dll
	if runtime.GOOS == "windows" {
		addDLLDirectory(filepath.Dir(libPath))
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
	return downloadVerified(modelURL, modelFilePath(), modelSHA256, "embedding model")
}

// downloadVerified fetches url, checks it against want, and only then puts it
// at dest. The file is hashed while streaming to a temporary path and renamed
// into place after it verifies, so a failed or substituted download never
// exists at the name the daemon loads from — an interrupted download that left
// a truncated model behind would otherwise be indistinguishable from a real one.
func downloadVerified(url, dest, want, what string) error {
	dir := modelDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	tmp, sum, err := downloadToTemp(url)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", what, err)
	}
	defer os.Remove(tmp)

	if sum != want {
		return fmt.Errorf("refusing to install the %s: SHA-256 %s does not match the pinned %s", what, sum, want)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fmt.Errorf("securing %s: %w", what, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("installing %s: %w", what, err)
	}
	return nil
}

// downloadVocab downloads the vocab.txt from Hugging Face
func downloadVocab() error {
	return downloadVerified(vocabURL, vocabFilePath(), vocabSHA256, "tokenizer vocabulary")
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
	case "windows":
		if runtime.GOARCH == "amd64" {
			url = fmt.Sprintf("https://github.com/microsoft/onnxruntime/releases/download/v%s/onnxruntime-win-x64-%s.zip", onnxVersion, onnxVersion)
		} else if runtime.GOARCH == "arm64" {
			url = fmt.Sprintf("https://github.com/microsoft/onnxruntime/releases/download/v%s/onnxruntime-win-arm64-%s.zip", onnxVersion, onnxVersion)
		}
	default:
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if url == "" {
		return fmt.Errorf("unsupported architecture: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// This archive is a NATIVE LIBRARY that gets loaded into this process, so a
	// substituted download is code execution as the user — with access to the
	// decrypted observations in memory and every credential the daemon can
	// reach. HTTPS stops an on-path attacker; it says nothing about whether the
	// bytes GitHub served are the bytes we expect. Verify before extracting.
	name := path.Base(url)
	want, pinned := onnxArchiveDigests[name]
	if !pinned {
		return fmt.Errorf("refusing to download %s: no pinned SHA-256 for it. "+
			"Add one to onnxArchiveDigests after verifying the archive, rather than "+
			"loading an unverified native library", name)
	}

	archive, sum, err := downloadToTemp(url)
	if err != nil {
		return err
	}
	defer os.Remove(archive)

	if sum != want {
		// Deleted, not left on disk: a mismatched archive is either a corrupt
		// download or a substituted one, and neither should be retrievable by
		// something else later.
		return fmt.Errorf("refusing to install %s: SHA-256 %s does not match the pinned %s", name, sum, want)
	}

	// Create lib directory
	libDir := filepath.Join(modelDir(), "lib")
	if err := os.MkdirAll(libDir, 0700); err != nil {
		return fmt.Errorf("create lib dir: %w", err)
	}

	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("reopening verified archive: %w", err)
	}
	defer f.Close()

	if runtime.GOOS == "windows" {
		return extractONNXZip(f, libDir)
	}
	return extractONNXTarGz(f, libDir)
}

// onnxArchiveDigests pins the SHA-256 of every ONNX Runtime archive this build
// will accept, keyed by the release asset's filename.
//
// Computed by downloading each asset from
// github.com/microsoft/onnxruntime/releases/tag/v1.23.2 and hashing it. Bumping
// onnxVersion REQUIRES recomputing every entry: an unpinned name is refused
// rather than downloaded, so a forgotten update fails loudly instead of
// silently dropping the check.
var onnxArchiveDigests = map[string]string{
	"onnxruntime-linux-aarch64-1.23.2.tgz": "7c63c73560ed76b1fac6cff8204ffe34fe180e70d6582b5332ec094810241e5c",
	"onnxruntime-linux-x64-1.23.2.tgz":     "1fa4dcaef22f6f7d5cd81b28c2800414350c10116f5fdd46a2160082551c5f9b",
	"onnxruntime-linux-x64-gpu-1.23.2.tgz": "2083e361072a79ce16a90dcd5f5cb3ab92574a82a3ce0ac01e5cfa3158176f53",
	"onnxruntime-osx-arm64-1.23.2.tgz":     "b4d513ab2b26f088c66891dbbc1408166708773d7cc4163de7bdca0e9bbb7856",
	"onnxruntime-win-x64-1.23.2.zip":       "0b38df9af21834e41e73d602d90db5cb06dbd1ca618948b8f1d66d607ac9f3cd",
	"onnxruntime-win-arm64-1.23.2.zip":     "1cfe88b6435df3b5fb0e9f6bd7d6f5df1e887b6174de7f6e2a47bab956f3f168",
}

// downloadToTemp streams url to a temporary file, returning its path and the
// SHA-256 of what was written.
//
// To a file rather than memory because these archives reach 240 MB, and hashed
// while streaming so the bytes verified are the bytes stored — hashing a
// separate read would leave a window where the two differ.
func downloadToTemp(url string) (path string, sum string, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "sinesync-onnx-*")
	if err != nil {
		return "", "", fmt.Errorf("creating temporary file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", "", fmt.Errorf("downloading %s: %w", url, err)
	}
	return tmp.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// extractONNXTarGz extracts the ONNX runtime shared library from a .tgz archive (Linux/macOS)
func extractONNXTarGz(r io.Reader, libDir string) error {
	gzr, err := gzip.NewReader(r)
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

// extractONNXZip extracts the ONNX runtime DLL from a .zip archive (Windows)
func extractONNXZip(r io.Reader, libDir string) error {
	// archive/zip needs a ReaderAt, so download to a temp file first
	tmpFile, err := os.CreateTemp("", "onnxruntime-*.zip")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, r); err != nil {
		return fmt.Errorf("download to temp: %w", err)
	}

	stat, err := tmpFile.Stat()
	if err != nil {
		return fmt.Errorf("stat temp file: %w", err)
	}

	zr, err := zip.NewReader(tmpFile, stat.Size())
	if err != nil {
		return fmt.Errorf("zip reader: %w", err)
	}

	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		if !strings.HasSuffix(name, ".dll") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %s: %w", name, err)
		}
		outPath := filepath.Join(libDir, name)
		outFile, err := os.Create(outPath)
		if err != nil {
			rc.Close()
			return fmt.Errorf("create file %s: %w", name, err)
		}
		if _, err := io.Copy(outFile, rc); err != nil {
			outFile.Close()
			rc.Close()
			return fmt.Errorf("extract file %s: %w", name, err)
		}
		outFile.Close()
		rc.Close()
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
