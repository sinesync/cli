package embeddings

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The ONNX archive is a native library loaded into this process, so an
// unverified download is code execution as the user. These tests guard the
// pinning itself: the check is only worth having if every archive the code can
// ask for actually has a pin, and if bumping the version cannot silently drop
// the check.
func TestEveryPinnedDigestIsWellFormed(t *testing.T) {
	sha256Hex := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if len(onnxArchiveDigests) == 0 {
		t.Fatal("no pinned digests: the verification would refuse every platform")
	}
	for name, sum := range onnxArchiveDigests {
		if !sha256Hex.MatchString(sum) {
			t.Errorf("%s: %q is not a lowercase 64-character SHA-256", name, sum)
		}
	}
}

// Every archive name the download code can construct must be pinned. Without
// this, adding a platform or bumping onnxVersion leaves a name with no pin —
// which is refused at runtime, so the failure is safe, but it is far better
// found here than by a user whose daemon cannot start.
func TestEveryPlatformArchiveIsPinned(t *testing.T) {
	// Read the archive names out of the SOURCE rather than restating them here.
	// The previous version listed six names by hand, called itself exhaustive,
	// and silently omitted onnxruntime-osx-x86_64 — so an Intel Mac built a URL
	// with no pin, the download was refused, and ONNX embeddings were lost on
	// that platform with this test still green. A list maintained beside the
	// thing it checks drifts from it; deriving it cannot.
	src, err := os.ReadFile("embeddings.go")
	if err != nil {
		t.Fatalf("reading source: %v", err)
	}
	names := regexp.MustCompile(`onnxruntime-[a-z0-9_-]+-%s\.(?:tgz|zip)`).FindAllString(string(src), -1)
	if len(names) == 0 {
		t.Fatal("found no archive names in embeddings.go; this test is not checking anything")
	}

	const version = "1.23.2" // must track onnxVersion
	seen := map[string]bool{}
	for _, pattern := range names {
		name := strings.Replace(pattern, "%s", version, 1)
		if seen[name] {
			continue
		}
		seen[name] = true
		if _, ok := onnxArchiveDigests[name]; !ok {
			t.Errorf("%s can be constructed by the download code but has no pinned digest, so that platform cannot install the runtime", name)
		}
	}
	t.Logf("checked %d distinct archive names derived from the source", len(seen))
}

// A pin for THIS platform must exist, or the daemon cannot embed anything here.
func TestThisPlatformHasAPin(t *testing.T) {
	found := false
	for name := range onnxArchiveDigests {
		switch {
		case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
			found = found || name == "onnxruntime-osx-arm64-1.23.2.tgz"
		case runtime.GOOS == "linux" && runtime.GOARCH == "amd64":
			found = found || name == "onnxruntime-linux-x64-1.23.2.tgz"
		case runtime.GOOS == "linux" && runtime.GOARCH == "arm64":
			found = found || name == "onnxruntime-linux-aarch64-1.23.2.tgz"
		case runtime.GOOS == "windows" && runtime.GOARCH == "amd64":
			found = found || name == "onnxruntime-win-x64-1.23.2.zip"
		default:
			t.Skipf("no expectation recorded for %s/%s", runtime.GOOS, runtime.GOARCH)
		}
	}
	if !found {
		t.Errorf("no pinned digest covers %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

// The model and vocabulary are pinned the same way as the runtime, and for a
// sharper reason: the URLs previously used /resolve/main/, a mutable branch
// pointer, so upstream could change what the daemon loads with no compromise
// involved at all. A digest is only meaningful against a fixed revision.
func TestModelIsPinnedToARevisionNotABranch(t *testing.T) {
	for name, url := range map[string]string{"model": modelURL, "vocab": vocabURL} {
		if strings.Contains(url, "/resolve/main/") {
			t.Errorf("%s URL resolves a branch, so the pinned digest cannot hold: %s", name, url)
		}
		if !strings.Contains(url, modelRevision) {
			t.Errorf("%s URL does not name the pinned revision: %s", name, url)
		}
	}
	if len(modelRevision) != 40 {
		t.Errorf("modelRevision %q is not a full commit sha", modelRevision)
	}
	for name, sum := range map[string]string{"modelSHA256": modelSHA256, "vocabSHA256": vocabSHA256} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sum) {
			t.Errorf("%s is not a lowercase 64-character SHA-256: %q", name, sum)
		}
	}
}

// The Go binding and the runtime it loads must speak the same C API. The
// binding asks the library for ORT_API_VERSION from the header it was built
// against, and a runtime older than that returns no API table at all, so the
// daemon fails at startup on every platform. A dependency bump moved the
// binding to a header for API 29 while onnxVersion still downloaded 1.23.2
// (API 23), and nothing here noticed. ONNX Runtime numbers its C API after the
// minor release, so the two sides are compared by deriving each from its
// source: the runtime from onnxVersion in embeddings.go, the binding from the
// header of the module version go.mod actually resolves.
func TestBindingAPIMatchesDownloadedRuntime(t *testing.T) {
	const bindingModule = "github.com/yalue/onnxruntime_go"

	src, err := os.ReadFile("embeddings.go")
	if err != nil {
		t.Fatalf("reading source: %v", err)
	}
	versions := regexp.MustCompile(`const onnxVersion = "(\d+)\.(\d+)\.(\d+)"`).FindAllStringSubmatch(string(src), -1)
	if len(versions) != 1 {
		t.Fatalf("expected exactly one onnxVersion constant in embeddings.go, found %d; this test cannot tell which runtime is downloaded", len(versions))
	}
	runtimeAPI, err := strconv.Atoi(versions[0][2])
	if err != nil {
		t.Fatalf("parsing minor version of onnxVersion %q: %v", versions[0][0], err)
	}

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("locating the go command to resolve %s: %v", bindingModule, err)
	}
	out, err := exec.Command(goBin, "list", "-m", "-json", bindingModule).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list -m %s: %v\n%s", bindingModule, err, ee.Stderr)
		}
		t.Fatalf("go list -m %s: %v", bindingModule, err)
	}
	var mod struct {
		Path    string
		Version string
		Dir     string
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatalf("parsing go list output for %s: %v\n%s", bindingModule, err, out)
	}
	if mod.Version == "" || mod.Dir == "" {
		t.Fatalf("%s resolved to version %q in directory %q; run `go mod download` so its header can be read", bindingModule, mod.Version, mod.Dir)
	}

	header := filepath.Join(mod.Dir, "onnxruntime_c_api.h")
	hdr, err := os.ReadFile(header)
	if err != nil {
		t.Fatalf("reading the header of %s@%s: %v", bindingModule, mod.Version, err)
	}
	defines := regexp.MustCompile(`(?m)^\s*#define\s+ORT_API_VERSION\s+(\d+)\s*$`).FindAllStringSubmatch(string(hdr), -1)
	if len(defines) != 1 {
		t.Fatalf("expected exactly one #define ORT_API_VERSION in %s, found %d", header, len(defines))
	}
	bindingAPI, err := strconv.Atoi(defines[0][1])
	if err != nil {
		t.Fatalf("parsing ORT_API_VERSION %q in %s: %v", defines[0][1], header, err)
	}

	if bindingAPI != runtimeAPI {
		t.Fatalf("%s@%s is built against ORT_API_VERSION %d, but embeddings.go downloads ONNX Runtime %s.%s.%s (API %d); move the binding and onnxVersion together",
			bindingModule, mod.Version, bindingAPI, versions[0][1], versions[0][2], versions[0][3], runtimeAPI)
	}
	t.Logf("%s@%s and ONNX Runtime %s.%s.%s both use C API %d", bindingModule, mod.Version, versions[0][1], versions[0][2], versions[0][3], bindingAPI)
}
