package embeddings

import (
	"fmt"
	"regexp"
	"runtime"
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
	const version = "1.23.2" // must track onnxVersion in embeddings.go
	for _, name := range []string{
		fmt.Sprintf("onnxruntime-linux-aarch64-%s.tgz", version),
		fmt.Sprintf("onnxruntime-linux-x64-%s.tgz", version),
		fmt.Sprintf("onnxruntime-linux-x64-gpu-%s.tgz", version),
		fmt.Sprintf("onnxruntime-osx-arm64-%s.tgz", version),
		fmt.Sprintf("onnxruntime-win-x64-%s.zip", version),
		fmt.Sprintf("onnxruntime-win-arm64-%s.zip", version),
	} {
		if _, ok := onnxArchiveDigests[name]; !ok {
			t.Errorf("%s has no pinned digest, so this platform cannot install the runtime", name)
		}
	}
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
