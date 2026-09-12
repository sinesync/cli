package owneronly

import (
	"os"
	"path/filepath"
	"testing"
)

// IsOwnerOnly is the verifier three security assertions in this repo now rest
// on, so it needs its own. A verifier that only ever says yes passes every one
// of those assertions while proving nothing — which is exactly what a mutation
// test found before these existed.

func writeTemp(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyMakesAFileOwnerOnly(t *testing.T) {
	path := writeTemp(t, "key")
	if err := Apply(path); err != nil {
		t.Fatalf("apply: %v", err)
	}
	private, err := IsOwnerOnly(path)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !private {
		t.Error("a file just restricted to its owner does not report as such")
	}
}

func TestApplyLeavesADirectoryTraversable(t *testing.T) {
	// A directory restricted to 0600 cannot be entered, including by the process
	// that restricted it — so the file inside becomes unreachable rather than
	// private.
	dir := t.TempDir()
	if err := Apply(dir); err != nil {
		t.Fatalf("apply: %v", err)
	}
	private, err := IsOwnerOnly(dir)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !private {
		t.Error("a directory just restricted to its owner does not report as such")
	}

	inside := filepath.Join(dir, "child")
	if err := os.WriteFile(inside, []byte("x"), 0o600); err != nil {
		t.Fatalf("the restricted directory cannot be written to: %v", err)
	}
	if _, err := os.ReadFile(inside); err != nil {
		t.Fatalf("the restricted directory cannot be read from: %v", err)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	path := writeTemp(t, "key")
	for i := 0; i < 3; i++ {
		if err := Apply(path); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	if private, _ := IsOwnerOnly(path); !private {
		t.Error("repeated application stopped being owner-only")
	}
}

func TestIsOwnerOnlyReportsAMissingFile(t *testing.T) {
	if _, err := IsOwnerOnly(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing file was reported on rather than erroring")
	}
}
