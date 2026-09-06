package project

import (
	"os"
	"path/filepath"
	"testing"
)

// repo makes a directory look like a git repository.
func repo(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mkdirs(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// The defect this replaced: work in one repository was filed under a different
// project for every directory it happened to start in, and only the root
// carried the repository's own name. Since project is what routes an
// observation to a vault, assigning a project to a shared vault routed the
// root and nothing else.
func TestEveryDirectoryInARepoIsTheSameProject(t *testing.T) {
	root := repo(t, filepath.Join(t.TempDir(), "sinesync"))
	backend := filepath.Join(root, "backend", "src", "services")
	infra := filepath.Join(root, "infra", "modules", "firestore")
	mkdirs(t, backend, infra)

	for _, dir := range []string{root, backend, infra} {
		if got := ForDir(dir); got != "sinesync" {
			t.Errorf("ForDir(%q) = %q, want %q", dir, got, "sinesync")
		}
	}
}

// The collision half: unrelated repositories used to share a project whenever
// they shared a subdirectory name, and therefore shared a vault.
func TestUnrelatedReposWithTheSameSubdirectoryAreDifferentProjects(t *testing.T) {
	base := t.TempDir()
	one := filepath.Join(repo(t, filepath.Join(base, "alpha")), "web")
	two := filepath.Join(repo(t, filepath.Join(base, "beta")), "web")
	mkdirs(t, one, two)

	if a, b := ForDir(one), ForDir(two); a == b {
		t.Errorf("both resolved to %q; unrelated repositories must not share a project", a)
	}
}

func TestFallsBackToTheDirectoryOutsideARepository(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose-notes")
	mkdirs(t, dir)

	if got := ForDir(dir); got != "loose-notes" {
		t.Errorf("ForDir(%q) = %q, want %q", dir, got, "loose-notes")
	}
}

// worktree makes `dir` look like a git worktree of `main`, the way git lays one
// out: a .git FILE pointing at the main repo's worktrees directory, with a
// commondir inside it pointing back at the main .git.
func worktree(t *testing.T, main, dir string) string {
	t.Helper()

	gitDir := filepath.Join(main, ".git", "worktrees", filepath.Base(dir))
	mkdirs(t, gitDir, dir)

	if err := os.WriteFile(filepath.Join(gitDir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Tools that drive work in worktrees create one per task, so filing each under
// its own name minted a project nothing had assigned to a vault. conclave alone
// had left twenty-odd of them.
func TestAWorktreeIsFiledUnderItsRepository(t *testing.T) {
	main := repo(t, filepath.Join(t.TempDir(), "conclave"))
	tree := worktree(t, main, filepath.Join(t.TempDir(), "conclave-149"))

	if got := ForDir(tree); got != "conclave" {
		t.Errorf("ForDir(worktree) = %q, want %q", got, "conclave")
	}
}

func TestADirectoryInsideAWorktreeResolvesTheSameWay(t *testing.T) {
	main := repo(t, filepath.Join(t.TempDir(), "conclave"))
	tree := worktree(t, main, filepath.Join(t.TempDir(), "conclave-36"))
	nested := filepath.Join(tree, "internal", "session")
	mkdirs(t, nested)

	if got := ForDir(nested); got != "conclave" {
		t.Errorf("ForDir(nested worktree dir) = %q, want %q", got, "conclave")
	}
}

// A .git file that cannot be followed must not send the walk up into an
// unrelated parent directory, which would file the work under whatever
// happened to be above it.
func TestAnUnfollowableGitFileStaysPut(t *testing.T) {
	base := filepath.Join(t.TempDir(), "outer")
	dir := filepath.Join(base, "orphan-tree")
	mkdirs(t, dir)
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: /nowhere/at/all\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := ForDir(dir); got != "orphan-tree" {
		t.Errorf("ForDir(unfollowable) = %q, want %q", got, "orphan-tree")
	}
}

// An empty working directory used to become the project ".", which is a real
// project name in the data and means nothing.
func TestAnEmptyDirectoryDoesNotBecomeDotProject(t *testing.T) {
	if got := ForDir(""); got == "." {
		t.Error(`ForDir("") returned ".", which is not a project`)
	}
}

// Nothing above should depend on where the test process happens to be running.
func TestDeepNestingStillResolvesToTheRoot(t *testing.T) {
	root := repo(t, filepath.Join(t.TempDir(), "deep"))
	nested := filepath.Join(root, "a", "b", "c", "d", "e", "f")
	mkdirs(t, nested)

	if got := ForDir(nested); got != "deep" {
		t.Errorf("ForDir(nested) = %q, want %q", got, "deep")
	}
}
