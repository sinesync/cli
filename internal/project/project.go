// Package project decides which project an observation belongs to.
//
// The answer used to be filepath.Base of the working directory, computed
// independently at eight call sites. That made a project's identity depend on
// which directory a session happened to start in: work in the same repository
// was filed under `backend`, `cli`, `web`, `shared`, `infra`, `docs` and
// `src` depending on where the shell was, and only work started at the
// repository root carried the repository's own name.
//
// That matters beyond tidiness, because project is what routes an observation
// to a vault. Assigning a project to a vault shared with someone routed only
// the directory whose basename matched it; every subdirectory of the same
// repository quietly went to the default vault instead.
//
// It also collided. Basenames like `docs`, `src`, `tests`, `server`, `client`,
// `data`, `build` and `web` are not distinctive, so two unrelated
// repositories with a `web/` directory were one project — and therefore one
// vault, shared with whoever that vault was shared with.
//
// The repository root is the unit people mean by "project": it does not change
// when you cd into a subdirectory, and it survives the directory being moved.
package project

import (
	"os"
	"path/filepath"
)

// ForDir names the project a directory belongs to: the basename of the git
// repository containing it, or the directory's own basename when it is not in
// a repository.
//
// The basename rather than the full path, because that is what every existing
// observation already carries and what vault assignments are written against —
// a repository at /Users/me/code/sinesync stays the project `sinesync`, so no
// history is orphaned and no assignment stops matching.
//
// A worktree counts as its own repository. Its .git is a file rather than a
// directory, and treating it as a root keeps a worktree filed under its own
// name, which is how they are used here.
func ForDir(dir string) string {
	if dir == "" {
		// An empty working directory used to become the project ".", which is
		// a real project name in the data and means nothing.
		cwd, err := os.Getwd()
		if err != nil {
			return ""
		}
		dir = cwd
	}

	if root := repoRoot(dir); root != "" {
		return filepath.Base(root)
	}
	return filepath.Base(dir)
}

// repoRoot walks up looking for .git, and returns "" if it reaches the
// filesystem root without finding one.
func repoRoot(dir string) string {
	dir = filepath.Clean(dir)

	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// filepath.Dir is its own fixed point at the root.
			return ""
		}
		dir = parent
	}
}
