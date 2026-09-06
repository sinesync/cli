package licenses

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// linkedModules asks the toolchain what actually ships, rather than trusting a
// list written down here. A notice that has to be maintained by hand is a
// notice that goes stale the first time someone adds a dependency, and the
// failure is silent: the build still works and the attribution is simply
// wrong.
func linkedModules(t *testing.T) []string {
	t.Helper()

	root, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	dir := filepath.Dir(strings.TrimSpace(string(root)))

	cmd := exec.Command("go", "list", "-deps",
		"-f", "{{if .Module}}{{.Module.Path}}{{end}}", "./cmd/...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("listing linked modules: %v", err)
	}

	seen := map[string]bool{}
	var mods []string
	for _, line := range strings.Split(string(out), "\n") {
		path := strings.TrimSpace(line)
		if path == "" || path == "github.com/sinesync/cli" || seen[path] {
			continue
		}
		seen[path] = true
		mods = append(mods, path)
	}
	return mods
}

func TestEveryLinkedModuleIsAttributed(t *testing.T) {
	text := Text()

	mods := linkedModules(t)
	if len(mods) == 0 {
		t.Fatal("no linked modules found; the check would pass vacuously")
	}

	for _, mod := range mods {
		if !strings.Contains(text, mod) {
			t.Errorf("%s is compiled into the binary but has no section in the notice.\n"+
				"Run `go generate ./internal/licenses` to rebuild it.", mod)
		}
	}
}

// SQLCipher's BSD licence asks for its notice in a user-accessible location,
// and `sinesync licenses` is the only such location. This asserts the specific
// obligation rather than only the general one, because it is the reason the
// command exists and the reason it must not quietly lose the section.
func TestSQLCipherNoticeIsReproduced(t *testing.T) {
	text := Text()

	for _, required := range []string{
		"ZETETIC LLC",
		"Redistribution and use in source and binary forms",
		"github.com/mutecomm/go-sqlcipher",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("the SQLCipher notice is incomplete: %q is missing", required)
		}
	}
}

// The generator marks a module that ships no licence file, and the curated
// notices then have to cover it by name. Without this, such a module would
// satisfy the attribution check above by appearing only as an empty heading.
func TestModulesWithoutLicenceFilesAreCoveredByName(t *testing.T) {
	text := Text()

	if !strings.Contains(text, "No licence file is distributed with this module") {
		t.Skip("every linked module currently ships a licence file")
	}

	if !strings.Contains(text, "Components that are not Go modules") {
		t.Error("a module ships no licence file, but the curated notices section is absent")
	}
	if !strings.Contains(text, "sqlite-vec") {
		t.Error("sqlite-vec ships no licence file and is not covered by name in the notices")
	}
}
