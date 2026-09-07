package licenses

import (
	"strings"
	"testing"
)

func TestEveryLinkedModuleIsAttributed(t *testing.T) {
	text := Text()

	// Shared with the generator, so the notice cannot satisfy this check while
	// still being wrong for the binaries we ship. It covers every released
	// platform, not the host: the Linux binaries link D-Bus and a Mac never
	// sees it.
	mods, err := LinkedModules("")
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
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
