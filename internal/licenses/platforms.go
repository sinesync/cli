package licenses

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// selfModulePath is this module, which needs no third-party attribution.
const selfModulePath = "github.com/sinesync/cli"

// ReleasePlatforms are the targets release.yml builds binaries for.
//
// The notice has to cover all of them, not the machine that generated it. The
// linked set genuinely differs: go-keyring reaches the Secret Service over D-Bus
// on Linux and the Keychain on macOS, so github.com/godbus/dbus/v5 ships in the
// Linux binaries and appears nowhere on a Mac. A notice generated on a Mac was
// silently missing it.
var ReleasePlatforms = []struct{ OS, Arch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

// LinkedModules names every module reachable from the binary on any released
// platform, not merely those required by go.mod and not merely those linked on
// the host.
//
// Shared by the generator and its test on purpose: if each asked the toolchain
// its own way, the notice could satisfy the check that guards it while still
// being wrong for the binaries we ship.
func LinkedModules(dir string) ([]string, error) {
	// Resolve the module root when the caller does not name one, since
	// ./cmd/... only resolves from there and getting it wrong yields an empty
	// list, which would pass a check rather than fail it.
	if dir == "" {
		out, err := exec.Command("go", "env", "GOMOD").Output()
		if err != nil {
			return nil, fmt.Errorf("locating module root: %w", err)
		}
		gomod := strings.TrimSpace(string(out))
		if gomod == "" || gomod == "/dev/null" {
			return nil, fmt.Errorf("not inside a Go module")
		}
		dir = filepath.Dir(gomod)
	}

	seen := map[string]bool{}

	for _, p := range ReleasePlatforms {
		cmd := exec.Command("go", "list", "-deps",
			"-f", "{{if .Module}}{{.Module.Path}}{{end}}", "./cmd/...")
		cmd.Dir = dir
		// CGO_ENABLED=1 is required, not optional: Go defaults it to 0 when
		// cross-listing, which excludes the cgo-gated files in sqlite-vec and
		// makes the whole listing fail. No cross-compiler is needed, because
		// `go list` resolves build constraints without compiling anything.
		cmd.Env = append(os.Environ(), "GOOS="+p.OS, "GOARCH="+p.Arch, "CGO_ENABLED=1")

		out, err := cmd.Output()
		if err != nil {
			var stderr string
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = strings.TrimSpace(string(ee.Stderr))
			}
			return nil, fmt.Errorf("listing modules for %s/%s: %w: %s", p.OS, p.Arch, err, stderr)
		}

		for _, line := range strings.Split(string(out), "\n") {
			path := strings.TrimSpace(line)
			if path == "" || path == selfModulePath {
				continue
			}
			seen[path] = true
		}
	}

	if len(seen) == 0 {
		return nil, fmt.Errorf("no linked modules found; a check built on this would pass vacuously")
	}

	mods := make([]string, 0, len(seen))
	for path := range seen {
		mods = append(mods, path)
	}
	sort.Strings(mods)
	return mods, nil
}
