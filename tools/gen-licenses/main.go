// Command gen-licenses assembles the third-party attribution notice that
// `sinesync licenses` prints.
//
// Several dependencies require their notices to be reproduced wherever the
// software is distributed. SQLCipher's BSD licence is the strictest of them:
// it asks for the notice in a user-accessible location, which is what the
// `licenses` command exists to be.
//
// The text is COPIED, never summarised. A licence retyped is a licence
// misquoted, so every section below is the module's own file verbatim; this
// tool only decides which files to concatenate and in what order.
//
// Modules are taken from `go list -deps` over the real binary rather than from
// go.mod, so the notice covers what actually ships and nothing else — go.mod
// lists the AWS SDK, for instance, which no code path reaches.
//
// Run it with `go generate ./internal/licenses`.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Filenames a module might use, in the order they are preferred.
var licenseNames = []string{
	"LICENSE", "LICENSE.txt", "LICENSE.md",
	"COPYING", "COPYING.txt",
	"LICENCE", "LICENCE.txt",
	"NOTICE", "NOTICE.txt",
}

const selfModule = "github.com/sinesync/cli"

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = moduleRoot
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// moduleRoot is where go.mod lives. Every go command below runs from there,
// because `go generate` invokes this from the package directory and `./cmd/...`
// means nothing from inside internal/licenses.
var moduleRoot = findModuleRoot()

func findModuleRoot() string {
	cmd := exec.Command("go", "env", "GOMOD")
	out, err := cmd.Output()
	if err != nil {
		return "."
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		return "."
	}
	return filepath.Dir(gomod)
}

// linkedModules names every module reachable from the binary, not merely
// required by it.
func linkedModules() ([]string, error) {
	out, err := run("go", "list", "-deps",
		"-f", "{{if .Module}}{{.Module.Path}}{{end}}", "./cmd/...")
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var mods []string
	for _, line := range strings.Split(out, "\n") {
		path := strings.TrimSpace(line)
		if path == "" || path == selfModule || seen[path] {
			continue
		}
		seen[path] = true
		mods = append(mods, path)
	}
	sort.Strings(mods)
	return mods, nil
}

// moduleInfo resolves where a module's source actually is, which is not where
// its path says when a replace directive is in force — go-sqlcipher is served
// from the sinesync fork, and it is the fork's notice that must be reproduced.
func moduleInfo(path string) (dir, version string) {
	dir, _ = run("go", "list", "-m", "-f", "{{.Dir}}", path)
	version, _ = run("go", "list", "-m", "-f", "{{if .Replace}}{{.Replace.Path}}@{{.Replace.Version}}{{else}}{{.Version}}{{end}}", path)
	return dir, version
}

func findLicense(dir string) (name, text string) {
	for _, candidate := range licenseNames {
		full := filepath.Join(dir, candidate)
		if body, err := os.ReadFile(full); err == nil {
			return candidate, string(body)
		}
	}
	return "", ""
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: gen-licenses <extra-notices-file> <output-file>")
		os.Exit(2)
	}
	extraPath, outPath := os.Args[1], os.Args[2]

	mods, err := linkedModules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing modules:", err)
		os.Exit(1)
	}

	var b strings.Builder
	b.WriteString("sine~sync third-party notices\n")
	b.WriteString(strings.Repeat("=", 76) + "\n\n")
	b.WriteString("This file is generated. Run `go generate ./internal/licenses` to rebuild it.\n")
	b.WriteString("Each section is the dependency's own licence file, reproduced verbatim.\n\n")

	var missing []string
	for _, mod := range mods {
		dir, version := moduleInfo(mod)
		name, text := findLicense(dir)

		b.WriteString(strings.Repeat("-", 76) + "\n")
		fmt.Fprintf(&b, "%s %s\n", mod, version)
		b.WriteString(strings.Repeat("-", 76) + "\n\n")

		if text == "" {
			missing = append(missing, mod)
			b.WriteString("No licence file is distributed with this module. Its terms are stated by\n" +
				"the upstream project; see the notice below for this component.\n\n")
			continue
		}
		fmt.Fprintf(&b, "(from %s)\n\n", name)
		b.WriteString(strings.TrimRight(text, "\n") + "\n\n")
	}

	extra, err := os.ReadFile(extraPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading extra notices:", err)
		os.Exit(1)
	}
	b.WriteString(strings.TrimRight(string(extra), "\n") + "\n")

	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "writing output:", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s: %d modules\n", outPath, len(mods))
	for _, mod := range missing {
		fmt.Printf("  no licence file in module: %s (covered by the curated notices)\n", mod)
	}
}
