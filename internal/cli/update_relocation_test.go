package cli

import (
	"path/filepath"
	"testing"
)

// pathPrecedes decides whether relocating the install is safe to do at all.
// Installing into a directory PATH consults AFTER the current one leaves the
// old binary winning every lookup, so the update would appear to do nothing.
// That is worse than needing sudo, because it is silent.
func TestPathPrecedes(t *testing.T) {
	sep := string(filepath.ListSeparator)

	cases := []struct {
		name   string
		path   string
		first  string
		second string
		want   bool
	}{
		{
			name:   "first is earlier, so relocating wins lookups",
			path:   "/home/me/.local/bin" + sep + "/usr/local/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   true,
		},
		{
			name:   "first is later, so the old binary would still win",
			path:   "/usr/local/bin" + sep + "/home/me/.local/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   false,
		},
		{
			name:   "first is absent from PATH entirely",
			path:   "/usr/local/bin" + sep + "/usr/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   false,
		},
		{
			// The current install can sit outside PATH — invoked by absolute
			// path, say — and anything on PATH then wins by default.
			name:   "second is absent, so anything on PATH precedes it",
			path:   "/home/me/.local/bin" + sep + "/usr/bin",
			first:  "/home/me/.local/bin",
			second: "/opt/weird/bin",
			want:   true,
		},
		{
			name:   "entries are compared cleaned, not textually",
			path:   "/home/me/.local/bin/" + sep + "/usr/local/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   true,
		},
		{
			name:   "neither is on PATH",
			path:   "/usr/bin",
			first:  "/a",
			second: "/b",
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			if got := pathPrecedes(tc.first, tc.second); got != tc.want {
				t.Errorf("pathPrecedes(%q, %q) with PATH=%q = %v, want %v",
					tc.first, tc.second, tc.path, got, tc.want)
			}
		})
	}
}

func TestUserBinDirIsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".local", "bin")
	if got := userBinDir(); got != want {
		t.Errorf("userBinDir() = %q, want %q", got, want)
	}
}
