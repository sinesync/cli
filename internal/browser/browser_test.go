package browser

import "testing"

func TestValidateURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// The URLs this code actually opens.
		{"dashboard loopback", "http://127.0.0.1:5741", false},
		{"dashboard with ticket fragment", "http://127.0.0.1:5741/#ticket=abc123", false},
		{"saml login over https", "https://api.sinesync.ai/auth/saml/login?org=acme&clientType=cli&port=1234", false},
		{"https with encoded query", "https://example.com/a?b=c%20d&e=f", false},

		// Command-interpreter payloads. These are why `cmd /c start` was
		// replaced rather than escaped: with an interpreter in the path, each of
		// these runs a second command on Windows.
		{"ampersand chains a command", "http://127.0.0.1:5741/&calc", false},
		{"pipe chains a command", "http://127.0.0.1:5741/|calc", false},

		// Whitespace is what an argument splitter would act on, and is never
		// valid unescaped in a URL we construct.
		{"space", "http://127.0.0.1:5741/ &calc", true},
		{"tab", "http://127.0.0.1:5741/\tcalc", true},
		{"newline", "http://127.0.0.1:5741/\ncalc", true},
		{"carriage return", "http://127.0.0.1:5741/\rcalc", true},

		// Non-HTTP schemes: `open` and `xdg-open` dispatch these to whatever
		// application claims them.
		{"file scheme", "file:///etc/passwd", true},
		{"custom app scheme", "ms-msdt:/id", true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"data scheme", "data:text/html,<script>alert(1)</script>", true},
		{"ssh scheme", "ssh://host", true},

		// Malformed or incomplete.
		{"empty", "", true},
		{"no scheme", "127.0.0.1:5741", true},
		{"scheme but no host", "http://", true},
		{"bare path", "/api/projects", true},
		{"control character", "http://127.0.0.1:5741/\x00", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateURL(tc.url)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateURL(%q) = nil, want an error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateURL(%q) = %v, want nil", tc.url, err)
			}
		})
	}
}
