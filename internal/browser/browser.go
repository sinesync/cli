package browser

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

// Opening a URL in the user's browser is a small operation with two sharp edges,
// so it lives in one place rather than being reimplemented per call site.
//
// The first edge is Windows. `cmd /c start <url>` runs the URL through the
// command interpreter, where & and | separate commands — so a URL carrying
// `&calc` launches a program. That is reachable: the SAML login URL embeds an
// org slug taken from the server's discovery response, so a hostile or
// compromised server chooses part of the string. rundll32 hands the URL to the
// shell's protocol handler as a single argument with no interpreter in between,
// which removes the class rather than trying to escape it.
//
// The second edge is the scheme. `open` on macOS and `xdg-open` on Linux will
// happily dispatch file:// or a registered application scheme, so a value that
// reaches here from a server response could invoke something other than a
// browser. Only http and https are accepted.

// validateBrowserURL reports why rawURL must not be handed to a URL opener, or
// nil if it is safe. Split out from openURL so the rules are testable without
// launching anything.
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("refusing to open an empty URL")
	}
	// url.Parse rejects ASCII control characters, but not a bare space, and a
	// space is the separator an argument-splitting opener would act on.
	if strings.ContainsAny(rawURL, " \t\r\n") {
		return fmt.Errorf("refusing to open a URL containing whitespace")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("refusing to open a malformed URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("refusing to open a URL with scheme %q; only http and https are allowed", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("refusing to open a URL with no host")
	}
	return nil
}

// openURL opens rawURL in the user's default browser.
func Open(rawURL string) error {
	if err := ValidateURL(rawURL); err != nil {
		return err
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "linux":
		cmd = exec.Command("xdg-open", rawURL)
	case "windows":
		// Deliberately not `cmd /c start` — see the note above.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		return fmt.Errorf("unsupported platform %q", runtime.GOOS)
	}
	return cmd.Start()
}
