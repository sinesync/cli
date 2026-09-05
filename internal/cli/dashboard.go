package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sinesync/cli/internal/browser"
	"github.com/sinesync/cli/internal/daemon"
	"github.com/spf13/cobra"
)

// requestDashboardTicket asks the daemon for a single-use ticket the browser can
// exchange for the hook secret. Minting requires the secret, which we can read
// because this process owns the 0600 file; the browser cannot, which is the
// whole reason the ticket exists.
func requestDashboardTicket(port int) (string, error) {
	secret := readHookSecret()
	if secret == "" {
		return "", fmt.Errorf("no hook secret found at %s", hookSecretPath())
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api/auth/ticket", port), bytes.NewReader(nil))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Hook-Secret", secret)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("daemon returned %s", resp.Status)
	}

	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Ticket == "" {
		return "", fmt.Errorf("daemon returned an empty ticket")
	}
	return body.Ticket, nil
}

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Open the sine~sync dashboard",
	Long: `Open the dashboard in your browser.

The daemon will be started automatically if not running.
The dashboard provides:
  - Overview statistics
  - Memory browsing and search
  - Tagging and classification
  - Project filtering

Default port: 5741 (looks like "SINE" if you squint)`,
	RunE: runDashboard,
}

func init() {
	dashboardCmd.Flags().Bool("no-browser", false, "Don't open browser automatically")
}

func runDashboard(cmd *cobra.Command, args []string) error {
	noBrowser, _ := cmd.Flags().GetBool("no-browser")

	// Ensure daemon is running
	info, err := daemon.EnsureRunning()
	if err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	base := fmt.Sprintf("http://127.0.0.1:%d", info.Port)

	// The dashboard API requires the daemon's hook secret, and the only channel
	// we have to a browser we are launching is the URL. A fragment keeps the
	// value out of the request line, access logs, and Referer headers — but the
	// URL is still handed to open/xdg-open/start as an argv element, and argv is
	// readable by every account on this machine. So the fragment carries a
	// single-use ticket rather than the secret itself: the page redeems it on
	// load, and anything scraped from argv afterwards is already spent.
	url := base
	switch ticket, err := requestDashboardTicket(info.Port); {
	case err != nil:
		fmt.Fprintf(os.Stderr, "Warning: could not obtain a dashboard ticket (%v); the dashboard will not be able to load data\n", err)
	case ticket != "":
		url = base + "/#ticket=" + ticket
	}

	fmt.Printf("Dashboard available at %s\n", base)

	// Always print the URL that actually authenticates, even when a browser is
	// being launched. Opening `base` by hand yields no token and every API call
	// returns 401, so this is the only way back in — and a successful launch is
	// not evidence the browser opened: the opener is spawned, not waited on, so
	// an xdg-open that exists but finds no display reports success and fails
	// afterwards where nothing observes it.
	//
	// Printing it unconditionally is safe precisely because it carries a ticket
	// rather than the secret: single-use, short-lived, and spent the instant the
	// page loads. The long-lived secret could not go here.
	if url != base {
		fmt.Printf("If the dashboard does not open, use this URL (single-use, expires shortly):\n  %s\n", url)
	}

	if noBrowser {
		return nil
	}

	time.Sleep(200 * time.Millisecond)
	if err := browser.Open(url); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open a browser (%v). Use the URL above.\n", err)
	}

	return nil
}
