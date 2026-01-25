package cli

import (
	"fmt"
	"time"

	"github.com/miclip/sinesync/internal/daemon"
	"github.com/spf13/cobra"
)

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

	url := fmt.Sprintf("http://127.0.0.1:%d", info.Port)
	fmt.Printf("Dashboard available at %s\n", url)

	if !noBrowser {
		time.Sleep(200 * time.Millisecond)
		openBrowser(url)
	}

	return nil
}
