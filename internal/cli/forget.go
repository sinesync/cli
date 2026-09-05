package cli

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sinesync/cli/internal/daemon"
	"github.com/spf13/cobra"
)

// The dashboard's delete button runs on a scoped session token, which is
// deliberately refused for DELETE — see requireDashboardAuth. That refusal only
// makes sense if there is another way to remove an observation, so this is it:
// the CLI reads the 0600 hook secret directly, which no browser and no
// process-listing attacker can.
var forgetCmd = &cobra.Command{
	Use:     "forget <observation-id>",
	Aliases: []string{"rm"},
	Short:   "Delete an observation",
	Long: `Delete an observation by ID.

Deletion propagates: the observation is removed locally and marked for deletion
in the cloud, so it disappears from every device on the next sync. This cannot
be undone.

The dashboard cannot delete. It runs on a scoped session token that is refused
for destructive operations, because that token is handed to the browser through
a URL and URLs are visible to other accounts on this machine. Deleting requires
the daemon's hook secret, which only this CLI can read.`,
	Args: cobra.ExactArgs(1),
	RunE: runForget,
}

func init() {
	forgetCmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt")
	rootCmd.AddCommand(forgetCmd)
}

func runForget(cmd *cobra.Command, args []string) error {
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("observation id is required")
	}

	info, err := daemon.EnsureRunning()
	if err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	if skip, _ := cmd.Flags().GetBool("yes"); !skip {
		fmt.Printf("Delete observation %s? This removes it from every synced device and cannot be undone. [y/N]: ", id)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
		default:
			fmt.Println("Cancelled.")
			return nil
		}
	}

	req, err := authedRequest(
		http.MethodDelete,
		fmt.Sprintf("http://127.0.0.1:%d/api/observations/%s", info.Port, id),
		nil,
	)
	if err != nil {
		return err
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the daemon: %w", err)
	}
	defer resp.Body.Close()

	if hookAuthError(resp, "forget") {
		return fmt.Errorf("daemon rejected the hook secret")
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		fmt.Printf("Deleted %s\n", id)
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("no observation with id %s", id)
	default:
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
}
