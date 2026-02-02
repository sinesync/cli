package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/miclip/sinesync/internal/daemon"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the sine~sync background daemon",
	Long: `The daemon runs in the background providing:
  - Dashboard web server on port 5741
  - Hook API for Claude Code integration
  - Background cloud sync

The daemon is automatically started when needed.`,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the daemon in the background",
	RunE:  runDaemonStart,
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running daemon",
	RunE:  runDaemonStop,
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check daemon status",
	RunE:  runDaemonStatus,
}

var daemonRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Run the daemon in foreground (internal use)",
	Hidden: true,
	RunE:   runDaemonForeground,
}

var daemonLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show daemon logs",
	Long:  `Tails the daemon log file. Use -f to follow, -n to specify number of lines.`,
	RunE:  runDaemonLogs,
}

func init() {
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonRunCmd)
	daemonCmd.AddCommand(daemonLogsCmd)

	daemonStartCmd.Flags().IntP("port", "p", daemon.DefaultPort, "Port to run on")
	daemonRunCmd.Flags().IntP("port", "p", daemon.DefaultPort, "Port to run on")
	daemonLogsCmd.Flags().BoolP("follow", "f", false, "Follow log output")
	daemonLogsCmd.Flags().IntP("lines", "n", 50, "Number of lines to show")
}

func runDaemonStart(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")

	// Check if already running
	if running, info := daemon.IsRunning(); running {
		fmt.Printf("Daemon already running (PID %d, port %d)\n", info.PID, info.Port)
		fmt.Printf("Dashboard: http://127.0.0.1:%d\n", info.Port)
		return nil
	}

	fmt.Println("Starting sine~sync daemon...")

	if err := daemon.Start(port); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	_, info := daemon.IsRunning()
	if info != nil {
		fmt.Printf("Daemon started (PID %d, port %d)\n", info.PID, info.Port)
		fmt.Printf("Dashboard: http://127.0.0.1:%d\n", info.Port)
	}

	return nil
}

func runDaemonStop(cmd *cobra.Command, args []string) error {
	running, info := daemon.IsRunning()
	if !running {
		fmt.Println("Daemon is not running")
		return nil
	}

	fmt.Printf("Stopping daemon (PID %d)...\n", info.PID)

	if err := daemon.Stop(); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	fmt.Println("Daemon stopped")
	return nil
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	running, info, uptime := daemon.Status()

	fmt.Println("sine~sync daemon status")
	fmt.Println("───────────────────────────────────────")

	if running {
		fmt.Printf("Status: running\n")
		fmt.Printf("PID: %d\n", info.PID)
		fmt.Printf("Port: %d\n", info.Port)
		fmt.Printf("Uptime: %s\n", uptime)
		fmt.Printf("Dashboard: http://127.0.0.1:%d\n", info.Port)
	} else {
		fmt.Println("Status: stopped")
		if info != nil {
			fmt.Printf("(stale PID file: %d)\n", info.PID)
		}
	}

	return nil
}

func runDaemonForeground(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")

	server := daemon.NewServer(port)
	return server.Run()
}

func runDaemonLogs(cmd *cobra.Command, args []string) error {
	follow, _ := cmd.Flags().GetBool("follow")
	lines, _ := cmd.Flags().GetInt("lines")

	// Find today's log file
	logFile := daemon.TodayLogFile()

	// Check if log file exists
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		fmt.Printf("No log file found at: %s\n", logFile)
		fmt.Println("The daemon may not have been started today.")
		return nil
	}

	// Use tail command
	tailArgs := []string{"-n", fmt.Sprintf("%d", lines)}
	if follow {
		tailArgs = append(tailArgs, "-f")
	}
	tailArgs = append(tailArgs, logFile)

	tailCmd := exec.Command("tail", tailArgs...)
	tailCmd.Stdout = os.Stdout
	tailCmd.Stderr = os.Stderr

	return tailCmd.Run()
}

// openBrowser opens a URL in the default browser
func openBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		return
	}

	cmd.Start()
}
