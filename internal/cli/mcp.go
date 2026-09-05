package cli

import (
	"github.com/sinesync/cli/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server commands",
}

func init() {
	mcpCmd.AddCommand(mcpStartCmd)
}

var mcpStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start MCP server (used by Claude Code)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return mcp.StartServer()
	},
}
