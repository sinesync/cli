package cli

import (
	"fmt"

	"github.com/sinesync/cli/internal/licenses"
	"github.com/spf13/cobra"
)

var licensesCmd = &cobra.Command{
	Use:   "licenses",
	Short: "Show third-party licences and attribution notices",
	Long: `Print the licences of everything compiled into or fetched by sinesync.

Several dependencies require their notices to be reproduced wherever the
software is distributed. SQLCipher, which encrypts the local database, asks
specifically for its notice to appear somewhere a user can reach — this command
is that place.

The notice is embedded in the binary, so it answers offline and always
describes the build it was compiled into rather than whatever the current
source tree happens to require.

  sinesync licenses            print the notices
  sinesync licenses > NOTICE   write them to a file`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := fmt.Fprint(cmd.OutOrStdout(), licenses.Text())
		return err
	},
}
