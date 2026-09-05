package httputil

import (
	"fmt"
	"net/http"

	"github.com/sinesync/cli/internal/version"
)

// SetClientHeaders adds standard sinesync client headers to an outgoing request.
func SetClientHeaders(req *http.Request) {
	req.Header.Set("X-Client-Version", version.Get())
}

// CheckUpdateRequired returns an error if the server responded with 426 Upgrade Required.
func CheckUpdateRequired(resp *http.Response) error {
	if resp.StatusCode == http.StatusUpgradeRequired {
		return fmt.Errorf("your sinesync CLI is outdated — run 'sinesync update' to upgrade")
	}
	return nil
}
