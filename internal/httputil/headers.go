package httputil

import (
	"net/http"

	"github.com/miclip/sinesync/internal/version"
)

// SetClientHeaders adds standard sinesync client headers to an outgoing request.
func SetClientHeaders(req *http.Request) {
	req.Header.Set("X-Client-Version", version.Get())
}
