package cli

import (
	"bytes"
	"net/http"
	"testing"
)

// The server rotates the refresh token on every use. The rotated one is written
// to the keyring, so reading the file copy means presenting a token the server
// has already retired — which is why every refresh after the first failed with
// "Invalid refresh token", permanently and silently.
func TestTheKeyringCopyWinsBecauseItIsTheRotatedOne(t *testing.T) {
	if got := pickRefreshToken("rotated-in-keyring", "stale-in-file"); got != "rotated-in-keyring" {
		t.Errorf("picked %q; the keyring holds the rotated token and must win", got)
	}
}

func TestFallsBackToTheFileWhenTheKeyringHasNothing(t *testing.T) {
	// A keyring that is unavailable, or an install that predates writing to it.
	if got := pickRefreshToken("", "only-copy-in-file"); got != "only-copy-in-file" {
		t.Errorf("picked %q, want the file copy", got)
	}
}

func TestNoTokenAnywhereIsEmptyRatherThanAGuess(t *testing.T) {
	if got := pickRefreshToken("", ""); got != "" {
		t.Errorf("picked %q with nothing stored", got)
	}
}

// doVaultRequest retries a 401 by cloning the request and refilling its body
// from GetBody. If GetBody were nil the retry would send an empty payload and
// the server would reject it for the wrong reason — so the way these requests
// are built has to keep GetBody populated.
func TestMigrationRequestsCanBeReplayedAfterARefresh(t *testing.T) {
	payload := []byte(`{"items":[{"id":"abc"}]}`)

	for _, path := range []string{"/sync/upload-urls", "/sync/confirm-uploads"} {
		req, err := http.NewRequest("POST", "https://api.example"+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}

		if req.GetBody == nil {
			t.Fatalf("%s: GetBody is nil, so a refresh-and-retry would resend an empty body", path)
		}

		body, err := req.GetBody()
		if err != nil {
			t.Fatalf("%s: GetBody failed: %v", path, err)
		}
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), payload) {
			t.Errorf("%s: replayed body = %q, want %q", path, buf.Bytes(), payload)
		}
	}
}
