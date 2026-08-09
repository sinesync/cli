package cli

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/miclip/sinesync/internal/crypto"
	"github.com/miclip/sinesync/internal/encryption"
	"github.com/miclip/sinesync/internal/httputil"
	"github.com/miclip/sinesync/internal/keychain"
	"github.com/spf13/cobra"
)

// pendingApprovalRequest is a device waiting to be granted encryption keys.
type pendingApprovalRequest struct {
	ID            string
	DeviceName    string
	Platform      string
	RequestType   string // currently only "sso-recovery"
	TempPublicKey string // the ephemeral key the bundle is sealed to
}

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Manage devices",
}

var deviceApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a new device for encryption key transfer",
	Long: `Approve a pending device approval request.

When you log in on a new device as an SSO user, that device generates an
ephemeral keypair and waits for approval. Run this command on a device that
already has your encryption keys to seal the credential bundle to the new
device's public key.

The bundle is sealed with X25519, so it is not readable in transit and the
server is not given key material it can derive anything from.

Because the public key you seal to is relayed by the server, both devices show a
short fingerprint of it. Compare them before approving: if a compromised server
had substituted its own key in order to read your credentials, the two would not
match. Decline if they differ.`,
	RunE: runDeviceApprove,
}

func init() {
	deviceCmd.AddCommand(deviceApproveCmd)
}

// loadDecryptedCredentialBundle fetches and decrypts the credential bundle using the device key.
func loadDecryptedCredentialBundle(apiBase, token string) ([]byte, error) {
	deviceKey, err := keychain.GetDeviceKey()
	if err != nil {
		return nil, fmt.Errorf("no device key in keychain — this device may not have SSO encryption set up")
	}

	bundleReq, err := http.NewRequest("GET", apiBase+"/sso/credentials/bundle", nil)
	if err != nil {
		return nil, err
	}
	bundleReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(bundleReq)

	bundleResp, err := authHTTPClient.Do(bundleReq)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	defer bundleResp.Body.Close()

	if bundleResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(bundleResp.Body)
		return nil, fmt.Errorf("fetch bundle failed: %d - %s", bundleResp.StatusCode, string(body))
	}

	var myBundle struct {
		EncryptedBundle string `json:"encryptedBundle"`
	}
	if err := json.NewDecoder(bundleResp.Body).Decode(&myBundle); err != nil {
		return nil, fmt.Errorf("parse bundle response: %w", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(myBundle.EncryptedBundle)
	if err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}

	bundleJSON, err := encryption.DecryptCredentialBundle(encryptedBytes, deviceKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt own bundle: %w", err)
	}

	return bundleJSON, nil
}

// fetchPendingSSORecoveries returns pending SSO recovery requests.
func fetchPendingSSORecoveries(apiBase, token string) ([]pendingApprovalRequest, error) {
	req, err := http.NewRequest("GET", apiBase+"/sso/credentials/recovery/pending", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch SSO recovery requests: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SSO recovery pending returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Recoveries []struct {
			ID            string `json:"id"`
			DeviceName    string `json:"deviceName"`
			TempPublicKey string `json:"tempPublicKey"`
		} `json:"recoveries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode SSO recovery response: %w", err)
	}

	var results []pendingApprovalRequest
	for _, r := range result.Recoveries {
		results = append(results, pendingApprovalRequest{
			ID:            r.ID,
			DeviceName:    r.DeviceName,
			RequestType:   "sso-recovery",
			TempPublicKey: r.TempPublicKey,
		})
	}
	return results, nil
}

// approveSSORecoveryRequest approves an SSO recovery request using X25519 sealing.
//
// The public key sealed to is relayed by the server, so approving blind would
// let a compromised server substitute its own key and read the credential
// bundle. The fingerprint check below is the only thing standing between that
// and the product's zero-knowledge claim, so it is a hard stop rather than a
// warning: declining costs a retry, approving the wrong key costs the account.
func approveSSORecoveryRequest(apiBase, token string, req pendingApprovalRequest, bundleJSON []byte, reader *bufio.Reader) (approved bool, err error) {
	fingerprint, err := crypto.KeyFingerprint(req.TempPublicKey)
	if err != nil {
		return false, fmt.Errorf("the requesting device sent an unusable public key (%w); refusing to seal your credentials to it", err)
	}

	// Not shown before the prompt. The requesting device prints the fingerprint
	// of the key it generated; this one holds the fingerprint of the key the
	// SERVER relayed. Displaying ours first would let the operator type it back
	// off this screen and never look at the other device at all.
	ok := confirmFingerprintByTyping(os.Stdout, reader, fingerprint, fingerprintPromptText{
		intro: []string{
			fmt.Sprintf("The device '%s' is showing a key fingerprint on its own screen.", req.DeviceName),
			"Read it from that device — not from anything this one has told you.",
			"Then type it in exactly. Case, dashes and spaces do not matter.",
		},
		label:    "Fingerprint shown on the requesting device: ",
		declined: []string{"Declined. Nothing was sent."},
		mismatchHint: []string{
			"A fingerprint that does not match means the key this server relayed is not the one",
			"that device generated — the request did not come from your device, or not intact.",
			"Do not retry until you know why.",
		},
	})
	if !ok {
		return false, nil
	}

	sealed, err := crypto.X25519Seal(bundleJSON, req.TempPublicKey)
	if err != nil {
		return false, fmt.Errorf("seal bundle: %w", err)
	}

	approveBody, _ := json.Marshal(map[string]string{
		"encryptedBundle": sealed,
	})

	approveReq, err := http.NewRequest("PATCH",
		fmt.Sprintf("%s/sso/credentials/recovery/%s", apiBase, req.ID),
		bytes.NewReader(approveBody))
	if err != nil {
		return false, err
	}
	approveReq.Header.Set("Content-Type", "application/json")
	approveReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(approveReq)

	approveResp, err := authHTTPClient.Do(approveReq)
	if err != nil {
		return false, fmt.Errorf("approve request: %w", err)
	}
	defer approveResp.Body.Close()

	if approveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approveResp.Body)
		return false, fmt.Errorf("approve failed: %d - %s", approveResp.StatusCode, string(body))
	}

	return true, nil
}

func runDeviceApprove(cmd *cobra.Command, args []string) error {
	authCfg, err := loadAuthConfig()
	if err != nil || authCfg == nil {
		return fmt.Errorf("not logged in — run 'sinesync login' first")
	}

	apiBase := getAPIBase()
	token := authCfg.DeviceToken
	if token == "" {
		token = authCfg.Token
	}

	allRequests, err := fetchPendingSSORecoveries(apiBase, token)
	if err != nil {
		return fmt.Errorf("failed to fetch pending requests — check your connection and try again: %w", err)
	}

	if len(allRequests) == 0 {
		fmt.Println("No pending device approval requests.")
		return nil
	}

	reader := bufio.NewReader(os.Stdin)

	// Select request
	var selected pendingApprovalRequest
	if len(allRequests) == 1 {
		selected = allRequests[0]
		if selected.Platform != "" {
			fmt.Printf("New device '%s' (%s) is requesting access recovery].\n", selected.DeviceName, selected.Platform)
		} else {
			fmt.Printf("New device '%s' is requesting access recovery].\n", selected.DeviceName)
		}
	} else {
		fmt.Printf("%d devices are requesting access:\n", len(allRequests))
		for i, r := range allRequests {
			if r.Platform != "" {
				fmt.Printf("  %d. '%s' (%s) recovery]\n", i+1, r.DeviceName, r.Platform)
			} else {
				fmt.Printf("  %d. '%s' recovery]\n", i+1, r.DeviceName)
			}
		}
		fmt.Print("\nSelect device number: ")
		var choice int
		if _, err := fmt.Fscan(reader, &choice); err != nil || choice < 1 || choice > len(allRequests) {
			return fmt.Errorf("invalid selection")
		}
		reader.ReadString('\n') // consume trailing newline
		selected = allRequests[choice-1]
		fmt.Printf("Approving '%s'.\n", selected.DeviceName)
	}
	fmt.Println()

	// Load decrypted credential bundle
	bundleJSON, err := loadDecryptedCredentialBundle(apiBase, token)
	if err != nil {
		return err
	}

	// Dispatch based on request type
	var approved bool
	switch selected.RequestType {
	case "sso-recovery":
		approved, err = approveSSORecoveryRequest(apiBase, token, selected, bundleJSON, reader)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown request type: %s", selected.RequestType)
	}

	// A decline is the security-critical outcome. Reporting it as success would
	// tell the user the suspicious key was rejected AND handled, while the
	// request stays pending and the other device keeps polling for approval.
	if !approved {
		fmt.Println("The request is still pending. It will expire on its own, or you can approve it later.")
		return nil
	}

	fmt.Println("✓ Device approved! The new device should now have access.")
	return nil
}
