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
	"strings"

	"github.com/miclip/sinesync/internal/crypto"
	"github.com/miclip/sinesync/internal/encryption"
	"github.com/miclip/sinesync/internal/httputil"
	"github.com/miclip/sinesync/internal/keychain"
	"github.com/spf13/cobra"
)

// pendingApprovalRequest is a unified type for both device-link and SSO recovery requests.
type pendingApprovalRequest struct {
	ID            string
	DeviceName    string
	Platform      string // device-link only
	RequestType   string // "device-link" or "sso-recovery"
	TempPublicKey string // sso-recovery only
}

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Manage devices",
}

var deviceApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a new device for encryption key transfer",
	Long: `Approve a pending device approval request.

This command handles two types of requests:

  1. Device linking (6-digit code): When a new device logs in via SSO and
     shows a 6-digit linking code, run this command and enter the code to
     transfer encryption keys securely.

  2. SSO device recovery: When you log in on a new device and request
     encryption keys for your account via SSO recovery, run this command
     on one of your existing devices to approve the transfer.

Run this command on an existing device that already has encryption keys.`,
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

// fetchPendingDeviceLinkRequests returns pending device link requests.
func fetchPendingDeviceLinkRequests(apiBase, token string) ([]pendingApprovalRequest, error) {
	req, err := http.NewRequest("GET", apiBase+"/device-link/pending", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch device-link requests: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device-link pending returned %d: %s", resp.StatusCode, string(body))
	}

	var pendingResp struct {
		Requests []struct {
			ID         string `json:"id"`
			DeviceName string `json:"deviceName"`
			Platform   string `json:"platform"`
		} `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pendingResp); err != nil {
		return nil, fmt.Errorf("decode device-link response: %w", err)
	}

	var results []pendingApprovalRequest
	for _, r := range pendingResp.Requests {
		results = append(results, pendingApprovalRequest{
			ID:          r.ID,
			DeviceName:  r.DeviceName,
			Platform:    r.Platform,
			RequestType: "device-link",
		})
	}
	return results, nil
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

// approveDeviceLinkRequest approves a device link request using a 6-digit code.
func approveDeviceLinkRequest(apiBase, token string, req pendingApprovalRequest, bundleJSON []byte, reader *bufio.Reader) error {
	fmt.Print("Enter the 6-digit code shown on the new device: ")
	codeInput, _ := reader.ReadString('\n')
	code := strings.TrimSpace(strings.ReplaceAll(codeInput, "-", ""))

	if len(code) != 6 {
		return fmt.Errorf("invalid code — must be 6 digits")
	}

	transferSalt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate transfer salt: %w", err)
	}
	transferKey := crypto.DeriveKeyFromCode(code, transferSalt)

	encryptedTransfer, err := encryption.EncryptForDeviceLink(bundleJSON, transferKey)
	if err != nil {
		return fmt.Errorf("encrypt for transfer: %w", err)
	}

	approveBody, _ := json.Marshal(map[string]string{
		"code":            code,
		"encryptedBundle": base64.StdEncoding.EncodeToString(encryptedTransfer),
		"transferSalt":    base64.StdEncoding.EncodeToString(transferSalt),
	})

	approveReq, err := http.NewRequest("POST",
		fmt.Sprintf("%s/device-link/%s/approve", apiBase, req.ID),
		bytes.NewReader(approveBody))
	if err != nil {
		return err
	}
	approveReq.Header.Set("Content-Type", "application/json")
	approveReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(approveReq)

	approveResp, err := authHTTPClient.Do(approveReq)
	if err != nil {
		return fmt.Errorf("approve request: %w", err)
	}
	defer approveResp.Body.Close()

	if approveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approveResp.Body)
		return fmt.Errorf("approve failed: %d - %s", approveResp.StatusCode, string(body))
	}

	return nil
}

// approveSSORecoveryRequest approves an SSO recovery request using X25519 sealing.
func approveSSORecoveryRequest(apiBase, token string, req pendingApprovalRequest, bundleJSON []byte) error {
	sealed, err := crypto.X25519Seal(bundleJSON, req.TempPublicKey)
	if err != nil {
		return fmt.Errorf("seal bundle: %w", err)
	}

	approveBody, _ := json.Marshal(map[string]string{
		"encryptedBundle": sealed,
	})

	approveReq, err := http.NewRequest("PATCH",
		fmt.Sprintf("%s/sso/credentials/recovery/%s", apiBase, req.ID),
		bytes.NewReader(approveBody))
	if err != nil {
		return err
	}
	approveReq.Header.Set("Content-Type", "application/json")
	approveReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(approveReq)

	approveResp, err := authHTTPClient.Do(approveReq)
	if err != nil {
		return fmt.Errorf("approve request: %w", err)
	}
	defer approveResp.Body.Close()

	if approveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approveResp.Body)
		return fmt.Errorf("approve failed: %d - %s", approveResp.StatusCode, string(body))
	}

	return nil
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

	// Fetch both types of pending requests
	var allRequests []pendingApprovalRequest

	linkReqs, linkErr := fetchPendingDeviceLinkRequests(apiBase, token)
	if linkErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not check device-link requests: %v\n", linkErr)
	} else {
		allRequests = append(allRequests, linkReqs...)
	}

	ssoReqs, ssoErr := fetchPendingSSORecoveries(apiBase, token)
	if ssoErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not check SSO recovery requests: %v\n", ssoErr)
	} else {
		allRequests = append(allRequests, ssoReqs...)
	}

	if linkErr != nil && ssoErr != nil {
		return fmt.Errorf("failed to fetch pending requests — check your connection and try again")
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
		label := "device-link"
		if selected.RequestType == "sso-recovery" {
			label = "recovery"
		}
		if selected.Platform != "" {
			fmt.Printf("New device '%s' (%s) is requesting access [%s].\n", selected.DeviceName, selected.Platform, label)
		} else {
			fmt.Printf("New device '%s' is requesting access [%s].\n", selected.DeviceName, label)
		}
	} else {
		fmt.Printf("%d devices are requesting access:\n", len(allRequests))
		for i, r := range allRequests {
			label := "device-link"
			if r.RequestType == "sso-recovery" {
				label = "recovery"
			}
			if r.Platform != "" {
				fmt.Printf("  %d. '%s' (%s) [%s]\n", i+1, r.DeviceName, r.Platform, label)
			} else {
				fmt.Printf("  %d. '%s' [%s]\n", i+1, r.DeviceName, label)
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
	switch selected.RequestType {
	case "device-link":
		if err := approveDeviceLinkRequest(apiBase, token, selected, bundleJSON, reader); err != nil {
			return err
		}
	case "sso-recovery":
		if err := approveSSORecoveryRequest(apiBase, token, selected, bundleJSON); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown request type: %s", selected.RequestType)
	}

	fmt.Println("✓ Device approved! The new device should now have access.")
	return nil
}
