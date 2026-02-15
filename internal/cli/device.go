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

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Manage devices",
}

var deviceApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a new device for SSO encryption",
	Long: `Approve a pending device link request from a new device.

When a new device logs in via SSO, it shows a 6-digit linking code.
Run this command on an existing device and enter the code to transfer
encryption keys securely.`,
	RunE: runDeviceApprove,
}

func init() {
	deviceCmd.AddCommand(deviceApproveCmd)
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

	// 1. Fetch pending device link requests
	req, err := http.NewRequest("GET", apiBase+"/device-link/pending", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch pending requests: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(os.Stdin)

	var pendingResp struct {
		Requests []struct {
			ID         string `json:"id"`
			DeviceName string `json:"deviceName"`
			Platform   string `json:"platform"`
			CreatedAt  string `json:"createdAt"`
			ExpiresAt  string `json:"expiresAt"`
		} `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pendingResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if len(pendingResp.Requests) == 0 {
		fmt.Println("No pending device link requests.")
		return nil
	}

	// 2. Show pending requests and let user choose if multiple
	var linkReq struct {
		ID         string `json:"id"`
		DeviceName string `json:"deviceName"`
		Platform   string `json:"platform"`
		CreatedAt  string `json:"createdAt"`
		ExpiresAt  string `json:"expiresAt"`
	}

	if len(pendingResp.Requests) == 1 {
		linkReq = pendingResp.Requests[0]
		fmt.Printf("New device '%s' (%s) is requesting access.\n", linkReq.DeviceName, linkReq.Platform)
	} else {
		fmt.Printf("%d devices are requesting access:\n", len(pendingResp.Requests))
		for i, r := range pendingResp.Requests {
			fmt.Printf("  %d. '%s' (%s)\n", i+1, r.DeviceName, r.Platform)
		}
		fmt.Print("\nSelect device number: ")
		var choice int
		if _, err := fmt.Fscan(reader, &choice); err != nil || choice < 1 || choice > len(pendingResp.Requests) {
			return fmt.Errorf("invalid selection")
		}
		reader.ReadString('\n') // consume trailing newline
		linkReq = pendingResp.Requests[choice-1]
		fmt.Printf("Approving '%s' (%s).\n", linkReq.DeviceName, linkReq.Platform)
	}
	fmt.Println()

	// 3. Prompt for code
	fmt.Print("Enter the 6-digit code shown on the new device: ")
	codeInput, _ := reader.ReadString('\n')
	code := strings.TrimSpace(strings.ReplaceAll(codeInput, "-", ""))

	if len(code) != 6 {
		return fmt.Errorf("invalid code — must be 6 digits")
	}

	// 4. Load own device key from keychain
	deviceKey, err := keychain.GetDeviceKey()
	if err != nil {
		return fmt.Errorf("no device key in keychain — this device may not have SSO encryption set up")
	}

	// 5. Download + decrypt own credential bundle
	bundleReq, err := http.NewRequest("GET", apiBase+"/sso/credentials/bundle", nil)
	if err != nil {
		return err
	}
	bundleReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(bundleReq)

	bundleResp, err := authHTTPClient.Do(bundleReq)
	if err != nil {
		return fmt.Errorf("fetch bundle: %w", err)
	}
	defer bundleResp.Body.Close()

	if bundleResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(bundleResp.Body)
		return fmt.Errorf("fetch bundle failed: %d - %s", bundleResp.StatusCode, string(body))
	}

	var myBundle struct {
		EncryptedBundle string `json:"encryptedBundle"`
	}
	if err := json.NewDecoder(bundleResp.Body).Decode(&myBundle); err != nil {
		return fmt.Errorf("parse bundle response: %w", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(myBundle.EncryptedBundle)
	if err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}

	bundleJSON, err := encryption.DecryptCredentialBundle(encryptedBytes, deviceKey)
	if err != nil {
		return fmt.Errorf("decrypt own bundle: %w", err)
	}

	// 6. Generate transfer salt and derive transfer key
	transferSalt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate transfer salt: %w", err)
	}
	transferKey := crypto.DeriveKeyFromCode(code, transferSalt)

	// 7. Encrypt bundle with transfer key
	encryptedTransfer, err := encryption.EncryptForDeviceLink(bundleJSON, transferKey)
	if err != nil {
		return fmt.Errorf("encrypt for transfer: %w", err)
	}

	// 8. Approve the request
	approveBody, _ := json.Marshal(map[string]string{
		"code":            code,
		"encryptedBundle": base64.StdEncoding.EncodeToString(encryptedTransfer),
		"transferSalt":    base64.StdEncoding.EncodeToString(transferSalt),
	})

	approveReq, err := http.NewRequest("POST",
		fmt.Sprintf("%s/device-link/%s/approve", apiBase, linkReq.ID),
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

	fmt.Println("✓ Device approved! The new device should now have access.")
	return nil
}
