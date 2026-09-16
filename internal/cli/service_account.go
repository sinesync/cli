// ABOUTME: `sinesync admin service-account` — create, list and revoke the
// ABOUTME: credentials a self-hosted export daemon authenticates with.

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ServiceAccountView mirrors the server's view of a service account. The secret
// is deliberately absent: it exists only in the creation response.
type ServiceAccountView struct {
	ID        string   `json:"id"`
	KeyID     string   `json:"keyId"`
	Label     string   `json:"label"`
	VaultIDs  []string `json:"vaultIds"`
	CreatedAt string   `json:"createdAt"`
	CreatedBy string   `json:"createdBy"`
	RevokedAt string   `json:"revokedAt,omitempty"`
}

type createServiceAccountResponse struct {
	ServiceAccount ServiceAccountView `json:"serviceAccount"`
	Secret         string             `json:"secret"`
}

var (
	saLabel    string
	saVaultIDs []string
	saAllVault bool
)

var adminServiceAccountCmd = &cobra.Command{
	Use:   "service-account",
	Short: "Manage service accounts for self-hosted export",
	Long: `Create, list and revoke the credentials a self-hosted export daemon uses.

A service account is scoped to the vaults named when it is created, and grants
API access only. It cannot decrypt anything on its own: the daemon also needs the
organization key, exported separately with 'sinesync admin export-key'. That
split is the point — revoking the token stops the daemon reaching the API without
touching the key, and losing the key file does not grant access.`,
}

var adminServiceAccountCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a service account and print its credentials once",
	RunE:  runServiceAccountCreate,
}

var adminServiceAccountListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the organization's service accounts",
	RunE:  runServiceAccountList,
}

var adminServiceAccountRevokeCmd = &cobra.Command{
	Use:   "revoke <key-id>",
	Short: "Revoke a service account by its key id",
	Args:  cobra.ExactArgs(1),
	RunE:  runServiceAccountRevoke,
}

func init() {
	adminServiceAccountCreateCmd.Flags().StringVar(&saLabel, "label", "", "what this daemon is, for the audit trail (required)")
	adminServiceAccountCreateCmd.Flags().StringSliceVar(&saVaultIDs, "vault", nil, "vault id to grant; repeat for several")
	adminServiceAccountCreateCmd.Flags().BoolVar(&saAllVault, "all-vaults", false, "grant every org vault that exists right now")

	adminServiceAccountCmd.AddCommand(adminServiceAccountCreateCmd)
	adminServiceAccountCmd.AddCommand(adminServiceAccountListCmd)
	adminServiceAccountCmd.AddCommand(adminServiceAccountRevokeCmd)
	adminCmd.AddCommand(adminServiceAccountCmd)
}

// roleMayManageServiceAccounts is split out to be testable without a server.
// Owner only, matching requireOrgOwner on the route: an admin can already reach
// org vaults, but minting a credential that leaves our infrastructure is a
// narrower decision than administering the org.
func roleMayManageServiceAccounts(role string) bool {
	return role == "owner"
}

// ownerOrgInfo resolves the caller's org and refuses anyone who is not its
// owner. The server enforces this too; failing here means a clearer message than
// a 403, and no half-finished work.
func ownerOrgInfo() (string, *OrgInfo, error) {
	token, err := getAuthTokenForVault()
	if err != nil {
		return "", nil, fmt.Errorf("not logged in: %w", err)
	}
	orgInfo, err := fetchUserOrgInfo(token)
	if err != nil || orgInfo == nil {
		return "", nil, fmt.Errorf("you are not in an organization")
	}
	if !roleMayManageServiceAccounts(orgInfo.Role) {
		return "", nil, fmt.Errorf("only the organization owner can manage service accounts (your role: %s)", orgInfo.Role)
	}
	return token, orgInfo, nil
}

func serviceAccountRequest(method, path string, body any) (*http.Response, error) {
	token, orgInfo, err := ownerOrgInfo()
	if err != nil {
		return nil, err
	}

	var rdr io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(encoded)
	}

	url := getAPIBase() + "/organizations/" + orgInfo.OrgID + "/service-accounts" + path
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return doVaultRequest(&http.Client{Timeout: 15 * time.Second}, req, &token)
}

func runServiceAccountCreate(cmd *cobra.Command, args []string) error {
	if saLabel == "" {
		return fmt.Errorf("--label is required: it is what identifies this daemon when you come to revoke it")
	}
	if len(saVaultIDs) == 0 && !saAllVault {
		return fmt.Errorf("name the vaults with --vault, or pass --all-vaults\n\nRun 'sinesync admin service-account list' to see existing accounts, or\n'sinesync vault list' for vault ids")
	}
	if len(saVaultIDs) > 0 && saAllVault {
		return fmt.Errorf("--vault and --all-vaults are mutually exclusive")
	}

	vaultIDs := saVaultIDs
	if saAllVault {
		token, orgInfo, err := ownerOrgInfo()
		if err != nil {
			return err
		}
		vaults, err := fetchOrgVaults(token, orgInfo.OrgID)
		if err != nil {
			return err
		}
		for _, v := range vaults {
			vaultIDs = append(vaultIDs, v.ID)
		}
		if len(vaultIDs) == 0 {
			return fmt.Errorf("this organization has no vaults to grant")
		}
		// Said out loud because --all-vaults is a snapshot, not a rule: a vault
		// created tomorrow is not in this account, by design.
		fmt.Printf("Granting the %d vault(s) that exist now:\n", len(vaultIDs))
		for _, v := range vaults {
			fmt.Printf("  %s  %s\n", v.ID, v.Name)
		}
		fmt.Println()
	}

	resp, err := serviceAccountRequest(http.MethodPost, "", map[string]any{
		"label":    saLabel,
		"vaultIds": vaultIDs,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("creating service account failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out createServiceAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	// Printed to stdout rather than written to a file: the secret belongs in the
	// operator's own secret store, and a file here would be one more copy to
	// forget about. It is not retrievable afterwards.
	fmt.Println()
	fmt.Println("Service account created. The secret is shown once and cannot be recovered.")
	fmt.Println()
	fmt.Printf("  keyId:   %s\n", out.ServiceAccount.KeyID)
	fmt.Printf("  secret:  %s\n", out.Secret)
	fmt.Printf("  label:   %s\n", out.ServiceAccount.Label)
	fmt.Printf("  vaults:  %s\n", strings.Join(out.ServiceAccount.VaultIDs, ", "))
	fmt.Println()
	fmt.Println("Put the secret in the environment the daemon reads (secretEnv in its")
	fmt.Println("config), then pair it with the organization key:")
	fmt.Println()
	fmt.Println("  sinesync admin export-key --out sinesync-org.key")
	fmt.Println()
	fmt.Println("The token grants API access; the key decrypts. Revoking this account stops")
	fmt.Println("the daemon reaching the API without touching the key.")

	return nil
}

func runServiceAccountList(cmd *cobra.Command, args []string) error {
	out := struct{ ServiceAccounts []ServiceAccountView }{}
	accounts, err := listServiceAccounts()
	if err != nil {
		return err
	}
	out.ServiceAccounts = accounts

	if len(out.ServiceAccounts) == 0 {
		fmt.Fprintln(os.Stdout, "No service accounts.")
		return nil
	}

	for _, sa := range out.ServiceAccounts {
		state := "active"
		if sa.RevokedAt != "" {
			state = "revoked " + sa.RevokedAt
		}
		fmt.Printf("%s  %-24s  %s\n", sa.KeyID, sa.Label, state)
		fmt.Printf("    vaults: %s\n", strings.Join(sa.VaultIDs, ", "))
	}
	return nil
}

// listServiceAccounts is factored out because revoke needs it: the DELETE route
// identifies an account by its document id, and the only identifier a person
// ever sees is the keyId — it is what create prints and what list shows. Asking
// for an opaque id instead would be asking them to read the database.
func listServiceAccounts() ([]ServiceAccountView, error) {
	resp, err := serviceAccountRequest(http.MethodGet, "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("listing service accounts failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		ServiceAccounts []ServiceAccountView `json:"serviceAccounts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return out.ServiceAccounts, nil
}

func runServiceAccountRevoke(cmd *cobra.Command, args []string) error {
	wanted := args[0]

	accounts, err := listServiceAccounts()
	if err != nil {
		return err
	}

	var target *ServiceAccountView
	for i := range accounts {
		// Either identifier is accepted, so a script holding the id is not
		// forced through a lookup it does not need.
		if accounts[i].KeyID == wanted || accounts[i].ID == wanted {
			target = &accounts[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no service account with key id %q\n\nRun 'sinesync admin service-account list' to see them", wanted)
	}
	if target.RevokedAt != "" {
		fmt.Printf("%s was already revoked at %s.\n", target.KeyID, target.RevokedAt)
		return nil
	}

	resp, err := serviceAccountRequest(http.MethodDelete, "/"+target.ID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoking %s failed (HTTP %d): %s", target.KeyID, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	fmt.Printf("Revoked %s. Any daemon using it stops at its next API call.\n", target.KeyID)
	fmt.Println("The organization key is unaffected — rotate it separately if it was exposed.")
	return nil
}
