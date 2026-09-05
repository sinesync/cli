package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sinesync/cli/internal/httputil"
)

// OrgInfo represents the user's organization info from /users/org-info
type OrgInfo struct {
	OrgID          string `json:"orgId"`
	Role           string `json:"role"`
	OrgPublicKey   string `json:"orgPublicKey"`
	KeyHolderCount *int   `json:"keyHolderCount"`
}

// OrgKeyResponse represents the response from /organizations/:id/org-key
type OrgKeyResponse struct {
	OrgPublicKey string      `json:"orgPublicKey"`
	KeyHolder    *KeyHolder  `json:"keyHolder"`
}

// KeyHolder represents an org key holder record
type KeyHolder struct {
	OrgID                  string `json:"orgId"`
	UserID                 string `json:"userId"`
	EncryptedOrgPrivateKey string `json:"encryptedOrgPrivateKey"`
	CreatedAt              string `json:"createdAt"`
}

// PendingProvision represents a member needing key provisioning
type PendingProvision struct {
	UserID    string   `json:"userId"`
	PublicKey string   `json:"publicKey"`
	VaultIDs  []string `json:"vaultIds"`
}

// OrgVaultResponse represents an org vault from the API
type OrgVaultResponse struct {
	ID                string `json:"id"`
	OrganizationID    string `json:"organizationId"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	EncryptedVaultKey string `json:"encryptedVaultKey,omitempty"`
	CreatedBy         string `json:"createdBy"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
	Role              string `json:"role,omitempty"`
}

// fetchUserOrgInfo gets the user's organization info
func fetchUserOrgInfo(token string) (*OrgInfo, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/users/org-info", nil)
	if err != nil {
		return nil, err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch org info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("org info fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var info OrgInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		// null response means no org
		return nil, nil
	}

	if info.OrgID == "" {
		return nil, nil
	}

	return &info, nil
}

// fetchOrgKey gets the org key holder and public key
func fetchOrgKey(token, orgID string) (*OrgKeyResponse, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/organizations/"+orgID+"/org-key", nil)
	if err != nil {
		return nil, err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch org key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("org key fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var result OrgKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// initOrgKeypairAPI initializes the org keypair on the server
func initOrgKeypairAPI(token, orgID, orgPublicKey, encryptedOrgPrivateKey string) error {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	body, err := json.Marshal(map[string]string{
		"orgPublicKey":           orgPublicKey,
		"encryptedOrgPrivateKey": encryptedOrgPrivateKey,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiBase+"/organizations/"+orgID+"/org-key/init", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to init org keypair: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("init org keypair failed %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// fetchPendingProvisions gets pending key provisions for an org
func fetchPendingProvisions(token, orgID string) ([]PendingProvision, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/organizations/"+orgID+"/org-key/pending", nil)
	if err != nil {
		return nil, err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pending provisions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pending provisions fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Pending []PendingProvision `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Pending, nil
}

// submitProvisions sends provisioned vault keys to the server
func submitProvisions(token, orgID string, provisions []map[string]interface{}) error {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	body, err := json.Marshal(map[string]interface{}{
		"provisions": provisions,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiBase+"/organizations/"+orgID+"/org-key/provision", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to submit provisions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit provisions failed %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// fetchOrgVaults lists org vaults
func fetchOrgVaults(token, orgID string) ([]OrgVaultResponse, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/organizations/"+orgID+"/vaults", nil)
	if err != nil {
		return nil, err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch org vaults: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("org vaults fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Vaults []OrgVaultResponse `json:"vaults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Vaults, nil
}

// fetchOrgVaultKey gets the user's encrypted vault key for an org vault
func fetchOrgVaultKey(token, orgID, vaultID string) (string, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/organizations/"+orgID+"/vaults/"+vaultID+"/key", nil)
	if err != nil {
		return "", err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return "", fmt.Errorf("failed to fetch org vault key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// User has no vault member record yet — needs provisioning
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("org vault key fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		EncryptedVaultKey *string `json:"encryptedVaultKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.EncryptedVaultKey == nil {
		return "", nil
	}

	return *result.EncryptedVaultKey, nil
}

// fetchMyPublicKey fetches the current user's X25519 public key from the server
func fetchMyPublicKey(token string) (string, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/users/keypair", nil)
	if err != nil {
		return "", err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return "", fmt.Errorf("failed to fetch keypair: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keypair fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.PublicKey == "" {
		return "", fmt.Errorf("user has no public key — run 'sinesync login' to set up keypair")
	}

	return result.PublicKey, nil
}

// AdminPendingHolder represents an admin who needs a key holder record
type AdminPendingHolder struct {
	UserID    string `json:"userId"`
	PublicKey string `json:"publicKey"`
}

// fetchAdminsPendingKeyHolders gets admins without key holder records
func fetchAdminsPendingKeyHolders(token, orgID string) ([]AdminPendingHolder, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/organizations/"+orgID+"/org-key/admins-pending", nil)
	if err != nil {
		return nil, err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pending admin holders: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pending admin holders fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Admins []AdminPendingHolder `json:"admins"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Admins, nil
}

// submitKeyHolders creates key holder records for other admins
func submitKeyHolders(token, orgID string, holders []map[string]string) error {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	body, err := json.Marshal(map[string]interface{}{
		"holders": holders,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiBase+"/organizations/"+orgID+"/org-key/holders", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to submit key holders: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit key holders failed %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// resetOrgKeypair resets the org keypair and all associated crypto state
func resetOrgKeypair(token, orgID string) error {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("POST", apiBase+"/organizations/"+orgID+"/org-key/reset", nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to reset org keypair: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reset org keypair failed %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// OrgMemberInfo represents a member from the org members list
type OrgMemberInfo struct {
	UserID string `json:"userId"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role"`
}

// fetchOrgMembers lists org members
func fetchOrgMembers(token, orgID string) ([]OrgMemberInfo, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/organizations/"+orgID+"/members", nil)
	if err != nil {
		return nil, err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch org members: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("org members fetch failed %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Members []OrgMemberInfo `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	members := result.Members

	return members, nil
}

// resetMemberEncryption resets a user's SSO encryption state
func resetMemberEncryption(token, orgID, userID string) error {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("POST", apiBase+"/organizations/"+orgID+"/members/"+userID+"/reset-encryption", nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to reset member encryption: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reset member encryption failed %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// updateOrgVaultKey updates the encrypted vault key on an org vault
func updateOrgVaultKey(token, orgID, vaultID, encryptedVaultKey string) error {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	body, err := json.Marshal(map[string]string{
		"encryptedVaultKey": encryptedVaultKey,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", apiBase+"/organizations/"+orgID+"/vaults/"+vaultID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update org vault key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update org vault key failed %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
