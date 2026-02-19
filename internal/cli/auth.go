package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/crypto"
	"github.com/miclip/sinesync/internal/encryption"
	"github.com/miclip/sinesync/internal/httputil"
	"github.com/miclip/sinesync/internal/keychain"
	"github.com/miclip/sinesync/internal/srp"
	"github.com/spf13/cobra"
	kr "github.com/zalando/go-keyring"
	"golang.org/x/term"
)

// zeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

const keyringService = "sinesync"

const DefaultAPIBase = "https://api.sinesync.ai/v1"

// AuthConfig stores authentication data
type AuthConfig struct {
	UserID       string `json:"userId"`
	Email        string `json:"email"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
	DeviceID     string `json:"deviceId,omitempty"`
	DeviceToken  string `json:"deviceToken,omitempty"`
	AuthMethod   string `json:"authMethod,omitempty"` // "srp" or "saml"
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to sine~sync cloud",
	Long: `Authenticate with sine~sync cloud service.

This command:
  1. Logs in with your email
  2. Registers this device automatically
  3. Enables cloud sync for your memories`,
	RunE: runLogin,
}

var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Create a sine~sync account",
	RunE:  runSignup,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from sine~sync cloud",
	RunE:  runLogout,
}

var keypairCmd = &cobra.Command{
	Use:   "keypair",
	Short: "Generate or regenerate your vault sharing keypair",
	Long: `Generate a new X25519 keypair for vault sharing.

This is required if you signed up via the website, or if you want to
rotate your keypair for security. The private key is encrypted with
your local encryption key before being uploaded.

Note: Regenerating your keypair will NOT affect existing vault shares.
You will still be able to access vaults that were shared with your
previous public key.`,
	RunE: runKeypair,
}

func init() {
	loginCmd.Flags().Int("sso-port", 0, "Fixed port for SSO callback (useful for SSH port forwarding)")
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(signupCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(keypairCmd)
}

func getAPIBase() string {
	if base := os.Getenv("SINESYNC_API_URL"); base != "" {
		return base
	}
	return DefaultAPIBase
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return "linux"
	}
}

func runLogin(cmd *cobra.Command, args []string) error {
	apiBase := getAPIBase()

	// Get email
	fmt.Print("Email: ")
	reader := bufio.NewReader(os.Stdin)
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Check for SAML SSO before prompting for password
	samlResult, err := discoverSAML(apiBase, email)
	if err != nil {
		// Discovery failure is non-fatal; fall back to password login
		fmt.Fprintf(os.Stderr, "Warning: SSO discovery failed: %v\n", err)
	}

	if samlResult != nil && samlResult.SAMLEnabled {
		ssoPort, _ := cmd.Flags().GetInt("sso-port")
		return doSAMLLoginFlow(apiBase, email, samlResult.OrgSlug, ssoPort)
	}

	// Get password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer zeroBytes(passwordBytes)
	password := string(passwordBytes)

	if password == "" {
		return fmt.Errorf("password is required")
	}

	fmt.Printf("Logging in as %s...\n", email)

	// Step 1: SRP login
	loginResp, err := doSRPLogin(apiBase, email, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	fmt.Println("✓ Authenticated")

	// Step 2: Setup encryption key
	encMgr := encryption.GetManager()
	hasSecretKey := encryption.HasSecretKeyInKeychain()

	if hasSecretKey {
		// Existing device - re-derive key from stored secret key
		fmt.Println("Verifying encryption key...")
		if err := encMgr.SetupExistingDevice(password); err != nil {
			return fmt.Errorf("encryption key setup failed: %w", err)
		}

		// Verify with test blob from server
		testBlob, err := fetchTestBlob(apiBase, loginResp.Token)
		if err != nil {
			fmt.Printf("Warning: could not verify encryption key: %v\n", err)
		} else if !encMgr.VerifyKey(testBlob) {
			return fmt.Errorf("encryption key verification failed - please check your password")
		}

		fmt.Println("✓ Encryption key verified")
	} else {
		// New device - need secret key from user
		fmt.Println()
		fmt.Println("This is a new device. To decrypt your data, you need your Secret Key.")
		fmt.Println("This was shown when you signed up - check your password manager or saved notes.")
		fmt.Println()

		secretKey, err := promptSecretKey()
		if err != nil {
			return fmt.Errorf("failed to read secret key: %w", err)
		}

		// Fetch salt and test blob from server
		encSalt, err := fetchSalt(apiBase, loginResp.Token)
		if err != nil {
			return fmt.Errorf("failed to fetch encryption salt: %w", err)
		}

		testBlob, err := fetchTestBlob(apiBase, loginResp.Token)
		if err != nil {
			return fmt.Errorf("failed to fetch test blob: %w", err)
		}

		// Setup encryption with provided secret key
		if err := encMgr.SetupNewDevice(password, secretKey, encSalt, testBlob); err != nil {
			if err == encryption.ErrKeyMismatch {
				return fmt.Errorf("invalid secret key - please check and try again")
			}
			return fmt.Errorf("encryption setup failed: %w", err)
		}

		fmt.Println("✓ Encryption key configured")
	}

	// Step 3: Register this device
	hostname := getHostname()
	platform := getPlatform()

	fmt.Printf("Registering device: %s (%s)...\n", hostname, platform)

	deviceResp, err := registerDevice(apiBase, loginResp.Token, hostname, platform)
	if err != nil {
		if isAccountDeletedError(err) {
			return fmt.Errorf("this account has been deleted")
		}
		return fmt.Errorf("device registration failed: %w", err)
	}

	fmt.Println("✓ Device registered")

	// Save auth config
	// Use device tokens for both access and refresh (device-specific auth)
	authCfg := &AuthConfig{
		UserID:       loginResp.User.ID,
		Email:        loginResp.User.Email,
		Token:        deviceResp.Token,         // Device access token
		RefreshToken: deviceResp.RefreshToken,  // Device refresh token
		ExpiresAt:    deviceResp.ExpiresAt,
		DeviceID:     deviceResp.Device.ID,
		DeviceToken:  deviceResp.Token,
		AuthMethod:   "srp",
	}

	if err := saveAuthConfig(authCfg); err != nil {
		return fmt.Errorf("failed to save auth: %w", err)
	}

	// Update last auth time
	keychain.SetLastAuth(time.Now())

	// Check if user has a keypair, generate one if not
	checkAndGenerateKeypair(authCfg.Token)

	fmt.Println()
	fmt.Println("✓ Logged in successfully!")
	fmt.Printf("  User: %s\n", authCfg.Email)
	fmt.Printf("  Device: %s\n", hostname)
	fmt.Println()
	fmt.Println("Cloud sync is now enabled with end-to-end encryption.")

	// Auto-sync vault keys so cloud sync works immediately
	if err := runVaultSync(nil, nil); err != nil {
		fmt.Printf("Warning: vault sync failed: %v\n", err)
		fmt.Println("You can run 'sinesync vault sync' manually to sync vault keys.")
	}

	return nil
}

// --- SAML SSO Login ---

type samlDiscoverResult struct {
	SAMLEnabled bool   `json:"samlEnabled"`
	OrgSlug     string `json:"orgSlug"`
}

// discoverSAML checks if the user's email domain has SAML SSO enabled.
func discoverSAML(apiBase, email string) (*samlDiscoverResult, error) {
	body, _ := json.Marshal(map[string]string{"email": email})
	req, err := http.NewRequest("POST", apiBase+"/auth/saml/discover", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %d", resp.StatusCode)
	}

	var result samlDiscoverResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// doSAMLLoginFlow performs the full SAML login: PKCE, browser, callback, token exchange, device registration.
// If ssoPort > 0, use that fixed port for the callback server (useful for SSH port forwarding).
func doSAMLLoginFlow(apiBase, email, orgSlug string, ssoPort int) error {
	if ssoPort > 0 {
		fmt.Printf("SSO detected for %s — follow the printed URL to authenticate (port %d)...\n", email, ssoPort)
	} else {
		fmt.Printf("SSO detected for %s — opening browser for authentication...\n", email)
	}

	// Generate PKCE pair
	verifierBytes := make([]byte, 43)
	if _, err := rand.Read(verifierBytes); err != nil {
		return fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// Generate state nonce
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Start HTTP server for the SSO callback
	// When --sso-port is set, bind to 0.0.0.0 so Docker port forwarding works
	listenAddr := "127.0.0.1:0"
	if ssoPort > 0 {
		listenAddr = fmt.Sprintf("0.0.0.0:%d", ssoPort)
		fmt.Fprintf(os.Stderr, "Warning: SSO callback listening on all interfaces (port %d)\n", ssoPort)
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	type callbackResult struct {
		code  string
		state string
		err   error
	}
	resultCh := make(chan callbackResult, 1)
	var once sync.Once
	sendResult := func(r callbackResult) {
		once.Do(func() { resultCh <- r })
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		cbState := r.URL.Query().Get("state")
		cbCode := r.URL.Query().Get("code")
		cbError := r.URL.Query().Get("error")

		if cbError != "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body><h2>Login failed</h2><p>%s</p><p>You can close this tab.</p></body></html>", html.EscapeString(cbError))
			sendResult(callbackResult{err: fmt.Errorf("SSO error: %s", cbError)})
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h2>Login complete!</h2><p>You can close this tab and return to the terminal.</p></body></html>")
		sendResult(callbackResult{code: cbCode, state: cbState})
	})

	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			sendResult(callbackResult{err: fmt.Errorf("callback server error: %w", err)})
		}
	}()

	// Build login URL
	loginURL := fmt.Sprintf("%s/auth/saml/login?org=%s&clientType=cli&port=%d&code_challenge=%s&state=%s",
		apiBase, orgSlug, port, codeChallenge, state)

	// Open browser (or print URL for headless/SSH environments)
	if ssoPort > 0 {
		// Replace Docker-internal hostnames with localhost for browser access
		browserURL := strings.Replace(loginURL, "host.docker.internal", "localhost", 1)
		fmt.Println("Open this URL in your local browser:")
		fmt.Printf("  %s\n", browserURL)
		fmt.Printf("\nEnsure port forwarding is active for port %d\n", port)
	} else if err := openBrowserForSAML(loginURL); err != nil {
		fmt.Println("Could not open browser automatically.")
		fmt.Println("Open this URL in your browser:")
		fmt.Printf("  %s\n", loginURL)
	}

	fmt.Println("\nWaiting for SSO authentication...")

	// Wait for callback with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var cbResult callbackResult
	select {
	case cbResult = <-resultCh:
	case <-ctx.Done():
		server.Shutdown(context.Background())
		return fmt.Errorf("SSO login timed out after 120 seconds")
	}

	// Shut down callback server
	server.Shutdown(context.Background())

	if cbResult.err != nil {
		return cbResult.err
	}

	// Verify state nonce
	if cbResult.state != state {
		return fmt.Errorf("SSO state mismatch — possible CSRF attack")
	}

	fmt.Println("✓ SSO authentication successful")

	// Exchange auth code for tokens
	exchangeBody, _ := json.Marshal(map[string]string{
		"code":          cbResult.code,
		"code_verifier": codeVerifier,
	})

	exchangeReq, err := http.NewRequest("POST", apiBase+"/auth/saml/token", bytes.NewReader(exchangeBody))
	if err != nil {
		return fmt.Errorf("failed to create token exchange request: %w", err)
	}
	exchangeReq.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(exchangeReq)

	exchangeResp, err := authHTTPClient.Do(exchangeReq)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	defer exchangeResp.Body.Close()

	if exchangeResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(exchangeResp.Body)
		return fmt.Errorf("token exchange failed: %d - %s", exchangeResp.StatusCode, string(respBody))
	}

	var tokenResult authResponse
	if err := json.NewDecoder(exchangeResp.Body).Decode(&tokenResult); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	fmt.Println("✓ Authenticated via SSO")

	// Register device
	hostname := getHostname()
	platform := getPlatform()

	fmt.Printf("Registering device: %s (%s)...\n", hostname, platform)

	deviceResp, err := registerDevice(apiBase, tokenResult.Token, hostname, platform)
	if err != nil {
		if isAccountDeletedError(err) {
			return fmt.Errorf("this account has been deleted")
		}
		return fmt.Errorf("device registration failed: %w", err)
	}

	fmt.Println("✓ Device registered")

	// Save auth config with SAML auth method
	authCfg := &AuthConfig{
		UserID:       tokenResult.User.ID,
		Email:        tokenResult.User.Email,
		Token:        deviceResp.Token,
		RefreshToken: deviceResp.RefreshToken,
		ExpiresAt:    deviceResp.ExpiresAt,
		DeviceID:     deviceResp.Device.ID,
		DeviceToken:  deviceResp.Token,
		AuthMethod:   "saml",
	}

	if err := saveAuthConfig(authCfg); err != nil {
		return fmt.Errorf("failed to save auth: %w", err)
	}

	// Update last auth time
	keychain.SetLastAuth(time.Now())

	// SSO device-key encryption setup
	token := authCfg.Token

	// Determine org role for encryption flow decisions
	isAdmin := false
	orgInfo, err := fetchUserOrgInfo(token)
	if err != nil {
		return fmt.Errorf("failed to fetch organization info; please retry login: %w", err)
	}
	if orgInfo != nil {
		isAdmin = orgInfo.Role == "admin" || orgInfo.Role == "owner"
	}

	status, err := ssoCredentialStatus(apiBase, token)
	if err != nil {
		return fmt.Errorf("failed to check SSO credential status: %w", err)
	}

	if !status.HasBundle {
		// First-ever SSO login — bootstrap encryption keys
		if err := ssoBootstrap(apiBase, token, isAdmin); err != nil {
			return fmt.Errorf("SSO key bootstrap failed: %w", err)
		}
	} else if keychain.HasDeviceKey() {
		// Returning device — unlock from device key
		if err := ssoSameDeviceUnlock(apiBase, token); err != nil {
			return fmt.Errorf("SSO device unlock failed: %w", err)
		}
	} else if isAdmin {
		// Admin on new device — recover using account key
		if err := ssoAccountKeyRecover(apiBase, token, status.TestBlob); err != nil {
			return fmt.Errorf("SSO account key recovery failed: %w", err)
		}
	} else {
		// Member on new device — try self-service recovery from existing device
		if err := ssoDeviceRecovery(apiBase, token, authCfg.DeviceID); err != nil {
			return fmt.Errorf("SSO device recovery failed: %w", err)
		}
	}

	// Check if user has a keypair, generate one if not
	checkAndGenerateKeypair(authCfg.Token)

	fmt.Println()
	fmt.Println("✓ Logged in via SSO!")
	fmt.Printf("  User: %s\n", authCfg.Email)
	fmt.Printf("  Device: %s\n", hostname)
	fmt.Println()
	fmt.Println("Cloud sync is now enabled with end-to-end encryption.")

	// Auto-sync vault keys
	if err := runVaultSync(nil, nil); err != nil {
		fmt.Printf("Warning: vault sync failed: %v\n", err)
		fmt.Println("You can run 'sinesync vault sync' manually to sync vault keys.")
	}

	return nil
}

// --- SSO encryption helpers ---

type ssoStatusResult struct {
	HasBundle bool   `json:"hasBundle"`
	TestBlob  string `json:"testBlob,omitempty"`
}

func ssoCredentialStatus(apiBase, token string) (*ssoStatusResult, error) {
	req, err := http.NewRequest("GET", apiBase+"/sso/credentials/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result ssoStatusResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ssoBootstrap generates new encryption keys for first-time SSO login.
// The server derives the device ID from the access token.
func ssoBootstrap(apiBase, token string, isAdmin bool) error {
	fmt.Println("Setting up device-key encryption for SSO...")

	// 1. Generate random 32-byte account key (master encryption key)
	accountKey, err := crypto.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("generate account key: %w", err)
	}

	// 2. Generate X25519 keypair for vault sharing
	publicKey, privateKey, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	// 3. Generate random 32-byte device key
	deviceKey, err := crypto.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("generate device key: %w", err)
	}

	// 4. Store device key in keychain
	if err := keychain.SetDeviceKey(deviceKey); err != nil {
		return fmt.Errorf("store device key: %w", err)
	}

	// 5. Build credential bundle JSON
	bundleJSON, err := json.Marshal(map[string]string{
		"version":    "1",
		"accountKey": base64.StdEncoding.EncodeToString(accountKey),
		"privateKey": privateKey,
	})
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}

	// 6. Encrypt bundle with device key
	encryptedBundle, err := encryption.EncryptCredentialBundle(bundleJSON, deviceKey)
	if err != nil {
		return fmt.Errorf("encrypt bundle: %w", err)
	}

	// 7. Set account key as the derived key
	encMgr := encryption.GetManager()
	if err := encMgr.SetKeyDirect(accountKey); err != nil {
		return fmt.Errorf("set key: %w", err)
	}

	// 8. Create test blob for key verification
	testBlob, err := encMgr.CreateTestBlob()
	if err != nil {
		return fmt.Errorf("create test blob: %w", err)
	}

	// 9. Encrypt private key with account key
	encryptedPrivateKey, err := encMgr.EncryptUserPrivateKey([]byte(privateKey))
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	// 10. Upload to server
	body, _ := json.Marshal(map[string]string{
		"encryptedBundle":     base64.StdEncoding.EncodeToString(encryptedBundle),
		"publicKey":           publicKey,
		"encryptedPrivateKey": encryptedPrivateKey,
		"testBlob":            base64.StdEncoding.EncodeToString(testBlob),
	})

	req, err := http.NewRequest("POST", apiBase+"/sso/credentials/bootstrap", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("bootstrap request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	fmt.Println()
	fmt.Println("✓ Encryption keys generated and secured with device key")

	if isAdmin {
		// Admins need the account key for new device recovery and web provisioning
		accountKeyFormatted := crypto.EncodeBase32(accountKey)
		fmt.Println()
		fmt.Println("  ┌────────────────────────────────────────────────────────────────────┐")
		fmt.Printf("  │  %-64s  │\n", "")
		fmt.Printf("  │  %-64s  │\n", "YOUR ACCOUNT KEY (save this securely)")
		fmt.Printf("  │  %-64s  │\n", "")
		fmt.Printf("  │  %-64s  │\n", accountKeyFormatted)
		fmt.Printf("  │  %-64s  │\n", "")
		fmt.Printf("  │  %-64s  │\n", "You will need this key to set up new devices and")
		fmt.Printf("  │  %-64s  │\n", "provision members from the web UI.")
		fmt.Printf("  │  %-64s  │\n", "It will not be shown again.")
		fmt.Printf("  │  %-64s  │\n", "")
		fmt.Println("  └────────────────────────────────────────────────────────────────────┘")
		fmt.Println()
		fmt.Print("Press Enter after you have saved your account key...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Println()
	}

	return nil
}

// ssoSameDeviceUnlock decrypts credential bundle using device key from keychain.
// The server derives the device ID from the access token.
func ssoSameDeviceUnlock(apiBase, token string) error {
	fmt.Println("Unlocking encryption keys from device key...")

	// 1. Get device key from keychain
	deviceKey, err := keychain.GetDeviceKey()
	if err != nil {
		return fmt.Errorf("get device key: %w", err)
	}

	// 2. Download encrypted bundle
	req, err := http.NewRequest("GET", apiBase+"/sso/credentials/bundle", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var bundleResp struct {
		EncryptedBundle string `json:"encryptedBundle"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bundleResp); err != nil {
		return err
	}

	// 3. Decrypt bundle
	encryptedBytes, err := base64.StdEncoding.DecodeString(bundleResp.EncryptedBundle)
	if err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}

	bundleJSON, err := encryption.DecryptCredentialBundle(encryptedBytes, deviceKey)
	if err != nil {
		return fmt.Errorf("decrypt bundle: %w", err)
	}

	// 4. Parse bundle
	var bundle struct {
		AccountKey string `json:"accountKey"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	accountKey, err := base64.StdEncoding.DecodeString(bundle.AccountKey)
	if err != nil {
		return fmt.Errorf("decode account key: %w", err)
	}

	// 5. Set account key
	encMgr := encryption.GetManager()
	if err := encMgr.SetKeyDirect(accountKey); err != nil {
		return fmt.Errorf("set key: %w", err)
	}

	fmt.Println("✓ Encryption keys unlocked from device key")
	return nil
}

// ssoAccountKeyRecover sets up encryption on a new device using the account key.
// The user enters their account key (dashed base32) to derive the encryption key directly.
func ssoAccountKeyRecover(apiBase, token, testBlobB64 string) error {
	fmt.Println("New device detected. Enter your account key to set up encryption.")
	fmt.Println()
	fmt.Print("Account Key: ")
	accountKeyInput, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read account key: %w", err)
	}

	// Normalize and decode dashed base32
	accountKeyInput = crypto.NormalizeSecretKey(accountKeyInput)
	accountKey, err := crypto.DecodeSecretKey(accountKeyInput)
	if err != nil {
		return fmt.Errorf("invalid account key format: %w", err)
	}

	// Set account key as the encryption key
	encMgr := encryption.GetManager()
	if err := encMgr.SetKeyDirect(accountKey); err != nil {
		return fmt.Errorf("set key: %w", err)
	}

	// Verify the key by decrypting the test blob
	testBlob, err := base64.StdEncoding.DecodeString(testBlobB64)
	if err != nil {
		return fmt.Errorf("decode test blob: %w", err)
	}
	if !encMgr.VerifyKey(testBlob) {
		return fmt.Errorf("invalid account key — decryption failed")
	}

	// Fetch the encrypted private key and decrypt to include in bundle
	privateKeyB64, err := fetchAndDecryptPrivateKey(token)
	if err != nil {
		return fmt.Errorf("fetch private key: %w", err)
	}

	// Generate new device key for this device
	deviceKey, err := crypto.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("generate device key: %w", err)
	}

	if err := keychain.SetDeviceKey(deviceKey); err != nil {
		return fmt.Errorf("store device key: %w", err)
	}

	// Build and encrypt credential bundle
	bundleJSON, err := json.Marshal(map[string]string{
		"version":    "1",
		"accountKey": base64.StdEncoding.EncodeToString(accountKey),
		"privateKey": privateKeyB64,
	})
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}

	encryptedBundle, err := encryption.EncryptCredentialBundle(bundleJSON, deviceKey)
	if err != nil {
		return fmt.Errorf("encrypt bundle: %w", err)
	}

	// Upload new bundle for this device
	body, _ := json.Marshal(map[string]string{
		"encryptedBundle": base64.StdEncoding.EncodeToString(encryptedBundle),
	})

	req, err := http.NewRequest("POST", apiBase+"/sso/credentials/bundle", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("store bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	fmt.Println("✓ Encryption keys recovered from account key")
	return nil
}

// ssoDeviceRecovery performs self-service recovery for a member on a new device.
// An ephemeral X25519 keypair is generated; the new device posts its temp public key
// and polls until an existing device seals the credential bundle with that key.
func ssoDeviceRecovery(apiBase, token, deviceID string) error {
	fmt.Println()
	fmt.Println("New device detected. Requesting encryption keys from your existing device...")
	fmt.Println("Run 'sinesync vault sync' on an existing device to approve.")
	fmt.Println()

	// 1. Generate ephemeral X25519 keypair
	tempPubKey, tempPrivKey, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	hostname := getHostname()

	// 2. POST recovery request
	reqBody, _ := json.Marshal(map[string]string{
		"tempPublicKey": tempPubKey,
		"deviceName":    hostname,
	})

	recoveryID := ""
	{
		req, err := http.NewRequest("POST", apiBase+"/sso/credentials/recovery", bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("create recovery request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(req)

		resp, err := authHTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("post recovery request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("recovery request failed: %d - %s", resp.StatusCode, string(body))
		}

		var result struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("parse recovery response: %w", err)
		}
		recoveryID = result.ID
	}

	// 3. Poll for approval (every 5s, 5-minute timeout)
	fmt.Println("Waiting for approval from existing device...")
	deadline := time.Now().Add(5 * time.Minute)
	var encryptedBundle string

	for {
		if time.Now().After(deadline) {
			fmt.Println()
			fmt.Println("Timed out waiting for approval from an existing device.")
			fmt.Println("Ask your org admin to run: sinesync admin reset-member <your-email>")
			fmt.Println("Then log in again.")
			return fmt.Errorf("device recovery timed out — no existing device responded")
		}

		time.Sleep(5 * time.Second)

		pollReq, err := http.NewRequest("GET", fmt.Sprintf("%s/sso/credentials/recovery/%s", apiBase, recoveryID), nil)
		if err != nil {
			continue
		}
		pollReq.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(pollReq)

		pollResp, err := authHTTPClient.Do(pollReq)
		if err != nil {
			continue
		}

		if pollResp.StatusCode != http.StatusOK {
			pollResp.Body.Close()
			continue
		}

		var recovery struct {
			Status          string `json:"status"`
			EncryptedBundle string `json:"encryptedBundle"`
		}
		if err := json.NewDecoder(pollResp.Body).Decode(&recovery); err != nil {
			pollResp.Body.Close()
			continue
		}
		pollResp.Body.Close()

		if recovery.Status == "ready" {
			encryptedBundle = recovery.EncryptedBundle
			break
		}
	}

	// 4. Decrypt bundle with ephemeral private key
	bundleJSON, err := crypto.X25519Open(encryptedBundle, tempPrivKey)
	if err != nil {
		return fmt.Errorf("decrypt recovery bundle: %w", err)
	}

	fmt.Println("✓ Encryption keys received from existing device")

	// 5. Parse bundle
	var bundle struct {
		AccountKey string `json:"accountKey"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	accountKey, err := base64.StdEncoding.DecodeString(bundle.AccountKey)
	if err != nil {
		return fmt.Errorf("decode account key: %w", err)
	}

	// 6. Generate new device key
	deviceKey, err := crypto.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("generate device key: %w", err)
	}

	if err := keychain.SetDeviceKey(deviceKey); err != nil {
		return fmt.Errorf("store device key: %w", err)
	}

	// 7. Re-encrypt bundle with device key
	reEncrypted, err := encryption.EncryptCredentialBundle(bundleJSON, deviceKey)
	if err != nil {
		return fmt.Errorf("re-encrypt bundle: %w", err)
	}

	// 8. Upload new device's bundle
	uploadBody, _ := json.Marshal(map[string]string{
		"encryptedBundle": base64.StdEncoding.EncodeToString(reEncrypted),
	})
	uploadReq, err := http.NewRequest("POST", apiBase+"/sso/credentials/bundle", bytes.NewReader(uploadBody))
	if err != nil {
		return fmt.Errorf("create upload request: %w", err)
	}
	uploadReq.Header.Set("Content-Type", "application/json")
	uploadReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(uploadReq)

	uploadResp, err := authHTTPClient.Do(uploadReq)
	if err != nil {
		return fmt.Errorf("upload bundle: %w", err)
	}
	defer uploadResp.Body.Close()

	if uploadResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(uploadResp.Body)
		return fmt.Errorf("upload failed: %d - %s", uploadResp.StatusCode, string(respBody))
	}

	// 9. Set account key
	encMgr := encryption.GetManager()
	if err := encMgr.SetKeyDirect(accountKey); err != nil {
		return fmt.Errorf("set key: %w", err)
	}

	// 10. Claim recovery (scrubs bundle from server)
	claimReq, err := http.NewRequest("POST", fmt.Sprintf("%s/sso/credentials/recovery/%s/claim", apiBase, recoveryID), nil)
	if err != nil {
		return fmt.Errorf("create claim request: %w", err)
	}
	claimReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(claimReq)

	claimResp, err := authHTTPClient.Do(claimReq)
	if err != nil {
		return fmt.Errorf("claim recovery: %w", err)
	}
	defer claimResp.Body.Close()

	fmt.Println("✓ Encryption keys secured with device key")
	return nil
}

// ssoNewDeviceLink performs the device linking flow for a new device.
// The server derives the device ID from the access token.
func ssoNewDeviceLink(apiBase, token, hostname, platform string) error {
	fmt.Println("This device needs to be linked to an existing device for encryption keys.")
	fmt.Println()

	// 1. Request a device link
	reqBody, _ := json.Marshal(map[string]string{
		"deviceName": hostname,
		"platform":   platform,
	})

	req, err := http.NewRequest("POST", apiBase+"/device-link/request", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("create link request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var linkResult struct {
		LinkRequestID string `json:"linkRequestId"`
		DisplayCode   string `json:"displayCode"`
		ExpiresAt     string `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&linkResult); err != nil {
		return err
	}

	// 2. Display linking code
	code := linkResult.DisplayCode
	if len(code) != 6 {
		return fmt.Errorf("server returned invalid display code (length %d)", len(code))
	}
	fmt.Printf("Linking code: %s-%s\n", code[:3], code[3:])
	fmt.Println()
	fmt.Println("On an existing device, run:")
	fmt.Println("  sinesync device approve")
	fmt.Println()
	fmt.Println("Waiting for approval...")

	// 3. Poll for approval
	pollURL := fmt.Sprintf("%s/device-link/%s/poll", apiBase, linkResult.LinkRequestID)
	expiresAt, err := time.Parse(time.RFC3339, linkResult.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid expiresAt in server response: %w", err)
	}

	var pollResult struct {
		Status          string `json:"status"`
		EncryptedBundle string `json:"encryptedBundle"`
		TransferSalt    string `json:"transferSalt"`
	}

	for {
		if time.Now().After(expiresAt) {
			return fmt.Errorf("device link request expired")
		}

		time.Sleep(3 * time.Second)

		pollReq, err := http.NewRequest("GET", pollURL, nil)
		if err != nil {
			continue
		}
		pollReq.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(pollReq)

		pollResp, err := authHTTPClient.Do(pollReq)
		if err != nil {
			continue
		}

		if pollResp.StatusCode != http.StatusOK {
			pollResp.Body.Close()
			continue
		}

		if err := json.NewDecoder(pollResp.Body).Decode(&pollResult); err != nil {
			pollResp.Body.Close()
			continue
		}
		pollResp.Body.Close()

		if pollResult.Status == "approved" {
			break
		}
		if pollResult.Status == "expired" {
			return fmt.Errorf("device link request expired")
		}
	}

	fmt.Println("✓ Device approved!")

	// 4. Derive transfer key from display code + salt
	transferSalt, err := base64.StdEncoding.DecodeString(pollResult.TransferSalt)
	if err != nil {
		return fmt.Errorf("decode transfer salt: %w", err)
	}
	transferKey := crypto.DeriveKeyFromCode(code, transferSalt)

	// 5. Decrypt the transfer bundle
	encryptedBundle, err := base64.StdEncoding.DecodeString(pollResult.EncryptedBundle)
	if err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}

	bundleJSON, err := encryption.DecryptForDeviceLink(encryptedBundle, transferKey)
	if err != nil {
		return fmt.Errorf("decrypt transfer bundle: %w", err)
	}

	// 6. Parse bundle
	var bundle struct {
		AccountKey string `json:"accountKey"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	accountKey, err := base64.StdEncoding.DecodeString(bundle.AccountKey)
	if err != nil {
		return fmt.Errorf("decode account key: %w", err)
	}

	// 7. Generate new device key and store in keychain
	newDeviceKey, err := crypto.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("generate device key: %w", err)
	}
	if err := keychain.SetDeviceKey(newDeviceKey); err != nil {
		return fmt.Errorf("store device key: %w", err)
	}

	// 8. Re-encrypt bundle with new device key
	reEncrypted, err := encryption.EncryptCredentialBundle(bundleJSON, newDeviceKey)
	if err != nil {
		return fmt.Errorf("re-encrypt bundle: %w", err)
	}

	// 9. Upload new device's bundle
	uploadBody, _ := json.Marshal(map[string]string{
		"encryptedBundle": base64.StdEncoding.EncodeToString(reEncrypted),
	})
	uploadReq, err := http.NewRequest("POST", apiBase+"/sso/credentials/bundle", bytes.NewReader(uploadBody))
	if err != nil {
		return fmt.Errorf("create upload request: %w", err)
	}
	uploadReq.Header.Set("Content-Type", "application/json")
	uploadReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(uploadReq)

	uploadResp, err := authHTTPClient.Do(uploadReq)
	if err != nil {
		return fmt.Errorf("upload bundle: %w", err)
	}
	defer uploadResp.Body.Close()

	if uploadResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(uploadResp.Body)
		return fmt.Errorf("upload failed: %d - %s", uploadResp.StatusCode, string(respBody))
	}

	// 10. Claim the link request
	claimReq, err := http.NewRequest("POST", fmt.Sprintf("%s/device-link/%s/claim", apiBase, linkResult.LinkRequestID), nil)
	if err != nil {
		return fmt.Errorf("create claim request: %w", err)
	}
	claimReq.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(claimReq)

	claimResp, err := authHTTPClient.Do(claimReq)
	if err != nil {
		return fmt.Errorf("claim request: %w", err)
	}
	defer claimResp.Body.Close()

	if claimResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(claimResp.Body)
		return fmt.Errorf("claim failed: %d - %s", claimResp.StatusCode, string(respBody))
	}

	// 11. Set account key as the derived key
	encMgr := encryption.GetManager()
	if err := encMgr.SetKeyDirect(accountKey); err != nil {
		return fmt.Errorf("set key: %w", err)
	}

	fmt.Println("✓ Encryption keys received and secured with device key")
	return nil
}

// openBrowserForSAML opens the given URL in the user's default browser.
func openBrowserForSAML(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		return fmt.Errorf("unsupported platform")
	}
	return cmd.Start()
}

func runSignup(cmd *cobra.Command, args []string) error {
	apiBase := getAPIBase()

	// Get email
	fmt.Print("Email: ")
	reader := bufio.NewReader(os.Stdin)
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Get password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer zeroBytes(passwordBytes)
	password := string(passwordBytes)

	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Confirm password
	fmt.Print("Confirm password: ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer zeroBytes(confirmBytes)

	if string(confirmBytes) != password {
		return fmt.Errorf("passwords do not match")
	}

	fmt.Printf("Creating account for %s...\n", email)

	// Generate SRP verifier (compatible with js-srp6a)
	srpClient := srp.NewClient(email, password)
	srpSalt, verifier := srpClient.ComputeVerifier()

	// Setup client-side encryption (2SKD)
	fmt.Println("Setting up end-to-end encryption...")
	encMgr := encryption.GetManager()
	secretKey, encSalt, testBlob, err := encMgr.SetupFirstDevice(password)
	if err != nil {
		return fmt.Errorf("encryption setup failed: %w", err)
	}

	// Generate X25519 keypair for vault sharing
	fmt.Println("Generating vault sharing keys...")
	publicKey, privateKey, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return fmt.Errorf("keypair generation failed: %w", err)
	}

	// Encrypt private key with user's derived key
	encryptedPrivateKey, err := encMgr.EncryptUserPrivateKey([]byte(privateKey))
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Signup with SRP credentials and keypair
	signupResp, err := doSignupWithKeypair(apiBase, email, srpSalt, verifier, publicKey, encryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("signup failed: %w", err)
	}

	fmt.Println("✓ Account created")

	// Store encryption salt on server
	if err := storeSalt(apiBase, signupResp.Token, encSalt); err != nil {
		return fmt.Errorf("failed to store encryption salt: %w", err)
	}

	// Store test blob on server
	if err := storeTestBlob(apiBase, signupResp.Token, testBlob); err != nil {
		return fmt.Errorf("failed to store test blob: %w", err)
	}

	fmt.Println("✓ Encryption configured")

	// Register this device
	hostname := getHostname()
	platform := getPlatform()

	fmt.Printf("Registering device: %s (%s)...\n", hostname, platform)

	deviceResp, err := registerDevice(apiBase, signupResp.Token, hostname, platform)
	if err != nil {
		return fmt.Errorf("device registration failed: %w", err)
	}

	fmt.Println("✓ Device registered")

	// Save auth config
	// Use device tokens for both access and refresh (device-specific auth)
	authCfg := &AuthConfig{
		UserID:       signupResp.User.ID,
		Email:        signupResp.User.Email,
		Token:        deviceResp.Token,         // Device access token
		RefreshToken: deviceResp.RefreshToken,  // Device refresh token
		ExpiresAt:    deviceResp.ExpiresAt,
		DeviceID:     deviceResp.Device.ID,
		DeviceToken:  deviceResp.Token,
	}

	if err := saveAuthConfig(authCfg); err != nil {
		return fmt.Errorf("failed to save auth: %w", err)
	}

	// Update last auth time
	keychain.SetLastAuth(time.Now())

	fmt.Println()
	fmt.Println("✓ Account created and logged in!")
	fmt.Printf("  User: %s\n", authCfg.Email)
	fmt.Printf("  Device: %s\n", hostname)
	fmt.Println()
	fmt.Println("You have a 14-day free trial.")

	// Display Emergency Kit (CRITICAL - only shown once)
	displayEmergencyKit(email, secretKey)

	return nil
}

func runLogout(cmd *cobra.Command, args []string) error {
	authCfg, err := loadAuthConfig()
	if err != nil || authCfg == nil {
		fmt.Println("Not logged in.")
		return nil
	}

	// Try to logout from server
	apiBase := getAPIBase()
	token := authCfg.DeviceToken
	if token == "" {
		token = authCfg.Token
	}

	req, err := http.NewRequest("POST", apiBase+"/auth/logout", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to create logout request: %v\n", err)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(req)
		client := &http.Client{Timeout: 10 * time.Second}
		client.Do(req) // Ignore response errors, we're logging out anyway
	}

	// Remove local auth config
	if err := removeAuthConfig(); err != nil {
		return fmt.Errorf("failed to remove auth: %w", err)
	}

	fmt.Println("✓ Logged out")
	return nil
}

func runKeypair(cmd *cobra.Command, args []string) error {
	authCfg, err := loadAuthConfig()
	if err != nil || authCfg == nil {
		return fmt.Errorf("not logged in - please run 'sinesync login' first")
	}

	return generateAndUploadKeypair(authCfg.Token, true)
}

// generateAndUploadKeypair generates a new X25519 keypair and uploads it
// If showSuccess is true, prints success message (used by manual command)
func generateAndUploadKeypair(token string, showSuccess bool) error {
	encMgr := encryption.GetManager()

	// Verify encryption is set up
	_, err := encMgr.GetKey()
	if err != nil {
		return fmt.Errorf("encryption not set up - please run 'sinesync login' first")
	}

	// Generate X25519 keypair
	fmt.Println("Generating vault sharing keypair...")
	publicKey, privateKey, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return fmt.Errorf("keypair generation failed: %w", err)
	}

	// Encrypt private key with user's derived key
	encryptedPrivateKey, err := encMgr.EncryptUserPrivateKey([]byte(privateKey))
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Upload to server
	apiBase := getAPIBase()
	body, _ := json.Marshal(map[string]string{
		"publicKey":           publicKey,
		"encryptedPrivateKey": encryptedPrivateKey,
	})

	req, err := http.NewRequest("POST", apiBase+"/users/keypair", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload keypair: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(respBody))
	}

	if showSuccess {
		fmt.Println("✓ Vault sharing keypair generated and uploaded")
		fmt.Println("  You can now share vaults with other users")
	}

	return nil
}

// checkAndGenerateKeypair checks if user has a keypair, generates one if not
func checkAndGenerateKeypair(token string) error {
	apiBase := getAPIBase()

	// Check if user already has a keypair
	req, err := http.NewRequest("GET", apiBase+"/users/keypair", nil)
	if err != nil {
		return nil // Don't fail login for this
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil // Don't fail login for this
	}
	defer resp.Body.Close()

	// If user has a keypair (200 OK), nothing to do
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	// User doesn't have a keypair, generate one
	fmt.Println()
	fmt.Println("Setting up vault sharing keypair...")
	if err := generateAndUploadKeypair(token, false); err != nil {
		fmt.Printf("Warning: could not generate keypair: %v\n", err)
		fmt.Println("You can run 'sinesync keypair' later to enable vault sharing")
		return nil
	}
	fmt.Println("✓ Vault sharing enabled")

	return nil
}

// Shared HTTP client with timeout for all auth requests
var authHTTPClient = &http.Client{Timeout: 30 * time.Second}

// API response types
type authResponse struct {
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
}

type deviceResponse struct {
	Device struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Platform string `json:"platform"`
	} `json:"device"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
}

// SRP login flow
func doSRPLogin(apiBase, email, password string) (*authResponse, error) {
	// Create SRP client (SHA256 + RFC5054 Group4096, compatible with js-srp6a)
	srpClient := srp.NewClient(email, password)

	// Generate client ephemeral A
	clientPublic := srpClient.GenerateEphemeral()

	// Step 1: Init - send email to get salt and server public B
	initBody, _ := json.Marshal(map[string]string{"email": email})
	initReq, err := http.NewRequest("POST", apiBase+"/auth/login/init", bytes.NewReader(initBody))
	if err != nil {
		return nil, err
	}
	initReq.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(initReq)
	initResp, err := authHTTPClient.Do(initReq)
	if err != nil {
		return nil, err
	}
	defer initResp.Body.Close()

	if initResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(initResp.Body)
		return nil, fmt.Errorf("server returned %d: %s", initResp.StatusCode, string(bodyBytes))
	}

	var initResult struct {
		Salt         string `json:"salt"`
		ServerPublic string `json:"serverPublic"`
	}
	if err := json.NewDecoder(initResp.Body).Decode(&initResult); err != nil {
		return nil, err
	}

	// Step 2: Compute client proof M1
	clientProof, err := srpClient.ComputeSession(initResult.Salt, initResult.ServerPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to compute proof: %w", err)
	}

	// Step 3: Verify - send client public A and proof M1
	verifyBody, _ := json.Marshal(map[string]string{
		"email":        email,
		"clientPublic": clientPublic,
		"clientProof":  clientProof,
	})
	verifyReq, err := http.NewRequest("POST", apiBase+"/auth/login/verify", bytes.NewReader(verifyBody))
	if err != nil {
		return nil, err
	}
	verifyReq.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(verifyReq)
	verifyResp, err := authHTTPClient.Do(verifyReq)
	if err != nil {
		return nil, err
	}
	defer verifyResp.Body.Close()

	if verifyResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(verifyResp.Body)
		return nil, fmt.Errorf("server returned %d: %s", verifyResp.StatusCode, string(bodyBytes))
	}

	var result struct {
		ServerProof string `json:"serverProof"`
		User        struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
		ExpiresAt    string `json:"expiresAt"`
	}
	if err := json.NewDecoder(verifyResp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Verify server's proof
	if !srpClient.VerifyServer(result.ServerProof) {
		return nil, fmt.Errorf("server proof verification failed")
	}

	return &authResponse{
		User:         result.User,
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
	}, nil
}

func doSignup(apiBase, email, srpSalt, srpVerifier string) (*authResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"email":       email,
		"srpSalt":     srpSalt,
		"srpVerifier": srpVerifier,
	})

	req, err := http.NewRequest("POST", apiBase+"/auth/signup", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(req)
	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result authResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func doSignupWithKeypair(apiBase, email, srpSalt, srpVerifier, publicKey, encryptedPrivateKey string) (*authResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"email":               email,
		"srpSalt":             srpSalt,
		"srpVerifier":         srpVerifier,
		"publicKey":           publicKey,
		"encryptedPrivateKey": encryptedPrivateKey,
	})

	req, err := http.NewRequest("POST", apiBase+"/auth/signup", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(req)
	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result authResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func registerDevice(apiBase, token, name, platform string) (*deviceResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"name":     name,
		"platform": platform,
	})

	req, err := http.NewRequest("POST", apiBase+"/devices", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result deviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Auth config storage
func authConfigPath() string {
	return config.ConfigDir() + "/auth.json"
}

func saveAuthConfig(cfg *AuthConfig) error {
	if err := os.MkdirAll(config.ConfigDir(), 0700); err != nil {
		return err
	}

	// Store tokens in system keychain — fail if keychain is unavailable
	if cfg.Token != "" {
		if err := kr.Set(keyringService, "token", cfg.Token); err != nil {
			return fmt.Errorf("system keychain unavailable — cannot store tokens securely: %w", err)
		}
	}
	if cfg.RefreshToken != "" {
		if err := kr.Set(keyringService, "refreshToken", cfg.RefreshToken); err != nil {
			return fmt.Errorf("failed to store refresh token in keychain: %w", err)
		}
	}
	if cfg.DeviceToken != "" {
		if err := kr.Set(keyringService, "deviceToken", cfg.DeviceToken); err != nil {
			return fmt.Errorf("failed to store device token in keychain: %w", err)
		}
	}

	// Store only non-sensitive metadata in file
	fileCfg := AuthConfig{
		UserID:     cfg.UserID,
		Email:      cfg.Email,
		ExpiresAt:  cfg.ExpiresAt,
		DeviceID:   cfg.DeviceID,
		AuthMethod: cfg.AuthMethod,
	}
	data, err := json.MarshalIndent(fileCfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(authConfigPath(), data, 0600)
}

func loadAuthConfig() (*AuthConfig, error) {
	data, err := os.ReadFile(authConfigPath())
	if err != nil {
		return nil, err
	}

	var cfg AuthConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Clear any tokens deserialized from disk — tokens must only come from keychain.
	// Legacy auth.json files may contain plaintext tokens that should not be trusted.
	cfg.Token = ""
	cfg.RefreshToken = ""
	cfg.DeviceToken = ""

	// Load tokens from keychain
	if token, err := kr.Get(keyringService, "token"); err == nil {
		cfg.Token = token
	}
	if refreshToken, err := kr.Get(keyringService, "refreshToken"); err == nil {
		cfg.RefreshToken = refreshToken
	}
	if deviceToken, err := kr.Get(keyringService, "deviceToken"); err == nil {
		cfg.DeviceToken = deviceToken
	}

	return &cfg, nil
}

// getAuthToken returns the best available auth token from the stored config.
func getAuthToken() (string, error) {
	authCfg, err := loadAuthConfig()
	if err != nil || authCfg == nil {
		return "", fmt.Errorf("not logged in - run 'sinesync login' first")
	}
	token := authCfg.DeviceToken
	if token == "" {
		token = authCfg.Token
	}
	if token == "" {
		return "", fmt.Errorf("no token found - run 'sinesync login' first")
	}
	return token, nil
}

// refreshAccessToken uses the stored refresh token to obtain a new access token.
func refreshAccessToken(apiBase string) (string, error) {
	authCfg, err := loadAuthConfig()
	if err != nil {
		return "", fmt.Errorf("cannot load auth config: %w", err)
	}

	refreshToken := authCfg.RefreshToken
	if refreshToken == "" {
		return "", fmt.Errorf("no refresh token available - run 'sinesync login'")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	reqBody, _ := json.Marshal(map[string]string{
		"refreshToken": refreshToken,
	})

	req, err := http.NewRequest("POST", apiBase+"/auth/refresh", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token refresh failed: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Save new access token to keyring
	if err := kr.Set(keyringService, "token", result.Token); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to store access token in keyring: %v\n", err)
	}

	// Save rotated refresh token if provided
	if result.RefreshToken != "" {
		if err := kr.Set(keyringService, "refreshToken", result.RefreshToken); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to store rotated refresh token in keyring — run 'sinesync login' to re-authenticate\n")
		}
	}

	return result.Token, nil
}

// isUnauthorizedError checks if an error indicates an expired or invalid token.
func isUnauthorizedError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "401") || strings.Contains(s, "INVALID_TOKEN") || strings.Contains(s, "unauthorized")
}

// isAccountDeletedError checks if an error indicates the user's account has been deleted.
func isAccountDeletedError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Prefer structured detection: server errors include JSON body with "code" field
	if i := strings.Index(msg, "{"); i != -1 {
		var payload struct {
			Code string `json:"code"`
		}
		if json.Unmarshal([]byte(msg[i:]), &payload) == nil && payload.Code == "ACCOUNT_DELETED" {
			return true
		}
	}
	return strings.Contains(msg, "ACCOUNT_DELETED")
}

func removeAuthConfig() error {
	// Remove from keychain
	_ = kr.Delete(keyringService, "token")
	_ = kr.Delete(keyringService, "refreshToken")
	_ = kr.Delete(keyringService, "deviceToken")

	// Clear encryption keys
	keychain.Clear()

	return os.Remove(authConfigPath())
}

// Encryption helpers

// displayEmergencyKit shows the secret key to the user (ONCE, at signup)
func displayEmergencyKit(email, secretKey string) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                     SAVE YOUR SECRET KEY                          ║")
	fmt.Println("║                                                                   ║")
	fmt.Println("║  YOU WILL ONLY SEE THIS ONCE!                                     ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Email: %-57s║\n", email)
	fmt.Println("║                                                                   ║")
	fmt.Println("║  Secret Key:                                                      ║")
	fmt.Printf("║    %-63s║\n", secretKey)
	fmt.Println("║                                                                   ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  You need your Secret Key + Password to:                          ║")
	fmt.Println("║    - Sign in on a new device                                      ║")
	fmt.Println("║    - Decrypt your data                                            ║")
	fmt.Println("║                                                                   ║")
	fmt.Println("║  Store it safely:                                                 ║")
	fmt.Println("║    - Save to a password manager                                   ║")
	fmt.Println("║    - Print and keep in a safe place                               ║")
	fmt.Println("║    - Store in an encrypted notes app                              ║")
	fmt.Println("║                                                                   ║")
	fmt.Println("║  WITHOUT YOUR SECRET KEY, YOUR DATA CANNOT BE DECRYPTED!          ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// promptSecretKey prompts the user to enter their secret key (hidden input)
func promptSecretKey() (string, error) {
	fmt.Print("Secret Key: ")
	input, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	defer zeroBytes(input)

	// Normalize the secret key (remove whitespace, uppercase)
	secretKey := crypto.NormalizeSecretKey(strings.TrimSpace(string(input)))

	if !crypto.ValidateSecretKey(secretKey) {
		return "", fmt.Errorf("invalid secret key format")
	}

	return secretKey, nil
}

// storeSalt stores the encryption salt on the server
func storeSalt(apiBase, token string, salt []byte) error {
	body, _ := json.Marshal(map[string]string{
		"salt": base64.StdEncoding.EncodeToString(salt),
	})

	req, err := http.NewRequest("POST", apiBase+"/auth/salt", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// fetchSalt retrieves the encryption salt from the server
func fetchSalt(apiBase, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", apiBase+"/auth/salt", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Salt string `json:"salt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(result.Salt)
}

// storeTestBlob stores the encryption test blob on the server
func storeTestBlob(apiBase, token string, testBlob []byte) error {
	body, _ := json.Marshal(map[string]string{
		"testBlob": base64.StdEncoding.EncodeToString(testBlob),
	})

	req, err := http.NewRequest("POST", apiBase+"/auth/test-blob", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// fetchTestBlob retrieves the encryption test blob from the server
func fetchTestBlob(apiBase, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", apiBase+"/auth/test-blob", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		TestBlob string `json:"testBlob"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(result.TestBlob)
}
