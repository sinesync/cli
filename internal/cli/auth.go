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
	"runtime"
	"strings"
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

	// Get password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
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

	// Store tokens in system keychain
	if cfg.Token != "" {
		if err := kr.Set(keyringService, "token", cfg.Token); err != nil {
			// Fall back to file storage if keychain unavailable
			fmt.Fprintf(os.Stderr, "Warning: system keychain unavailable, storing tokens in %s\n", authConfigPath())
			return saveAuthConfigToFile(cfg)
		}
	}
	if cfg.RefreshToken != "" {
		_ = kr.Set(keyringService, "refreshToken", cfg.RefreshToken)
	}
	if cfg.DeviceToken != "" {
		_ = kr.Set(keyringService, "deviceToken", cfg.DeviceToken)
	}

	// Store non-sensitive data in file
	fileCfg := AuthConfig{
		UserID:    cfg.UserID,
		Email:     cfg.Email,
		ExpiresAt: cfg.ExpiresAt,
		DeviceID:  cfg.DeviceID,
	}
	data, err := json.MarshalIndent(fileCfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(authConfigPath(), data, 0600)
}

func saveAuthConfigToFile(cfg *AuthConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
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
