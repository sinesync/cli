package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/fmitra/srp"
	"github.com/miclip/sinesync/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

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

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(signupCmd)
	rootCmd.AddCommand(logoutCmd)
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
	var email string
	fmt.Print("Email: ")
	fmt.Scanln(&email)

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

	// Step 2: Register this device
	hostname := getHostname()
	platform := getPlatform()

	fmt.Printf("Registering device: %s (%s)...\n", hostname, platform)

	deviceResp, err := registerDevice(apiBase, loginResp.Token, hostname, platform)
	if err != nil {
		return fmt.Errorf("device registration failed: %w", err)
	}

	fmt.Println("✓ Device registered")

	// Save auth config
	authCfg := &AuthConfig{
		UserID:       loginResp.User.ID,
		Email:        loginResp.User.Email,
		Token:        loginResp.Token,
		RefreshToken: loginResp.RefreshToken,
		ExpiresAt:    loginResp.ExpiresAt,
		DeviceID:     deviceResp.Device.ID,
		DeviceToken:  deviceResp.Token,
	}

	if err := saveAuthConfig(authCfg); err != nil {
		return fmt.Errorf("failed to save auth: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Logged in successfully!")
	fmt.Printf("  User: %s\n", authCfg.Email)
	fmt.Printf("  Device: %s\n", hostname)
	fmt.Println()
	fmt.Println("Cloud sync is now enabled.")

	return nil
}

func runSignup(cmd *cobra.Command, args []string) error {
	apiBase := getAPIBase()

	// Get email
	var email string
	fmt.Print("Email: ")
	fmt.Scanln(&email)

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

	// Generate SRP verifier using fmitra/srp (SHA256 + RFC5054 Group4096)
	srpClient, err := srp.NewDefaultClient(email, password)
	if err != nil {
		return fmt.Errorf("failed to create SRP client: %w", err)
	}

	_, salt, verifierBI, err := srpClient.Enroll()
	if err != nil {
		return fmt.Errorf("failed to create SRP verifier: %w", err)
	}

	// Convert verifier big.Int to hex string (salt is already string)
	verifier := fmt.Sprintf("%x", verifierBI)

	// Signup with SRP credentials
	signupResp, err := doSignup(apiBase, email, salt, verifier)
	if err != nil {
		return fmt.Errorf("signup failed: %w", err)
	}

	fmt.Println("✓ Account created")

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
	authCfg := &AuthConfig{
		UserID:       signupResp.User.ID,
		Email:        signupResp.User.Email,
		Token:        signupResp.Token,
		RefreshToken: signupResp.RefreshToken,
		ExpiresAt:    signupResp.ExpiresAt,
		DeviceID:     deviceResp.Device.ID,
		DeviceToken:  deviceResp.Token,
	}

	if err := saveAuthConfig(authCfg); err != nil {
		return fmt.Errorf("failed to save auth: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Account created and logged in!")
	fmt.Printf("  User: %s\n", authCfg.Email)
	fmt.Printf("  Device: %s\n", hostname)
	fmt.Println()
	fmt.Println("You have a 14-day free trial.")

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
	// Create SRP client (SHA256 + RFC5054 Group4096)
	srpClient, err := srp.NewDefaultClient(email, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRP client: %w", err)
	}

	// Get client public key A
	_, clientPublicBI := srpClient.Auth()
	clientPublic := fmt.Sprintf("%x", clientPublicBI)

	// Step 1: Init - send email to get salt and server public B
	initBody, _ := json.Marshal(map[string]string{"email": email})
	initReq, err := http.NewRequest("POST", apiBase+"/auth/login/init", bytes.NewReader(initBody))
	if err != nil {
		return nil, err
	}
	initReq.Header.Set("Content-Type", "application/json")
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

	// Convert server public B from hex to big.Int
	serverPublicBI := new(big.Int)
	serverPublicBI.SetString(initResult.ServerPublic, 16)

	// Step 2: Compute client proof M1 (takes B as *big.Int, salt as string)
	clientProofBI, err := srpClient.ProveIdentity(serverPublicBI, initResult.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to compute proof: %w", err)
	}
	clientProof := fmt.Sprintf("%x", clientProofBI)

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

	// Convert server proof from hex to big.Int and verify
	serverProofBI := new(big.Int)
	serverProofBI.SetString(result.ServerProof, 16)
	if !srpClient.IsProofValid(serverProofBI) {
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

	return &cfg, nil
}

func removeAuthConfig() error {
	return os.Remove(authConfigPath())
}
