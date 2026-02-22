package cli

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"regexp"

	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/daemon"
	"github.com/miclip/sinesync/internal/version"
	"github.com/spf13/cobra"
)

// semverPattern matches version strings like "0.2.0", "v1.2.3", "1.0.0-rc1".
var semverPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$`)

const releaseBucketURL = "https://storage.googleapis.com/sinesync-releases"

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update sinesync to the latest version",
	Long: `Check for a newer version and update the sinesync binary.

Downloads the latest release, verifies the SHA256 checksum, and replaces
the current binary. The daemon is stopped before the update and restarted
after if it was running.`,
	RunE: runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	current := version.Get()
	fmt.Printf("Current version: %s\n", current)

	// Fetch latest version
	latest, err := fetchLatestVersion()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if !version.IsNewer(latest, current) {
		fmt.Println("Already up to date.")
		return nil
	}

	fmt.Printf("New version available: %s\n", latest)
	fmt.Print("Update now? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		fmt.Println("Update cancelled.")
		return nil
	}

	// Detect platform
	osName := runtime.GOOS
	arch := runtime.GOARCH

	// Build archive name
	var archiveName string
	if osName == "windows" {
		archiveName = fmt.Sprintf("sinesync-%s-%s-%s.zip", latest, osName, arch)
	} else {
		archiveName = fmt.Sprintf("sinesync-%s-%s-%s.tar.gz", latest, osName, arch)
	}

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "sinesync-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download archive and checksums
	fmt.Printf("Downloading %s...\n", archiveName)
	archivePath := filepath.Join(tmpDir, archiveName)
	if err := downloadFile(fmt.Sprintf("%s/%s", releaseBucketURL, archiveName), archivePath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	checksumsPath := filepath.Join(tmpDir, "checksums.txt")
	if err := downloadFile(fmt.Sprintf("%s/checksums.txt", releaseBucketURL), checksumsPath); err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}

	// Verify checksum
	fmt.Println("Verifying checksum...")
	if err := verifyChecksum(archivePath, checksumsPath, archiveName); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Stop daemon if running
	wasRunning, _ := daemon.IsRunning()
	if wasRunning {
		fmt.Println("Stopping daemon...")
		if err := daemon.Stop(); err != nil {
			fmt.Printf("Warning: failed to stop daemon: %v\n", err)
		}
	}

	// Ensure daemon is restarted if it was running, even on failure
	restartDaemon := func() {
		if wasRunning {
			fmt.Println("Restarting daemon...")
			if err := daemon.Start(daemon.DefaultPort); err != nil {
				fmt.Printf("Warning: failed to restart daemon: %v\n", err)
			}
		}
	}

	// Extract binary from archive
	fmt.Println("Extracting...")
	var binaryPath string
	if osName == "windows" {
		binaryPath, err = extractZip(archivePath, tmpDir)
	} else {
		binaryPath, err = extractTarGz(archivePath, tmpDir)
	}
	if err != nil {
		restartDaemon()
		return fmt.Errorf("extraction failed: %w", err)
	}

	// Replace binary
	fmt.Println("Installing...")
	if err := replaceBinary(binaryPath); err != nil {
		restartDaemon()
		return fmt.Errorf("install failed: %w", err)
	}

	restartDaemon()
	fmt.Printf("Updated to %s\n", latest)
	return nil
}

func fetchLatestVersion() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(releaseBucketURL + "/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	v := strings.TrimSpace(string(body))
	if !semverPattern.MatchString(v) {
		return "", fmt.Errorf("server returned invalid version: %q", v)
	}
	return v, nil
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d for %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func verifyChecksum(archivePath, checksumsPath, archiveName string) error {
	// Compute SHA256 of archive
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualSum := hex.EncodeToString(h.Sum(nil))

	// Read checksums file and find matching entry
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == archiveName {
			if parts[0] != actualSum {
				return fmt.Errorf("checksum mismatch: expected %s, got %s", parts[0], actualSum)
			}
			return nil
		}
	}

	return fmt.Errorf("no checksum found for %s in checksums.txt", archiveName)
}

func extractTarGz(archivePath, destDir string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	binaryName := "sinesync"

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		// Look for the sinesync binary (may be at root or in a subdirectory)
		name := filepath.Base(hdr.Name)
		if name == binaryName && hdr.Typeflag == tar.TypeReg {
			destPath := filepath.Join(destDir, binaryName)
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return "", err
			}
			outFile.Close()
			return destPath, nil
		}
	}

	return "", fmt.Errorf("sinesync binary not found in archive")
}

func extractZip(archivePath, destDir string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	binaryName := "sinesync.exe"

	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if name == binaryName && !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}

			destPath := filepath.Join(destDir, binaryName)
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				rc.Close()
				return "", err
			}

			_, copyErr := io.Copy(outFile, rc)
			outFile.Close()
			rc.Close()
			if copyErr != nil {
				return "", copyErr
			}
			return destPath, nil
		}
	}

	return "", fmt.Errorf("sinesync.exe not found in archive")
}

func replaceBinary(newBinaryPath string) error {
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine current binary path: %w", err)
	}

	// Resolve symlinks
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return fmt.Errorf("cannot resolve symlinks: %w", err)
	}

	if runtime.GOOS == "windows" {
		// Windows: can't overwrite running binary, rename current then copy new
		oldPath := currentPath + ".old"
		os.Remove(oldPath) // Clean up any leftover from a previous failed update
		if err := os.Rename(currentPath, oldPath); err != nil {
			return fmt.Errorf("failed to rename current binary: %w", err)
		}
		if err := copyFile(newBinaryPath, currentPath); err != nil {
			// Try to restore
			os.Rename(oldPath, currentPath)
			return fmt.Errorf("failed to copy new binary: %w", err)
		}
		os.Remove(oldPath)
		return nil
	}

	// Unix: check if we can write to the target directory
	targetDir := filepath.Dir(currentPath)
	if isWritable(targetDir) {
		// Direct replace: rename new binary over old
		if err := copyFile(newBinaryPath, currentPath); err != nil {
			return err
		}
		return os.Chmod(currentPath, 0755)
	}

	// Need elevated permissions
	fmt.Println("Root permissions required to update. You may be prompted for your password.")
	mvCmd := exec.Command("sudo", "mv", newBinaryPath, currentPath)
	mvCmd.Stdin = os.Stdin
	mvCmd.Stdout = os.Stdout
	mvCmd.Stderr = os.Stderr
	if err := mvCmd.Run(); err != nil {
		return fmt.Errorf("sudo mv failed: %w", err)
	}

	chmodCmd := exec.Command("sudo", "chmod", "755", currentPath)
	chmodCmd.Stdin = os.Stdin
	chmodCmd.Stdout = os.Stdout
	chmodCmd.Stderr = os.Stderr
	return chmodCmd.Run()
}

func isWritable(path string) bool {
	testFile := filepath.Join(path, ".sinesync-write-test")
	f, err := os.Create(testFile)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(testFile)
	return true
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// checkForUpdate is a non-blocking check that prints a notice if a newer version exists.
// Called as a fire-and-forget goroutine from status and daemon start.
func checkForUpdate() {
	checkFile := filepath.Join(config.DataDir(), "update-check.json")

	// Rate limit: at most once per 24 hours
	if data, err := os.ReadFile(checkFile); err == nil {
		var state struct {
			LastCheck time.Time `json:"lastCheck"`
		}
		if json.Unmarshal(data, &state) == nil && time.Since(state.LastCheck) < 24*time.Hour {
			return
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(releaseBucketURL + "/latest")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	latest := strings.TrimSpace(string(body))
	if !semverPattern.MatchString(latest) {
		return
	}
	if version.IsNewer(latest, version.Get()) {
		fmt.Fprintf(os.Stderr, "\nA newer version (%s) is available. Run 'sinesync update' to upgrade.\n", latest)
	}

	// Ensure data dir exists before writing check file
	os.MkdirAll(filepath.Dir(checkFile), 0755)

	// Save check timestamp
	state, _ := json.Marshal(struct {
		LastCheck time.Time `json:"lastCheck"`
	}{LastCheck: time.Now()})
	os.WriteFile(checkFile, state, 0600)
}
