package cli

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"golang.org/x/term"

	sinesync "github.com/sinesync/cli"
	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/daemon"
	"github.com/sinesync/cli/internal/version"
	"github.com/spf13/cobra"
)

// semverPattern matches version strings like "0.2.0", "v1.2.3", "1.0.0-rc1".
var semverPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$`)

const releaseBucketURL = "https://storage.googleapis.com/sinesync-releases"

// allowPrerelease opts this invocation into installing a prerelease.
var allowPrerelease bool

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
	updateCmd.Flags().BoolVar(&allowPrerelease, "prerelease", false,
		"install a prerelease if one is published as latest")
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

		// Being current is not a reason to leave the install somewhere that
		// needs root. Someone whose update asked for a password, who then
		// fixed their PATH so it would not have to, would otherwise have to
		// wait for an unrelated release before the fix they prepared for
		// became reachable (#161). Silent when the location is already fine.
		if err := offerRelocationWhenCurrent(); err != nil {
			return err
		}
		return nil
	}

	// Refuse to move a stable install onto a prerelease.
	//
	// Compare now orders a prerelease below its own release, so an RC user is
	// correctly offered the finished version. It does NOT stop a prerelease of a
	// LATER version outranking an earlier release: v0.3.0-rc.1 still beats
	// v0.2.0, and should, since the core is genuinely newer. That is the case
	// this gate exists for. Release CI never points `latest` at a prerelease, but
	// `latest` is an unsigned pointer in the same bucket as the artifacts: an
	// attacker who can write there cannot forge a binary (the Ed25519 signature
	// stops that) but CAN repoint `latest` at a real, correctly signed
	// prerelease and have every stable install take it. Signature verification
	// succeeds, because the build is genuine — it is simply not one anyone was
	// meant to run.
	//
	// Opting in means already running a prerelease, or asking for one.
	if version.IsPrerelease(latest) && !allowPrerelease && !version.IsPrerelease(current) {
		fmt.Printf("Latest published version %s is a prerelease; staying on %s.\n", latest, current)
		fmt.Println("Use --prerelease to install it deliberately.")
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

	// Download archive and checksums from versioned subdirectory
	versionURL := fmt.Sprintf("%s/%s", releaseBucketURL, latest)
	fmt.Printf("Downloading %s...\n", archiveName)
	archivePath := filepath.Join(tmpDir, archiveName)
	if err := downloadFile(fmt.Sprintf("%s/%s", versionURL, archiveName), archivePath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	checksumsPath := filepath.Join(tmpDir, "checksums.txt")
	if err := downloadFile(fmt.Sprintf("%s/checksums.txt", versionURL), checksumsPath); err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}

	// Resolve the signing key before spending a download on the signature, so a
	// build with no usable key fails with that reason rather than a network one.
	pubKey, err := releasePublicKey()
	if err != nil {
		return err
	}

	// A missing signature is a hard failure, not a skip: an attacker who can
	// delete the .sig from the bucket must not thereby disable verification.
	sigPath := filepath.Join(tmpDir, "checksums.txt.sig")
	if err := downloadFile(fmt.Sprintf("%s/checksums.txt.sig", versionURL), sigPath); err != nil {
		return fmt.Errorf("failed to download release signature: %w", err)
	}

	// Gate 1: the signature proves checksums.txt is the file the release signer
	// produced. Nothing in checksums.txt is trusted before this passes.
	fmt.Println("Verifying release signature...")
	if err := verifyChecksumsSignature(checksumsPath, sigPath, pubKey); err != nil {
		return fmt.Errorf("release signature verification failed: %w", err)
	}

	// Gate 2: the now-trusted checksums.txt proves the archive is the one that
	// was signed.
	fmt.Println("Verifying checksum...")
	if err := verifyChecksum(archivePath, checksumsPath, archiveName); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Stop the daemon if its PROCESS is alive, not merely if it is healthy.
	//
	// daemon.IsRunning reports false for a daemon that is alive but not
	// answering its health check, which is exactly the state a struggling
	// daemon is in — and skipping the stop then leaves it running from the
	// binary about to be replaced.
	wasRunning := daemon.IsProcessRunning()
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
			if _, err := daemon.Start(daemon.DefaultPort); err != nil {
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

// fetchLatestVersion reads the bucket's /latest pointer.
//
// KNOWN GAP (not addressed here): /latest is unsigned. Signature verification
// proves that whatever version we fetch is authentic, but it cannot prove the
// version is current — an attacker with write access to the bucket can rewrite
// /latest to an older release that was legitimately signed, pinning users to a
// version with known vulnerabilities. Closing this needs a signed, monotonic
// version manifest rather than a bare string. checkForUpdate reads the same
// unsigned pointer.
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

// Release signature verification.
//
// The trust chain has two links. checksums.txt.sig is a detached Ed25519
// signature over the exact bytes of checksums.txt, verified against a public key
// baked into this binary at build time; checksums.txt in turn carries the SHA256
// of every platform archive. Verifying the signature first and the archive's
// SHA256 second means an attacker who can write to the release bucket cannot
// substitute either one without holding the private key.
//
// Consequence worth knowing when reading test names: an archive modified after
// signing is rejected as a *checksum* failure, not a signature failure. The
// signature covers checksums.txt, and the SHA256 chain covers the archive. Both
// paths reject; only the error class differs.
var (
	// errNoReleaseKey means this build has no usable signing key embedded.
	errNoReleaseKey = errors.New("this build has no release signing key; refusing to install an unverified update")
	// errMalformedKey means the embedded key is present but not a valid key.
	errMalformedKey = errors.New("embedded release public key is malformed")
	// errMalformedSignature means checksums.txt.sig is not a well-formed signature.
	errMalformedSignature = errors.New("release signature is malformed")
	// errBadSignature means the signature did not verify against the public key.
	errBadSignature = errors.New("release signature verification failed")
)

// placeholderKeyPrefix marks a key file that is a stand-in rather than a real
// key. A build carrying one refuses to update rather than silently skipping
// verification.
const placeholderKeyPrefix = "PLACEHOLDER"

// parseReleasePublicKey decodes a base64-encoded raw 32-byte Ed25519 public key.
// Callers pass the embedded key; tests pass one they generated.
func parseReleasePublicKey(encoded string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" || strings.HasPrefix(trimmed, placeholderKeyPrefix) {
		return nil, errNoReleaseKey
	}

	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base64: %v", errMalformedKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", errMalformedKey, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// releasePublicKey returns the key this binary was built with.
func releasePublicKey() (ed25519.PublicKey, error) {
	return parseReleasePublicKey(sinesync.ReleaseEd25519PublicKey)
}

// verifyChecksumsSignature checks that sigPath is a valid detached Ed25519
// signature by pub over the exact bytes of checksumsPath.
//
// The signature file must be base64-encoded. Raw binary is deliberately not
// accepted as a fallback: a parser that guesses between encodings is a parser an
// attacker can steer.
func verifyChecksumsSignature(checksumsPath, sigPath string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errNoReleaseKey
	}

	checksums, err := os.ReadFile(checksumsPath)
	if err != nil {
		return fmt.Errorf("cannot read checksums: %w", err)
	}

	encoded, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("cannot read signature: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return fmt.Errorf("%w: not valid base64: %v", errMalformedSignature, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: got %d bytes, want %d", errMalformedSignature, len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pub, checksums, sig) {
		return errBadSignature
	}
	return nil
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

	// The install lives somewhere this user cannot write, so this update needs
	// root — and root needs a terminal, which means updates here can never be
	// automated, scheduled or run from a hook. Offer to move the install
	// somewhere writable so this is the last time (#160).
	if moved, err := offerRelocation(newBinaryPath, currentPath); err != nil {
		return err
	} else if moved {
		return nil
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

// copyFile replaces dst with src atomically: write a temporary file beside it,
// then rename over the top.
//
// It used to open dst with O_TRUNC and copy into it, which destroys the
// existing file BEFORE knowing the new contents can be written. Replacing a
// running executable fails on macOS, so the truncate landed, the write did not,
// and the install was left as a zero-byte binary — with the tool that would
// have repaired it being the one just destroyed.
//
// Rename cannot half-happen. Either the destination is the old file or it is
// the complete new one, and a failure anywhere before that leaves the old one
// untouched. It also replaces a running binary safely on Unix: the directory
// entry changes while the running process keeps the inode it started from.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Beside the destination, so the rename stays within one filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".sinesync-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Removes the temporary file on every path that does not rename it away.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, dst)
}

// checkForUpdate is a non-blocking check that prints a notice if a newer version exists.
// Called as a fire-and-forget goroutine from status and daemon start.
//
// This reads the same unsigned /latest pointer as fetchLatestVersion — see the
// KNOWN GAP note there. It only prints a notice and installs nothing, so the
// exposure is limited to suppressing or faking an update prompt.
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

// userBinDir is the conventional per-user binary directory.
func userBinDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "bin")
}

// pathPrecedes reports whether `first` is found before `second` on PATH.
//
// It decides whether relocating is safe to do at all. Installing into a
// directory that PATH consults AFTER the current one would leave the old
// binary winning every lookup, so the update would appear to do nothing —
// worse than needing sudo, because it would be silent.
func pathPrecedes(first, second string) bool {
	firstAt, secondAt := -1, -1
	for i, entry := range filepath.SplitList(os.Getenv("PATH")) {
		clean := filepath.Clean(entry)
		if firstAt == -1 && clean == filepath.Clean(first) {
			firstAt = i
		}
		if secondAt == -1 && clean == filepath.Clean(second) {
			secondAt = i
		}
	}
	return firstAt != -1 && (secondAt == -1 || firstAt < secondAt)
}

// offerRelocation asks whether to move the install to a writable directory,
// and does it if the answer is yes. Reports whether the update is complete.
//
// Declines silently in every case where it cannot be sure the result would be
// an improvement — no home directory, the target not on PATH ahead of the
// current location, or no terminal to ask at. Falling back to sudo is a worse
// experience but a known one; a relocation that leaves the old binary shadowing
// the new one would be a silent failure.
func offerRelocation(newBinaryPath, currentPath string) (bool, error) {
	dest := userBinDir()
	if dest == "" {
		return false, nil
	}

	currentDir := filepath.Dir(currentPath)
	if filepath.Clean(dest) == filepath.Clean(currentDir) {
		return false, nil
	}

	if !pathPrecedes(dest, currentDir) {
		fmt.Printf("\nTip: installing to %s would let future updates run without sudo,\n"+
			"     but it is not on your PATH ahead of %s.\n"+
			"     Add it to PATH first, then run update again.\n\n", dest, currentDir)
		return false, nil
	}

	// Never block waiting for an answer nobody can give.
	if !isInteractive() {
		fmt.Printf("\nTip: run this from a terminal and %s can be moved to %s,\n"+
			"     after which updates will not need sudo.\n\n", filepath.Base(currentPath), dest)
		return false, nil
	}

	fmt.Printf("\n%s is not writable, so updating there needs sudo.\n", currentDir)
	fmt.Printf("Move the install to %s so future updates do not? [y/N]: ", dest)

	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		return false, nil
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return false, fmt.Errorf("cannot create %s: %w", dest, err)
	}

	destPath := filepath.Join(dest, filepath.Base(currentPath))
	if err := copyFile(newBinaryPath, destPath); err != nil {
		return false, fmt.Errorf("cannot install to %s: %w", dest, err)
	}
	if err := os.Chmod(destPath, 0o755); err != nil {
		return false, fmt.Errorf("cannot make %s executable: %w", destPath, err)
	}

	fmt.Printf("Installed to %s\n", destPath)

	// Remove the old one, which needs sudo this once. If it fails, the new
	// binary still wins on PATH, so say exactly that rather than reporting a
	// failure the user cannot act on.
	fmt.Printf("Removing the old install at %s (sudo, this once)...\n", currentPath)
	rm := exec.Command("sudo", "rm", "-f", currentPath)
	rm.Stdin, rm.Stdout, rm.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := rm.Run(); err != nil {
		fmt.Printf("\nCould not remove %s: %v\n", currentPath, err)
		fmt.Printf("The new install at %s comes first on PATH, so it is what runs.\n", destPath)
		fmt.Printf("Remove the old one when convenient: sudo rm %s\n\n", currentPath)
	}

	return true, nil
}

// isInteractive reports whether there is a terminal to prompt at.
//
// Without one, sudo cannot ask for a password either, which is the whole
// reason an unattended update fails here.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// offerRelocationWhenCurrent offers to move an up-to-date install out of a
// directory that needs root.
//
// Being current is not a reason to leave it there. The natural sequence for
// someone stuck with a sudo-requiring install is: run update, see it ask for a
// password, fix PATH so it would not have to, run update again to take the
// offer — and that last step did nothing, because by then there was no update
// to install and the offer lived only on the install path (#161).
//
// Silent when the location is already writable, so the ordinary case is
// unchanged.
func offerRelocationWhenCurrent() error {
	if runtime.GOOS == "windows" {
		return nil
	}

	currentPath, err := os.Executable()
	if err != nil {
		return nil
	}
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return nil
	}

	return relocateIfInstallNeedsRoot(currentPath)
}

// relocateIfInstallNeedsRoot does the work of offerRelocationWhenCurrent for a
// given install path. Split out so the gate can be tested without a real
// executable: an install that is already writable must return silently, having
// touched nothing — no prompt, and no stopping the daemon.
func relocateIfInstallNeedsRoot(currentPath string) error {
	if isWritable(filepath.Dir(currentPath)) {
		return nil
	}

	// The daemon runs from the binary being moved, so it is stopped first and
	// restarted afterwards from whichever path now wins — the same care the
	// update path takes, for the same reason. Skipping it would leave a daemon
	// running from a file that is about to be deleted.
	wasRunning, _ := daemon.IsRunning()
	if wasRunning {
		if err := daemon.Stop(); err != nil {
			fmt.Printf("Warning: failed to stop daemon: %v\n", err)
		}
	}
	restart := func() {
		if !wasRunning {
			return
		}
		if _, err := daemon.Start(daemon.DefaultPort); err != nil {
			fmt.Printf("Warning: failed to restart daemon: %v\n", err)
		}
	}

	// The binary to install is the one already running.
	moved, err := offerRelocation(currentPath, currentPath)
	restart()
	if err != nil {
		return err
	}
	if moved {
		fmt.Println("Updates from here on will not need sudo.")
	}
	return nil
}
