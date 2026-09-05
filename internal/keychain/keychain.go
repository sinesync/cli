package keychain

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const serviceName = "sinesync"

// securityBinary is the macOS keychain CLI, addressed absolutely.
//
// It must stay identical to go-keyring's own execPathKeychain
// (keyring_darwin.go), which is unexported and so cannot be referenced from
// here. The two are a matched pair: if this probe and the library disagree
// about which binary they reach, the guard can veto a keychain the library
// would have used.
const securityBinary = "/usr/bin/security"

// ErrNoKeychainSession means this process cannot reach an OS keychain without
// blocking on user interaction, so no keychain call was attempted.
//
// Callers must treat it as "unknown", never as "absent". Reacting by creating a
// replacement key would orphan a database encrypted with the real one.
var ErrNoKeychainSession = errors.New("no keychain session available in this context")

// noKeychainEnv disables all keychain access when set to anything but "0".
const noKeychainEnv = "SINESYNC_NO_KEYCHAIN"

// DisabledByEnv reports whether the user has explicitly opted out of the
// keychain. Callers need this to tell a deliberate opt-out apart from a machine
// with no reachable keyring: both surface as ErrNoKeychainSession, but only one
// of them is fixed by changing the environment, and telling a user to unset a
// variable they never set is how a real fault gets mistaken for a typo.
func DisabledByEnv() bool {
	v := os.Getenv(noKeychainEnv)
	return v != "" && v != "0"
}

// usable reports whether the OS keychain can be reached without raising UI.
//
// This exists because of a specific, destructive failure. When a process with no
// GUI session touches the macOS keychain — a daemon started via nohup, an MCP
// server spawned by an agent, anything over SSH, CI — the Security framework
// does not return an error. It puts a modal "Keychain Not Found" panel on
// screen whose primary button is "Reset To Defaults", which would discard the
// user's stored secret key and session tokens. A headless process must
// therefore decide BEFORE calling, not handle an error afterwards.
//
// Probed once: the answer cannot change within a process lifetime, and the
// darwin probe shells out.
var usable = sync.OnceValue(detectUsable)

func detectUsable() bool {
	return detectUsableFor(runtime.GOOS)
}

// detectUsableFor takes the platform as a parameter rather than reading
// runtime.GOOS so that every platform's answer is reachable from a test on any
// machine. The previous Linux branch was a hand-rolled D-Bus discovery that no
// one working on a Mac could execute, which is part of how it drifted from the
// library it was standing in front of.
func detectUsableFor(goos string) bool {
	// Explicit override, for containers and anywhere the heuristics are wrong.
	if DisabledByEnv() {
		return false
	}

	switch goos {
	case "darwin":
		// Probe the exact condition that fails: no DEFAULT keychain. That is
		// what raised the modal — the process had a perfectly good GUI session,
		// it just could not resolve a keychain, because it had been started with
		// an environment whose HOME did not point at one. Session-type checks
		// like `launchctl managername` return "Aqua" in that case and miss it.
		//
		// Probing through the `security` CLI rather than in-process is the whole
		// trick. It is a subprocess with no GUI connection, so the same
		// condition comes back as text on stderr and a non-zero result instead
		// of a panel offering to reset the user's keychain.
		//
		// By absolute path, not through $PATH. go-keyring reaches this same
		// binary as a hard-coded /usr/bin/security, so a $PATH that cannot
		// resolve `security` — empty, minimal, a daemon's inherited environment,
		// or one whose leading empty element makes Go refuse the match as a
		// relative path — would make this guard answer "no keychain" while the
		// library it stands in front of would have succeeded. That disagreement
		// is not a safe default: the daemon now refuses to start when the key
		// cannot be resolved, so a false negative here takes down a daemon whose
		// keychain was reachable all along. Fixing the path also means the probe
		// can never execute a `security` someone left in the working directory.
		out, err := exec.Command(securityBinary, "default-keychain").CombinedOutput()
		if err != nil {
			return false
		}
		// `security` exits 0 even when it cannot find one, so read the output.
		// On success it prints the default keychain's path; on failure it prints
		// a SecKeychainCopyDefault error. Match the failure, not the success —
		// the keychain's filename is user-configurable, so requiring it to look
		// a particular way would reject valid custom keychains and drop the user
		// to plaintext storage for no reason.
		text := strings.TrimSpace(string(out))
		if text == "" ||
			strings.Contains(text, "could not be found") ||
			strings.Contains(text, "SecKeychainCopyDefault") {
			return false
		}
		// Deliberately NOT also rejecting a locked keychain, though
		// `security show-keychain-info` could detect one. A locked keychain
		// raises an ordinary unlock prompt: expected, benign, and dismissible
		// by unlocking. What this guard exists to prevent is the panel raised
		// when there is no default keychain at all, whose primary button erases
		// the user's stored secrets. Rejecting locked keychains too would trade
		// a benign prompt for more false negatives, and a false negative here
		// silently drops the user to plaintext storage — the worse outcome.
		return true

	default:
		// Every other platform, Linux included: do not gate. Answer "usable" and
		// let go-keyring report its own failure.
		//
		// This guard exists for one specific thing — the macOS panel whose
		// primary button erases the user's secrets, which must be avoided BEFORE
		// calling because it is not an error you can handle afterwards. Nothing
		// off darwin has that property. Windows Credential Manager works without
		// a desktop session, and Linux Secret Service returns a D-Bus error
		// rather than prompting. With no modal to prevent, a Linux gate had no
		// upside left, only the cost of being wrong.
		//
		// And it was wrong in the destructive direction. It tried to predict
		// whether godbus could find a session bus, but godbus's real discovery
		// (dbus/v5@v5.1.0 conn.go:76 getSessionBusAddress, conn_other.go) is
		// strictly more permissive than any reimplementation can be: go-keyring
		// reaches it via dbus.SessionBus, which passes autolaunch=true, so when
		// no address and no /run/user socket exist it still runs `dbus-launch`
		// and can succeed. A probe cannot mirror that — replicating it means
		// spawning a daemon to answer a question, which is not something a probe
		// gets to do. So the check was permanently a subset of the library, and
		// a subset here means false negatives, and since the daemon refuses to
		// start without a key, a false negative is a daemon that will not run on
		// a machine whose keyring works.
		// (godbus is also more forgiving on stat: conn_other.go:89 accepts any
		// error that is not IsNotExist, where the guard demanded err == nil.)
		//
		// The two properties the guard was carrying are not lost:
		//
		//   - Nothing invents a replacement key. CreateLocalDBKey is only
		//     reached when DBKeyCandidates came back empty, which on Linux
		//     means keyring.ErrNotFound, and go-keyring's Linux backend
		//     produces that solely from an empty search result
		//     (keyring_unix.go:73). A bus that cannot be reached surfaces the
		//     dbus error verbatim (keyring_unix.go:104-108), which is not
		//     ErrNotFound, so the create path stays closed.
		//   - SINESYNC_NO_KEYCHAIN still short-circuits above, so anyone who
		//     needs to opt a headless box out entirely still can.
		//
		// What is given up is a tailored message: a headless Linux daemon now
		// reports the raw D-Bus error instead of ErrNoKeychainSession. Both land
		// in the same plaintext-fallback warning, and a real error beats a
		// guess about one.
		return true
	}
}

// Get, Set and Delete are the ONLY paths from this codebase to the OS keychain.
//
// They exist because a guard is worth nothing if callers can route around it,
// and they could: the daemon and CLI previously reached for go-keyring directly
// with the same "sinesync" service name, so the availability check protected
// database-key resolution and nothing else. Session tokens and sync credentials
// went straight to the Security framework and could still raise the modal these
// functions exist to prevent.
//
// Nothing outside this package should import go-keyring.

func Get(key string) (string, error) {
	if !usable() {
		return "", ErrNoKeychainSession
	}
	return keyring.Get(serviceName, key)
}

func Set(key, value string) error {
	if !usable() {
		return ErrNoKeychainSession
	}
	return keyring.Set(serviceName, key, value)
}

func Delete(key string) error {
	if !usable() {
		return ErrNoKeychainSession
	}
	return keyring.Delete(serviceName, key)
}

// Session token
func GetSessionToken() (string, error) {
	return Get("session-token")
}

func SetSessionToken(token string) error {
	return Set("session-token", token)
}

// User salt
func GetUserSalt() ([]byte, error) {
	encoded, err := Get("user-salt")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetUserSalt(salt []byte) error {
	encoded := base64.StdEncoding.EncodeToString(salt)
	return Set("user-salt", encoded)
}

// Secret key
func GetSecretKey() (string, error) {
	return Get("secret-key")
}

func SetSecretKey(key string) error {
	return Set("secret-key", key)
}

// Derived key
func GetDerivedKey() ([]byte, error) {
	encoded, err := Get(EntryDerivedKey)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetDerivedKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return Set(EntryDerivedKey, encoded)
}

func ClearDerivedKey() error {
	return Delete(EntryDerivedKey)
}

// Last auth timestamp
func GetLastAuth() (time.Time, error) {
	ts, err := Get("last-auth")
	if err != nil {
		return time.Time{}, err
	}
	epoch, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(epoch, 0), nil
}

func SetLastAuth(t time.Time) error {
	return Set("last-auth", strconv.FormatInt(t.Unix(), 10))
}

// NeedsReauth checks if re-authentication is needed (24 hours)
func NeedsReauth() bool {
	lastAuth, err := GetLastAuth()
	if err != nil {
		return true
	}
	return time.Since(lastAuth) > 24*time.Hour
}

// Local DB key (for SQLCipher encryption before login)
func GetLocalDBKey() ([]byte, error) {
	encoded, err := Get(EntryLocalDBKey)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetLocalDBKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return Set(EntryLocalDBKey, encoded)
}

// Device key (for SSO credential bundle encryption)

func GetDeviceKey() ([]byte, error) {
	encoded, err := Get("device-key")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetDeviceKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return Set("device-key", encoded)
}

func DeleteDeviceKey() error {
	return Delete("device-key")
}

func HasDeviceKey() bool {
	key, err := GetDeviceKey()
	return err == nil && len(key) > 0
}

// Clear removes all stored credentials
func Clear() error {
	return ClearExcept(nil)
}

// ClearExcept removes all stored credentials except those in the keep list.
func ClearExcept(keep []string) error {
	allKeys := []string{"session-token", "user-salt", "secret-key", EntryDerivedKey, "last-auth", EntryLocalDBKey, "device-key"}
	keepSet := make(map[string]bool, len(keep))
	for _, k := range keep {
		keepSet[k] = true
	}
	// Through the guarded Delete, not keyring.Delete. Teardown and stale-login
	// cleanup both reach here, and both can run headless — deleting is exactly
	// as capable of raising the modal as reading.
	for _, key := range allKeys {
		if !keepSet[key] {
			_ = Delete(key) // best effort: a key that was never set is not an error
		}
	}
	return nil
}
