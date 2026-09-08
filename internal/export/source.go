package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/sinesync/cli/internal/crypto"
)

// APISource pulls encrypted observations from the sinesync API and decrypts them
// locally with the organization key.
//
// Decryption happens here, in the customer's own process, which is the whole
// point of #104: our servers never hold the plaintext this daemon writes.
type APISource struct {
	base     string
	keyID    string
	secret   string
	vaultIDs []string
	client   *http.Client

	// orgPrivateKey unwraps each vault key. Held for the life of the daemon
	// because every pass needs it; the process is expected to be the trust
	// boundary, and it is the customer's own.
	orgPrivateKey []byte

	mu        sync.Mutex
	token     string
	tokenTill time.Time
	vaultKeys map[string][]byte

	// decryptFn is the observation decryptor, injectable so the source can be
	// tested without a server.
	decryptFn func(encrypted, key []byte) (json.RawMessage, string, error)
}

// NewAPISource builds a source. The org private key is the caller's to zero.
func NewAPISource(base, keyID, secret string, vaultIDs []string, orgPrivateKey []byte) *APISource {
	return &APISource{
		base:     base,
		keyID:    keyID,
		secret:   secret,
		vaultIDs: vaultIDs,
		// Bounded for the same reason the artifact downloads are: this runs
		// unattended, and a stalled response must not wedge the daemon.
		client:        &http.Client{Timeout: 2 * time.Minute},
		orgPrivateKey: orgPrivateKey,
		vaultKeys:     map[string][]byte{},
		decryptFn:     decryptObservation,
	}
}

// token returns a valid service account token, exchanging credentials when the
// current one is near expiry.
//
// Refreshed early rather than on failure: a token that expires mid-pass would
// turn into a 401 the loop reports as an error, when it is really routine.
func (s *APISource) accessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.tokenTill.Add(-time.Minute)) {
		return s.token, nil
	}

	body, _ := json.Marshal(map[string]string{"keyId": s.keyID, "secret": s.secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.base+"/v1/service-accounts/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchanging service account credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The server answers alike for an unknown key, a wrong secret and a
		// revoked account, so there is nothing more specific to report.
		return "", fmt.Errorf("service account credentials refused (HTTP %d)", resp.StatusCode)
	}

	var out struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("reading token: %w", err)
	}

	s.token = out.Token
	s.tokenTill = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return s.token, nil
}

type encryptedObservation struct {
	ID        string `json:"id"`
	VaultID   string `json:"vaultId"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// Fetch implements Source.
func (s *APISource) Fetch(ctx context.Context, after Cursor, limit int) ([]Observation, bool, error) {
	token, err := s.accessToken(ctx)
	if err != nil {
		return nil, false, err
	}

	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if !after.UpdatedAt.IsZero() {
		q.Set("afterUpdatedAt", after.UpdatedAt.UTC().Format(time.RFC3339Nano))
		// The id half of the cursor, so the server can break a tie the same way
		// the target does.
		q.Set("afterId", after.ID)
	}
	for _, v := range s.vaultIDs {
		q.Add("vaultId", v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.base+"/v1/sync/export?"+q.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetching observations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Forget the token so the next attempt exchanges a fresh one rather
		// than retrying with the same dead credential.
		s.mu.Lock()
		s.token = ""
		s.mu.Unlock()
		return nil, false, fmt.Errorf("service account token rejected")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("fetching observations: HTTP %d", resp.StatusCode)
	}

	var page struct {
		Items []encryptedObservation `json:"items"`
		More  bool                   `json:"more"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, false, fmt.Errorf("reading observations: %w", err)
	}

	out := make([]Observation, 0, len(page.Items))
	for _, item := range page.Items {
		o, err := s.decrypt(ctx, item)
		if err != nil {
			// One undecryptable record must not stop the export: it would block
			// every later observation behind it forever, and the cursor would
			// never advance past it.
			continue
		}
		out = append(out, o)
	}

	return out, page.More, nil
}

// vaultKey unwraps and caches a vault key using the org private key.
func (s *APISource) vaultKey(ctx context.Context, vaultID string) ([]byte, error) {
	s.mu.Lock()
	if k, ok := s.vaultKeys[vaultID]; ok {
		s.mu.Unlock()
		return k, nil
	}
	s.mu.Unlock()

	token, err := s.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.base+"/v1/vaults/"+url.PathEscape(vaultID)+"/key", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching vault key: HTTP %d", resp.StatusCode)
	}

	var out struct {
		EncryptedVaultKey string `json:"encryptedVaultKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	key, err := crypto.X25519Open(out.EncryptedVaultKey, string(s.orgPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("unwrapping vault key: %w", err)
	}

	s.mu.Lock()
	s.vaultKeys[vaultID] = key
	s.mu.Unlock()
	return key, nil
}

// decrypt turns one encrypted record into an exportable observation.
func (s *APISource) decrypt(ctx context.Context, item encryptedObservation) (Observation, error) {
	key, err := s.vaultKey(ctx, item.VaultID)
	if err != nil {
		return Observation{}, err
	}

	payload, err := base64.StdEncoding.DecodeString(item.Payload)
	if err != nil {
		return Observation{}, fmt.Errorf("decoding payload: %w", err)
	}

	// The whole canonical observation is stored, not a chosen subset. A new
	// field in the format then appears in the export without a schema change,
	// which is what makes the migrations additive-only.
	content, obsType, err := s.decryptFn(payload, key)
	if err != nil {
		return Observation{}, fmt.Errorf("decrypting observation: %w", err)
	}

	// Timestamps come from the SERVER's metadata, not from inside the encrypted
	// record. The cursor orders by exactly what the server paginates by; taking
	// UpdatedAt from the plaintext would let the two disagree, and rows between
	// the two values would be skipped and never looked at again.
	created, err := time.Parse(time.RFC3339, item.CreatedAt)
	if err != nil {
		return Observation{}, fmt.Errorf("parsing createdAt: %w", err)
	}
	updated, err := time.Parse(time.RFC3339, item.UpdatedAt)
	if err != nil {
		return Observation{}, fmt.Errorf("parsing updatedAt: %w", err)
	}

	return Observation{
		ID:        item.ID,
		VaultID:   item.VaultID,
		Type:      obsType,
		Content:   content,
		CreatedAt: created,
		UpdatedAt: updated,
	}, nil
}

// aadObservation must match internal/encryption's constant of the same value.
const aadObservation = "sinesync-observation-v1"

// decryptObservation opens one encrypted observation with a vault key.
//
// Reimplemented here rather than calling internal/encryption, which imports
// SQLCipher and sqlite-vec: linking those would make this daemon need a cgo
// toolchain for every platform it runs on, to carry code it never executes. A
// server-side exporter should cross-compile from anywhere.
//
// The duplicated format is guarded by a parity test that encrypts with the real
// manager and opens it with this, so the two cannot drift apart silently.
func decryptObservation(encrypted, key []byte) (json.RawMessage, string, error) {
	compressed, err := crypto.Decrypt(encrypted, key, aadObservation)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting: %w", err)
	}

	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, "", fmt.Errorf("decompressing: %w", err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, "", fmt.Errorf("decompressing: %w", err)
	}

	// Only the type is read out; everything else is carried through verbatim.
	var head struct {
		Core struct {
			Type string `json:"type"`
		} `json:"core"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, "", fmt.Errorf("parsing observation: %w", err)
	}

	return json.RawMessage(raw), head.Core.Type, nil
}
