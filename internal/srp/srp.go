// Package srp implements SRP-6a compatible with js-srp6a library
// Uses SHA-256 and 4096-bit group from RFC 5054
package srp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

// RFC 5054 4096-bit group parameters
var (
	// N is the 4096-bit prime from RFC 5054
	N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16)
	// g is the generator
	g = big.NewInt(5)
	// k = H(N, PAD(g))
	hashBytes = 32 // SHA-256 output
)

// PBKDF2 iterations for SHA-256 (matches js-srp6a)
const pbkdf2Iterations = 310000

// Client represents an SRP client
type Client struct {
	username  string
	password  string
	salt      []byte
	x         *big.Int // private key
	a         *big.Int // ephemeral secret
	A         *big.Int // ephemeral public
	K         []byte   // session key
	M1        []byte   // client proof
}

// NewClient creates a new SRP client for login
func NewClient(username, password string) *Client {
	return &Client{
		username: norm.NFKC.String(username),
		password: norm.NFKC.String(password),
	}
}

// GenerateSalt generates a random salt for signup
func GenerateSalt() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	return hex.EncodeToString(salt)
}

// ComputeVerifier computes the verifier for signup
// Returns (salt, verifier) as hex strings
func (c *Client) ComputeVerifier() (string, string) {
	salt := GenerateSalt()
	saltBytes, _ := hex.DecodeString(salt)
	c.salt = saltBytes

	// x = PBKDF2(password, salt, iterations, SHA-256)
	x := pbkdf2.Key([]byte(c.password), saltBytes, pbkdf2Iterations, hashBytes, sha256.New)
	c.x = new(big.Int).SetBytes(x)

	// v = g^x mod N
	v := new(big.Int).Exp(g, c.x, N)

	return salt, toHex(v)
}

// GenerateEphemeral generates the client ephemeral values
// Returns A (public) as hex string
func (c *Client) GenerateEphemeral() string {
	// a = random
	c.a = randomBigInt(hashBytes)
	// A = g^a mod N
	c.A = new(big.Int).Exp(g, c.a, N)
	return toHex(c.A)
}

// ComputeSession computes the session key and proof
// Takes salt and B (server public) as hex strings
// Returns (proof M1) as hex string
func (c *Client) ComputeSession(saltHex, serverPublicHex string) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("invalid salt: %w", err)
	}
	c.salt = salt

	B, ok := new(big.Int).SetString(serverPublicHex, 16)
	if !ok {
		return "", fmt.Errorf("invalid server public")
	}

	// Check B != 0 mod N
	if new(big.Int).Mod(B, N).Cmp(big.NewInt(0)) == 0 {
		return "", fmt.Errorf("invalid server public ephemeral")
	}

	// Derive x from password if not already done
	if c.x == nil {
		x := pbkdf2.Key([]byte(c.password), salt, pbkdf2Iterations, hashBytes, sha256.New)
		c.x = new(big.Int).SetBytes(x)
	}

	// Generate A if not already done
	if c.A == nil {
		c.GenerateEphemeral()
	}

	// k = H(N, PAD(g))
	k := computeK()

	// u = H(PAD(A), PAD(B))
	u := computeU(c.A, B)

	// S = (B - k*g^x)^(a + u*x) mod N
	// First compute k*g^x mod N
	gx := new(big.Int).Exp(g, c.x, N)
	kgx := new(big.Int).Mul(k, gx)
	kgx.Mod(kgx, N)

	// B - k*g^x mod N (handle negative by adding N)
	base := new(big.Int).Sub(B, kgx)
	if base.Sign() < 0 {
		base.Add(base, N)
	}

	// a + u*x
	ux := new(big.Int).Mul(u, c.x)
	exp := new(big.Int).Add(c.a, ux)

	// S = base^exp mod N
	S := new(big.Int).Exp(base, exp, N)

	// K = H(S)
	c.K = hash(S.Bytes())

	// M1 = H(H(N) xor H(g), H(I), s, A, B, K)
	HN := hash(N.Bytes())
	Hg := hash(g.Bytes())
	HNxorHg := xorBytes(HN, Hg)
	HI := hash([]byte(c.username))

	c.M1 = hash(HNxorHg, HI, salt, pad(c.A), pad(B), c.K)

	return hex.EncodeToString(c.M1), nil
}

// VerifyServer verifies the server's proof
func (c *Client) VerifyServer(serverProofHex string) bool {
	serverProof, err := hex.DecodeString(serverProofHex)
	if err != nil {
		return false
	}

	// M2 = H(A, M1, K)
	expected := hash(pad(c.A), c.M1, c.K)

	return hmac.Equal(expected, serverProof)
}

// Helper functions

func hash(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func pad(n *big.Int) []byte {
	bytes := n.Bytes()
	padLen := (N.BitLen() + 7) / 8
	if len(bytes) < padLen {
		padded := make([]byte, padLen)
		copy(padded[padLen-len(bytes):], bytes)
		return padded
	}
	return bytes
}

func toHex(n *big.Int) string {
	return strings.ToLower(hex.EncodeToString(pad(n)))
}

func computeK() *big.Int {
	// k = H(N, PAD(g))
	kBytes := hash(pad(N), pad(g))
	return new(big.Int).SetBytes(kBytes)
}

func computeU(A, B *big.Int) *big.Int {
	// u = H(PAD(A), PAD(B))
	uBytes := hash(pad(A), pad(B))
	return new(big.Int).SetBytes(uBytes)
}

func randomBigInt(bytes int) *big.Int {
	b := make([]byte, bytes)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}

func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
