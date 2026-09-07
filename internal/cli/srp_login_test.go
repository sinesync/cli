package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/sinesync/cli/internal/srp"
)

// doSRPLogin no longer computes the proof itself: requestSRPChallenge runs
// /auth/login/init and returns A and M1, and login sends those on to
// /auth/login/verify. These tests talk to a server that does the real SRP-6a
// arithmetic, so they fail if the helper hands login the wrong values, if login
// sends something other than what the helper produced, or if the srp.Client that
// computed M1 is no longer the one that checks the server's M2.

const (
	testSRPEmail    = "user@example.com"
	testSRPPassword = "correct horse battery staple"
	testSRPSalt     = "0123456789abcdef0123456789abcdef"
)

// The client's own parameters, mirrored for the server side. srp exports N but
// not g; g is 5 per RFC 5054. k and u hash the padded values, while the
// H(N) xor H(g) term inside M1 hashes them unpadded — the client does both.
var srpG = big.NewInt(5)

// PBKDF2 at 310000 iterations is deliberately slow, so the verifier for the one
// account these tests use is derived once.
var (
	verifierOnce sync.Once
	testVerifier *big.Int
)

func srpVerifier() *big.Int {
	verifierOnce.Do(func() {
		salt, err := hex.DecodeString(testSRPSalt)
		if err != nil {
			panic(err)
		}
		x := pbkdf2.Key([]byte(testSRPPassword), salt, 310000, 32, sha256.New)
		testVerifier = new(big.Int).Exp(srpG, new(big.Int).SetBytes(x), srp.N)
	})
	return testVerifier
}

// fakeSRPServer is an SRP-6a server for one account. It records what each
// endpoint received so a test can tell whether login sent the helper's values.
type fakeSRPServer struct {
	url string

	b *big.Int // server ephemeral secret
	B *big.Int // server ephemeral public

	initCalls   int
	initEmail   string
	verifyCalls int
	gotPublic   string
	gotProof    string

	// initStatus, when non-zero, is returned by /auth/login/init instead of a
	// challenge.
	initStatus int
	// corruptServerProof replaces M2 with a value the client must reject.
	corruptServerProof bool
}

func startFakeSRPServer(t *testing.T) *fakeSRPServer {
	t.Helper()

	v := srpVerifier()
	s := &fakeSRPServer{}

	// b random, B = (k*v + g^b) mod N with k = H(N, PAD(g))
	bBytes := make([]byte, 32)
	if _, err := rand.Read(bBytes); err != nil {
		t.Fatal(err)
	}
	s.b = new(big.Int).SetBytes(bBytes)
	k := new(big.Int).SetBytes(srpHash(srpPad(srp.N), srpPad(srpG)))
	kv := new(big.Int).Mul(k, v)
	s.B = new(big.Int).Add(kv, new(big.Int).Exp(srpG, s.b, srp.N))
	s.B.Mod(s.B, srp.N)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login/init":
			s.initCalls++
			var req struct {
				Email string `json:"email"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.initEmail = req.Email

			if s.initStatus != 0 {
				w.WriteHeader(s.initStatus)
				_, _ = w.Write([]byte(`{"error":"no such account"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"salt":         testSRPSalt,
				"serverPublic": hex.EncodeToString(s.B.Bytes()),
			})

		case "/auth/login/verify":
			s.verifyCalls++
			var req struct {
				ClientPublic string `json:"clientPublic"`
				ClientProof  string `json:"clientProof"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.gotPublic, s.gotProof = req.ClientPublic, req.ClientProof

			expectedM1, K, ok := s.expectedProof(req.ClientPublic)
			if !ok || expectedM1 != req.ClientProof {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
				return
			}

			A, _ := new(big.Int).SetString(req.ClientPublic, 16)
			m1, _ := hex.DecodeString(expectedM1)
			serverProof := hex.EncodeToString(srpHash(srpPad(A), m1, K))
			if s.corruptServerProof {
				serverProof = hex.EncodeToString(make([]byte, 32))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"serverProof":  serverProof,
				"user":         map[string]string{"id": "user-1", "email": testSRPEmail},
				"token":        "access-token",
				"refreshToken": "refresh-token",
				"expiresAt":    "2099-01-01T00:00:00Z",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	s.url = srv.URL
	return s
}

// expectedProof recomputes M1 the way a server holding the verifier would, from
// the A the client sent. Returns the proof and the session key K.
func (s *fakeSRPServer) expectedProof(clientPublicHex string) (string, []byte, bool) {
	A, ok := new(big.Int).SetString(clientPublicHex, 16)
	if !ok || new(big.Int).Mod(A, srp.N).Sign() == 0 {
		return "", nil, false
	}

	u := new(big.Int).SetBytes(srpHash(srpPad(A), srpPad(s.B)))
	// S = (A * v^u)^b mod N
	S := new(big.Int).Exp(srpVerifier(), u, srp.N)
	S.Mul(S, A)
	S.Mod(S, srp.N)
	S.Exp(S, s.b, srp.N)

	K := srpHash(S.Bytes())

	salt, _ := hex.DecodeString(testSRPSalt)
	hn := srpHash(srp.N.Bytes())
	hg := srpHash(srpG.Bytes())
	hnXorHg := make([]byte, len(hn))
	for i := range hn {
		hnXorHg[i] = hn[i] ^ hg[i]
	}
	m1 := srpHash(hnXorHg, srpHash([]byte(testSRPEmail)), salt, srpPad(A), srpPad(s.B), K)
	return hex.EncodeToString(m1), K, true
}

func srpHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// srpPad left-pads to the byte length of N, as the client does.
func srpPad(n *big.Int) []byte {
	b := n.Bytes()
	width := (srp.N.BitLen() + 7) / 8
	if len(b) >= width {
		return b
	}
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

func TestTheHelperProducesAProofTheServerAccepts(t *testing.T) {
	srv := startFakeSRPServer(t)

	challenge, err := requestSRPChallenge(srv.url, testSRPEmail, testSRPPassword)
	if err != nil {
		t.Fatalf("requestSRPChallenge: %v", err)
	}

	if srv.initCalls != 1 {
		t.Errorf("init called %d times, want 1", srv.initCalls)
	}
	if srv.initEmail != testSRPEmail {
		t.Errorf("init received email %q, want %q", srv.initEmail, testSRPEmail)
	}
	if srv.verifyCalls != 0 {
		t.Errorf("the helper called verify %d times; it must stop after init", srv.verifyCalls)
	}
	if challenge.client == nil {
		t.Fatal("challenge carries no srp.Client, so nothing can verify the server's M2")
	}

	wantM1, _, ok := srv.expectedProof(challenge.clientPublic)
	if !ok {
		t.Fatalf("clientPublic %q is not a usable ephemeral", challenge.clientPublic)
	}
	if challenge.clientProof != wantM1 {
		t.Errorf("clientProof = %q, server computes %q", challenge.clientProof, wantM1)
	}
}

func TestLoginSendsTheHelpersValuesAndSucceeds(t *testing.T) {
	srv := startFakeSRPServer(t)

	resp, err := doSRPLogin(srv.url, testSRPEmail, testSRPPassword)
	if err != nil {
		t.Fatalf("doSRPLogin: %v", err)
	}

	if srv.initCalls != 1 || srv.verifyCalls != 1 {
		t.Errorf("init called %d times, verify %d; want 1 each", srv.initCalls, srv.verifyCalls)
	}
	// The server only accepted the proof because A and M1 agreed with each
	// other, which is what "login sent the helper's pair" amounts to on the wire.
	wantM1, _, ok := srv.expectedProof(srv.gotPublic)
	if !ok || srv.gotProof != wantM1 {
		t.Errorf("verify received clientPublic %q with proof %q, which do not match", srv.gotPublic, srv.gotProof)
	}
	if resp.Token != "access-token" || resp.RefreshToken != "refresh-token" {
		t.Errorf("login returned token %q / refresh %q", resp.Token, resp.RefreshToken)
	}
	if resp.User.Email != testSRPEmail {
		t.Errorf("login returned user %q", resp.User.Email)
	}
}

func TestLoginStillVerifiesTheServersProof(t *testing.T) {
	srv := startFakeSRPServer(t)
	srv.corruptServerProof = true

	if _, err := doSRPLogin(srv.url, testSRPEmail, testSRPPassword); err == nil {
		t.Fatal("login accepted a server that could not prove it holds the verifier")
	} else if err.Error() != "server proof verification failed" {
		t.Errorf("error = %v, want the M2 check to be what failed", err)
	}
}

func TestAWrongPasswordIsRejectedAtVerify(t *testing.T) {
	srv := startFakeSRPServer(t)

	_, err := doSRPLogin(srv.url, testSRPEmail, "not the password")
	if err == nil {
		t.Fatal("login succeeded with the wrong password")
	}
	if srv.verifyCalls != 1 {
		t.Errorf("verify called %d times, want 1", srv.verifyCalls)
	}
}

func TestAFailedInitStopsBeforeVerify(t *testing.T) {
	srv := startFakeSRPServer(t)
	srv.initStatus = http.StatusNotFound

	_, err := doSRPLogin(srv.url, testSRPEmail, testSRPPassword)
	if err == nil {
		t.Fatal("login continued past a failed init")
	}
	if srv.verifyCalls != 0 {
		t.Errorf("verify called %d times after init failed", srv.verifyCalls)
	}
}
