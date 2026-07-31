package wgkey

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// The test vector from RFC 7748 section 6.1. If a toolchain change ever makes
// crypto/ecdh disagree with this, the keys this client writes stop matching
// every other WireGuard implementation, so the build must fail rather than
// enroll a router that cannot handshake.
const (
	rfc7748AlicePrivateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748AlicePublicHex  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc7748BobPrivateHex   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	rfc7748BobPublicHex    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
)

// The same two public keys in the base64 form "wg pubkey" prints. Checking the
// encoding as well as the curve catches a swap to base64url, which produces
// "-" and "_" and yields keys wg rejects.
const (
	rfc7748AlicePublicBase64 = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
	rfc7748BobPublicBase64   = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
)

func keyFromHex(t *testing.T, s string) Key {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %s: %v", s, err)
	}
	if len(raw) != Length {
		t.Fatalf("vector is %d bytes, want %d", len(raw), Length)
	}
	var k Key
	copy(k[:], raw)
	return k
}

func TestPublicForMatchesRFC7748Vector(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privateHex string
		publicHex  string
		base64     string
	}{
		{"alice", rfc7748AlicePrivateHex, rfc7748AlicePublicHex, rfc7748AlicePublicBase64},
		{"bob", rfc7748BobPrivateHex, rfc7748BobPublicHex, rfc7748BobPublicBase64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private := keyFromHex(t, tc.privateHex)
			public, err := PublicFor(private)
			if err != nil {
				t.Fatalf("PublicFor: %v", err)
			}
			if got := hex.EncodeToString(public[:]); got != tc.publicHex {
				t.Errorf("public key is %s, want %s", got, tc.publicHex)
			}
			if got := public.String(); got != tc.base64 {
				t.Errorf("base64 public key is %s, want %s", got, tc.base64)
			}
		})
	}
}

// The RFC prints Alice's private key unclamped. X25519 clamps during the
// scalar multiplication, so clamping before storage must leave the public key
// alone. This is what lets the client store a key in the same form wg genkey
// produces without changing what the hub was told.
func TestClampingDoesNotChangeThePublicKey(t *testing.T) {
	private := keyFromHex(t, rfc7748AlicePrivateHex)
	before, err := PublicFor(private)
	if err != nil {
		t.Fatalf("PublicFor before clamping: %v", err)
	}
	clamped := private
	clamped.clamp()
	if clamped == private {
		t.Fatal("the RFC vector is expected to be unclamped, so clamping should change it")
	}
	after, err := PublicFor(clamped)
	if err != nil {
		t.Fatalf("PublicFor after clamping: %v", err)
	}
	if before != after {
		t.Errorf("clamping changed the public key: %s then %s", before, after)
	}
}

func TestGenerateProducesAClampedKeyPair(t *testing.T) {
	for i := 0; i < 64; i++ {
		private, public, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if private[0]&7 != 0 || private[31]&128 != 0 || private[31]&64 == 0 {
			t.Fatalf("private key is not clamped: %s", private)
		}
		derived, err := PublicFor(private)
		if err != nil {
			t.Fatalf("PublicFor: %v", err)
		}
		if derived != public {
			t.Fatalf("Generate returned a public key that the private key does not derive")
		}
		if len(private.String()) != EncodedLength || len(public.String()) != EncodedLength {
			t.Fatalf("encoded key is not %d characters", EncodedLength)
		}
	}
}

func TestGenerateDoesNotRepeatItself(t *testing.T) {
	seen := make(map[Key]bool, 64)
	for i := 0; i < 64; i++ {
		private, _, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[private] {
			t.Fatal("Generate returned the same private key twice")
		}
		seen[private] = true
	}
}

func TestParseRoundTrip(t *testing.T) {
	private, public, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, k := range []Key{private, public} {
		parsed, err := Parse(k.String())
		if err != nil {
			t.Fatalf("Parse(%s): %v", k, err)
		}
		if parsed != k {
			t.Errorf("Parse did not round trip %s", k)
		}
	}
}

func TestParseRejectsBadKeys(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	long := base64.StdEncoding.EncodeToString(make([]byte, 33))
	urlSafe := "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo="
	for _, tc := range []struct{ name, text string }{
		{"empty", ""},
		{"not base64", "not a key"},
		{"31 bytes", short},
		{"33 bytes", long},
		{"base64url", urlSafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.text); err == nil {
				t.Errorf("Parse(%q) succeeded, want an error", tc.text)
			}
		})
	}
}

// A private key must never reach an error message, because the caller logs
// these and the key is the one secret on the router.
func TestParseErrorsDoNotQuoteTheKey(t *testing.T) {
	secret := "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo" // 43 characters, no padding
	_, err := Parse(secret)
	if err == nil {
		t.Fatal("Parse accepted an unpadded key")
	}
	if contains(err.Error(), secret) {
		t.Errorf("the error message repeats the key: %v", err)
	}
}

func contains(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
