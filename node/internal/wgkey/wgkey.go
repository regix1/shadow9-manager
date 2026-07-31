// Package wgkey creates and parses WireGuard keys. A WireGuard key is an
// X25519 key from RFC 7748 written in standard base64, so crypto/ecdh covers
// it with no third-party module.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Length is the size of a WireGuard key in bytes.
const Length = 32

// EncodedLength is the size of a WireGuard key in standard base64, which is
// what "wg" prints and what UCI stores.
const EncodedLength = 44

// Key is a WireGuard public, private or preshared key.
type Key [Length]byte

// ErrEmpty is returned when a key was expected but the text was blank.
var ErrEmpty = errors.New("key is empty")

// String returns the key in the base64 form "wg pubkey" and "wg genkey" use.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// Parse decodes a base64 key and checks its length.
func Parse(text string) (Key, error) {
	var k Key
	if text == "" {
		return k, ErrEmpty
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		// The text itself is not repeated, because a private key takes this
		// path and error text ends up in logs.
		return k, fmt.Errorf("key is not standard base64")
	}
	if len(raw) != Length {
		return k, fmt.Errorf("key is %d bytes, want %d", len(raw), Length)
	}
	copy(k[:], raw)
	return k, nil
}

// Generate returns a new private key and the public key derived from it.
//
// The private key is clamped. X25519 clamps during the scalar multiplication
// either way, so clamping here does not change the public key, but it makes
// the stored private key byte-identical in form to one from "wg genkey"
// instead of a value that looks unlike every other WireGuard tool's output.
func Generate() (private Key, public Key, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return private, public, fmt.Errorf("generating an X25519 key: %w", err)
	}
	copy(private[:], k.Bytes())
	private.clamp()
	public, err = PublicFor(private)
	if err != nil {
		return private, public, err
	}
	return private, public, nil
}

// PublicFor derives the public key belonging to a private key.
func PublicFor(private Key) (Key, error) {
	var public Key
	k, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return public, fmt.Errorf("private key is not a valid X25519 key: %w", err)
	}
	copy(public[:], k.PublicKey().Bytes())
	return public, nil
}

// clamp applies the RFC 7748 section 5 clamping to a private key.
func (k *Key) clamp() {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}
