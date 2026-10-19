// Package jwt issues and verifies ES256 compact JWS tokens. It is deliberately
// small: one algorithm, string audiences, no library, so the KMS-backed signer
// slots in without adapters.
package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/nathanblatter/squawk/internal/signer"
)

// Claims is the registered + private claim set this service emits.
type Claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Email    string `json:"email,omitempty"`
	// PreferredUsername is set on tokens of accounts that sign in by name
	// (password method, or a passkey account converted from one).
	PreferredUsername string `json:"preferred_username,omitempty"`
	// EmailVerified is set on user tokens once the address is proven
	// (Google asserted it, an email code was entered, or the owner vouched).
	EmailVerified bool `json:"email_verified,omitempty"`
	// Org / OrgRole are set when the app asked for an org context and the
	// subject is a member (or the owner): the org id and admin|member.
	Org      string `json:"org,omitempty"`
	OrgRole  string `json:"org_role,omitempty"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	ID       string `json:"jti"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

var (
	ErrMalformed  = errors.New("jwt: malformed token")
	ErrSignature  = errors.New("jwt: bad signature")
	ErrUnknownKey = errors.New("jwt: unknown kid")
	ErrExpired    = errors.New("jwt: expired")
	ErrNotYet     = errors.New("jwt: issued in the future")
	ErrIssuer     = errors.New("jwt: wrong issuer")
	ErrAudience   = errors.New("jwt: wrong audience")
)

// Sign produces a compact JWS. It fills jti when empty.
func Sign(ctx context.Context, s signer.Signer, c Claims) (string, error) {
	if c.ID == "" {
		c.ID = randomID()
	}
	hdr, err := json.Marshal(header{Alg: "ES256", Typ: "at+jwt", Kid: s.KeyID()})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64(hdr) + "." + b64(body)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := s.Sign(ctx, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// Verify checks structure, signature, time bounds, issuer and audience.
// lookup resolves a kid to a public key; nil means unknown.
func Verify(token string, lookup func(kid string) *ecdsa.PublicKey, now time.Time, issuer, audience string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	hdrRaw, err := unb64(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var hdr header
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil || hdr.Alg != "ES256" || hdr.Kid == "" {
		return Claims{}, ErrMalformed
	}
	pub := lookup(hdr.Kid)
	if pub == nil {
		return Claims{}, ErrUnknownKey
	}
	sig, err := unb64(parts[2])
	if err != nil || len(sig) != 64 {
		return Claims{}, ErrMalformed
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	sv := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, sv) {
		return Claims{}, ErrSignature
	}
	bodyRaw, err := unb64(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var c Claims
	if err := json.Unmarshal(bodyRaw, &c); err != nil {
		return Claims{}, ErrMalformed
	}
	unix := now.Unix()
	if c.Expires <= unix {
		return Claims{}, ErrExpired
	}
	if c.IssuedAt > unix+60 {
		return Claims{}, ErrNotYet
	}
	if c.Issuer != issuer {
		return Claims{}, ErrIssuer
	}
	if c.Audience != audience {
		return Claims{}, ErrAudience
	}
	return c, nil
}

// JWK is one public key in JWKS form.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS is the document served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS publishes every key in the ring.
func BuildJWKS(ring *signer.Ring) JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(ring.All()))}
	for _, s := range ring.All() {
		// Uncompressed SEC1 point: 0x04 || X (32) || Y (32).
		pt, err := s.Public().Bytes()
		if err != nil || len(pt) != 65 || pt[0] != 4 {
			panic(fmt.Sprintf("jwt: bad public key for kid %s: %v", s.KeyID(), err))
		}
		out.Keys = append(out.Keys, JWK{
			Kty: "EC", Crv: "P-256", Kid: s.KeyID(), Use: "sig", Alg: "ES256",
			X: b64(pt[1:33]), Y: b64(pt[33:65]),
		})
	}
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("jwt: crypto/rand failed: %v", err))
	}
	return b64(b[:])
}
