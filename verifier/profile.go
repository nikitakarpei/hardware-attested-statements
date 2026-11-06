package verifier

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json/jsontext"
	"fmt"
	"time"
)

// Profile verifies one kind of key evidence (spec section 3): for example Android key attestation.
type Profile interface {
	Name() string
	// CheckPolicy validates a predicate type's trustedSigners entries for this profile and its settings (nil:
	// defaults), so mistakes surface before any bundle is checked.
	CheckPolicy(trusted []jsontext.Value, settings jsontext.Value) error
	// Binding returns the evidence's key binding (spec section 2), exactly as carried, without verifying it.
	Binding(evidence jsontext.Value) ([]byte, error)
	// VerifyKey checks evidence under settings, in context kc, and that it names a signer one of trusted accepts.
	VerifyKey(evidence jsontext.Value, trusted []jsontext.Value, settings jsontext.Value, kc KeyContext) (*Key, error)
}

// KeyContext is what a profile's VerifyKey may rely on besides the evidence and the policy's entries for it.
type KeyContext struct {
	// Now is the verification time.
	Now time.Time
	// Drand holds the drand chains the policy trusts, by chain hash: a round in key evidence from any other chain
	// can't be relied on (see VerifyRound).
	Drand map[string]DrandChain
}

// VerifyRound checks a drand round, in key evidence, from one of the policy's trusted chains, and returns its time.
func (kc KeyContext) VerifyRound(r DrandRound) (time.Time, error) {
	if err := r.check(); err != nil {
		return time.Time{}, err
	}
	chain, ok := kc.Drand[r.Chain]
	if !ok {
		return time.Time{}, fmt.Errorf("drand chain %s is not trusted", r.Chain)
	}
	sig, _ := hex.DecodeString(r.Signature)
	if err := chain.Verify(r.Round, sig); err != nil {
		return time.Time{}, err
	}
	return chain.RoundTime(r.Round), nil
}

// Key is what a profile established about a signing key.
type Key struct {
	PublicKey *ecdsa.PublicKey `json:"-"`
	// Signer and Device are profile-specific (for Android: android.App and android.Device).
	Signer any `json:"signer"`
	Device any `json:"device"`
	// The evidence was valid (for example, all certificates of a chain) at every instant from ValidFrom to ValidUntil.
	ValidFrom  time.Time `json:"validFrom"`
	ValidUntil time.Time `json:"validUntil"`
	// Created is when the key was made, as the evidence states it; MaxAge, if set, limits the key's age at the
	// statement's upper bound.
	Created *time.Time    `json:"created,omitzero"`
	MaxAge  time.Duration `json:"-"`
	// Description is a few lines for people.
	Description []string `json:"description"`
}
