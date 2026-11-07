package verifier

import (
	"crypto/ecdsa"
	"encoding/json/jsontext"
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
	// VerifyKey checks evidence under settings, at verification time now, and that it names a signer one of
	// trusted accepts.
	VerifyKey(evidence jsontext.Value, trusted []jsontext.Value, settings jsontext.Value, now time.Time) (*Key, error)
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
	// The statement's upper bound must be from PlausibleFrom and before StaleFrom, if set: limits on the evidence
	// besides its validity (for example, an attested patch level that is in the future, or too old, at that
	// time). ImplausibleReason and StaleReason say why, for the error.
	PlausibleFrom     time.Time `json:"plausibleFrom,omitzero"`
	ImplausibleReason string    `json:"-"`
	StaleFrom         time.Time `json:"staleFrom,omitzero"`
	StaleReason       string    `json:"-"`
	// Description is a few lines for people.
	Description []string `json:"description"`
}
