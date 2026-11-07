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
	// Limits besides the evidence's validity, each if set: the statement's upper bound must be at or after
	// AcceptedFrom, and before AcceptedUntil (for example, while the attested patch levels are neither in the
	// future nor too old).
	AcceptedFrom  time.Time `json:"acceptedFrom,omitzero"`
	AcceptedUntil time.Time `json:"acceptedUntil,omitzero"`
	// Description is a few lines for people.
	Description []string `json:"description"`
}
