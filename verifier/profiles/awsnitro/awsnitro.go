// Package awsnitro is the AWS Nitro Enclaves profile (spec/profiles/awsnitro.md): a signing key generated inside
// an enclave and attested by the enclave's Nitro Secure Module.
package awsnitro

import (
	"bytes"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
)

const (
	Name = "awsnitro"
	// KeyChallenge starts the user_data commitment, binding a key to this profile and version.
	KeyChallenge = "hardware-attested-statement/v0.1/awsnitro/key"
	// DefaultMaxKeyAgeHours is how long a key is usable after its drand round, unless the policy says otherwise.
	DefaultMaxKeyAgeHours = 24
)

// Each verification step (spec: profiles/awsnitro.md, Verification) fails with its own error, so tests and
// callers can tell which rule rejected a key.
var (
	ErrEvidence  = errors.New("awsnitro key evidence is malformed")
	ErrCOSE      = errors.New("not the COSE_Sign1 structure this profile accepts")        // step 1
	ErrCBOR      = errors.New("not the CBOR this profile accepts")                        // step 2
	ErrDocument  = errors.New("not an enclave's attestation document")                    // step 3
	ErrChain     = errors.New("the attestation document's certificate chain isn't AWS's") // step 4
	ErrSignature = errors.New("the attestation document's signature is invalid")          // step 5
	ErrKey       = errors.New("the attested key isn't a key made for this profile")       // step 6
	ErrDebug     = errors.New("the enclave runs in debug mode")                           // step 7
	ErrSigner    = errors.New("the enclave image isn't one the policy trusts")            // step 8
	ErrTimestamp = errors.New("the attestation document's time isn't within its certificate's validity")
)

// Evidence is the profile's key evidence.
type Evidence struct {
	Profile             string                 `json:"profile"`
	AttestationDocument verifier.Bytes         `json:"attestationDocument"`
	KeyStartedAfter     *verifier.StartedAfter `json:"keyStartedAfter"`
}

// Signer is a policy entry: an enclave image, by its PCRs (decimal index to lowercase hex).
type Signer struct {
	Profile string            `json:"profile"`
	PCRs    map[string]string `json:"pcrs"`
}

// Settings are the policy's "awsnitro" profile settings.
type Settings struct {
	MaxKeyAgeHours *int64 `json:"maxKeyAgeHours"`
}

// Image is what the document says about the enclave's image: all of its PCRs, by decimal index, as lowercase hex.
type Image struct {
	PCRs map[string]string `json:"pcrs"`
}

// Enclave is what the document says about where the enclave ran, as of the document.
type Enclave struct {
	ModuleID     string    `json:"moduleId"`
	Region       string    `json:"region"`
	DocumentTime time.Time `json:"documentTime"`
}

// Profile verifies keys attested by AWS Nitro Enclaves.
type Profile struct {
	trust *Trust
}

// New makes the profile from its trust store.
func New(trust *Trust) *Profile { return &Profile{trust: trust} }

func (p *Profile) Name() string { return Name }

func (p *Profile) CheckPolicy(trusted []jsontext.Value, settings jsontext.Value) error {
	for _, raw := range trusted {
		if _, err := parseSigner(raw); err != nil {
			return err
		}
	}
	_, err := parseSettings(settings)
	return err
}

// Binding is the content of the COSE_Sign1 payload: the attestation document, which holds the key, the
// commitment to its round, the PCRs and the chain, and can't be altered, unlike the COSE signature.
func (p *Profile) Binding(raw jsontext.Value) ([]byte, error) {
	ev, err := parseEvidence(raw)
	if err != nil {
		return nil, err
	}
	cose, err := parseCOSE(ev.AttestationDocument)
	if err != nil {
		return nil, err
	}
	return cose.payload, nil
}

func (p *Profile) VerifyKey(raw jsontext.Value, trusted []jsontext.Value, settings jsontext.Value, kc verifier.KeyContext) (*verifier.Key, error) {
	s, err := parseSettings(settings)
	if err != nil {
		return nil, err
	}
	ev, err := parseEvidence(raw)
	if err != nil {
		return nil, err
	}
	cose, err := parseCOSE(ev.AttestationDocument)
	if err != nil {
		return nil, err
	}
	d, err := parseDocument(cose.payload)
	if err != nil {
		return nil, err
	}
	ch, err := d.verifyChain(p.trust.Roots)
	if err != nil {
		return nil, err
	}
	if err := cose.verify(leafKey(ch)); err != nil {
		return nil, err
	}
	if d.timestamp.Before(ch.leaf.NotBefore) || d.timestamp.After(ch.leaf.NotAfter) {
		return nil, fmt.Errorf("%w: %v", ErrTimestamp, d.timestamp)
	}
	pub, created, err := d.checkKey(*ev.KeyStartedAfter.Drand, kc)
	if err != nil {
		return nil, err
	}
	if err := d.checkNotDebug(); err != nil {
		return nil, err
	}
	image, err := d.matchSigner(trusted)
	if err != nil {
		return nil, err
	}
	enclave := &Enclave{ModuleID: d.moduleID, Region: ch.region, DocumentTime: d.timestamp}
	key := &verifier.Key{PublicKey: pub, Signer: image, Device: enclave, ValidFrom: ch.validFrom,
		ValidUntil: ch.validUntil, Created: &created, MaxAge: time.Duration(*s.MaxKeyAgeHours) * time.Hour}
	key.Description = []string{
		fmt.Sprintf("enclave image PCR0 %s, PCR1 %s, PCR2 %s", image.PCRs["0"], image.PCRs["1"], image.PCRs["2"]),
		fmt.Sprintf("enclave %s in %s; document of %s; key made after %s",
			d.moduleID, ch.region, d.timestamp.Format(time.RFC3339), created.UTC().Format(time.RFC3339)),
	}
	return key, nil
}

func parseEvidence(raw jsontext.Value) (*Evidence, error) {
	var ev Evidence
	if err := verifier.UnmarshalStrict(raw, &ev); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvidence, err)
	}
	if ev.Profile != Name || ev.AttestationDocument == nil || ev.KeyStartedAfter == nil || ev.KeyStartedAfter.Drand == nil {
		return nil, fmt.Errorf("%w: it needs attestationDocument and keyStartedAfter (drand)", ErrEvidence)
	}
	return &ev, nil
}

func parseSettings(raw jsontext.Value) (*Settings, error) {
	s := &Settings{}
	if len(raw) > 0 {
		if err := verifier.UnmarshalStrict(raw, s); err != nil {
			return nil, fmt.Errorf("awsnitro settings: %w", err)
		}
	}
	if s.MaxKeyAgeHours == nil {
		s.MaxKeyAgeHours = new(int64(DefaultMaxKeyAgeHours))
	}
	if *s.MaxKeyAgeHours < 1 {
		return nil, errors.New("awsnitro settings: maxKeyAgeHours must be at least 1")
	}
	return s, nil
}

// parseSigner reads a policy entry: PCRs 0, 1 and 2 at least, none of them zero, and others from 0 to 15 (PCRs
// 16 to 31 can be extended while the enclave runs), each 48 bytes of lowercase hex.
func parseSigner(raw jsontext.Value) (*Signer, error) {
	var s Signer
	if err := verifier.UnmarshalStrict(raw, &s); err != nil {
		return nil, fmt.Errorf("awsnitro signer: %w", err)
	}
	for name, value := range s.PCRs {
		i, err := strconv.Atoi(name)
		if err != nil || i < 0 || i > 15 || strconv.Itoa(i) != name {
			return nil, fmt.Errorf("awsnitro signer: PCR %q isn't an index from 0 to 15", name)
		}
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 48 || strings.ToLower(value) != value {
			return nil, fmt.Errorf("awsnitro signer: PCR%s isn't 48 bytes of lowercase hex", name)
		}
	}
	for _, name := range []string{"0", "1", "2"} {
		v, ok := s.PCRs[name]
		if !ok {
			return nil, errors.New("awsnitro signer: it must name PCRs 0, 1 and 2")
		}
		if v == strings.Repeat("0", 96) {
			return nil, fmt.Errorf("awsnitro signer: PCR%s is zero, which only debug enclaves report", name)
		}
	}
	return &s, nil
}

// matchSigner checks the PCRs match a policy entry (verification step 8): every PCR it names is in the document,
// and equal.
func (d *document) matchSigner(trusted []jsontext.Value) (*Image, error) {
	image := &Image{PCRs: map[string]string{}}
	for i, v := range d.pcrs {
		image.PCRs[strconv.Itoa(i)] = hex.EncodeToString(v)
	}
	for _, raw := range trusted {
		s, err := parseSigner(raw)
		if err != nil {
			return nil, err
		}
		matches := true
		for _, name := range slices.Sorted(maps.Keys(s.PCRs)) {
			want, _ := hex.DecodeString(s.PCRs[name])
			i, _ := strconv.Atoi(name)
			got, ok := d.pcrs[i]
			matches = matches && ok && bytes.Equal(got, want)
		}
		if matches {
			return image, nil
		}
	}
	return nil, fmt.Errorf("%w: PCR0 %s", ErrSigner, image.PCRs["0"])
}
