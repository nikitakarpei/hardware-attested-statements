package verifier

import (
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"slices"
)

const PolicyVersion = "hardware-attested-statement/policy/v0.1"

// Policy is what a verifier trusts (spec section 5).
type Policy struct {
	Policy               string     `json:"policy"`
	TimestampAuthorities []TSAEntry `json:"timestampAuthorities"`
	DrandChains          []string   `json:"drandChains"`
	// Compromised ones: their bounds aren't accepted, and statements using them are reported.
	DistrustedTimestampAuthorities []string                   `json:"distrustedTimestampAuthorities,omitzero"`
	DistrustedDrandChains          []string                   `json:"distrustedDrandChains,omitzero"`
	PredicateTypes                 map[string]PredicatePolicy `json:"predicateTypes"`
	// Profiles holds each profile's settings, by profile name.
	Profiles map[string]jsontext.Value `json:"profiles,omitzero"`
}

type PredicatePolicy struct {
	// TrustedSigners are profile-specific entries ({"profile": "android", …}); a statement of this type is
	// accepted only if one of them accepts its key.
	TrustedSigners      []jsontext.Value `json:"trustedSigners"`
	RequireTimestamp    bool             `json:"requireTimestamp,omitzero"`
	RequireStartedAfter bool             `json:"requireStartedAfter,omitzero"`
	// AllowUnverifiedInputs accepts a statement of this type although some of the inputs it lists aren't.
	AllowUnverifiedInputs bool `json:"allowUnverifiedInputs,omitzero"`
	// Profiles replaces the policy's settings of these profiles for this predicate type.
	Profiles map[string]jsontext.Value `json:"profiles,omitzero"`
}

// TSAEntry names a time-stamp authority the verifier knows ("freetsa"), or gives one in full.
type TSAEntry struct {
	Name                string   `json:"name"`
	Root                string   `json:"root,omitzero"`
	Intermediates       []string `json:"intermediates,omitzero"`
	SigningCertificates []string `json:"signingCertificates,omitzero"`
}

func (e *TSAEntry) UnmarshalJSON(raw []byte) error {
	if len(raw) > 0 && raw[0] == '"' {
		e.Root, e.Intermediates, e.SigningCertificates = "", nil, nil
		return json.Unmarshal(raw, &e.Name)
	}
	type plain TSAEntry
	if err := UnmarshalStrict(raw, (*plain)(e)); err != nil {
		return err
	}
	if e.Name == "" || e.Root == "" || len(e.SigningCertificates) == 0 {
		return errors.New("a time-stamp authority needs a name, root and signingCertificates")
	}
	if builtinTSA(e.Name) {
		return fmt.Errorf("%q is a built-in time-stamp authority's name", e.Name)
	}
	return nil
}

// ParsePolicy reads a policy; unknown members are errors, so a typo can't silently weaken it.
func ParsePolicy(raw []byte) (*Policy, error) {
	var p Policy
	if err := UnmarshalStrict(raw, &p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if p.Policy != PolicyVersion {
		return nil, fmt.Errorf("policy: expected %q, got %q", PolicyVersion, p.Policy)
	}
	if p.TimestampAuthorities == nil || p.DrandChains == nil {
		return nil, errors.New(`policy: "timestampAuthorities" and "drandChains" are required (they may be empty)`)
	}
	for t, pp := range p.PredicateTypes {
		if len(pp.TrustedSigners) == 0 {
			return nil, fmt.Errorf("policy: no trustedSigners for %s", t)
		}
	}
	for _, d := range p.DistrustedTimestampAuthorities {
		if !builtinTSA(d) {
			return nil, fmt.Errorf("policy: distrusted time-stamp authority %q isn't a built-in one", d)
		}
		for _, e := range p.TimestampAuthorities {
			if e.Name == d {
				return nil, fmt.Errorf("policy: %q is both trusted and distrusted", d)
			}
		}
	}
	for _, d := range p.DistrustedDrandChains {
		if _, err := drandChain(d); err != nil {
			return nil, err
		}
		if slices.Contains(p.DrandChains, d) {
			return nil, fmt.Errorf("policy: %q is both trusted and distrusted", d)
		}
	}
	return &p, nil
}

// signersFor returns the predicate type's trustedSigners entries for one profile.
func (pp PredicatePolicy) signersFor(profile string) ([]jsontext.Value, error) {
	var out []jsontext.Value
	for _, raw := range pp.TrustedSigners {
		name, err := profileOf(raw)
		if err != nil {
			return nil, errors.New("policy: every trustedSigners entry needs a profile")
		}
		if name == profile {
			out = append(out, raw)
		}
	}
	return out, nil
}

// settingsFor returns a profile's settings for this predicate type: the type's own merged over the policy's,
// member by member (spec section 5).
func (p *Policy) settingsFor(pp PredicatePolicy, profile string) (jsontext.Value, error) {
	own, ok := pp.Profiles[profile]
	if !ok {
		return p.Profiles[profile], nil
	}
	global, ok := p.Profiles[profile]
	if !ok {
		return own, nil
	}
	var merged, over map[string]jsontext.Value
	if err := json.Unmarshal(global, &merged); err != nil {
		return nil, fmt.Errorf("policy: %s settings: %w", profile, err)
	}
	if err := json.Unmarshal(own, &over); err != nil {
		return nil, fmt.Errorf("policy: %s settings: %w", profile, err)
	}
	maps.Copy(merged, over)
	return json.Marshal(merged, json.Deterministic(true))
}

func profileOf(raw jsontext.Value) (string, error) {
	var head struct {
		Profile string `json:"profile"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.Profile == "" {
		return "", errors.New("no profile")
	}
	return head.Profile, nil
}

func builtinTSA(name string) bool { return name == "freetsa" }

// tsa resolves an entry: a built-in authority by name, or one given in full.
func (e TSAEntry) tsa() (TSA, error) {
	if e.Root == "" {
		switch e.Name {
		case "freetsa":
			return FreeTSA()
		}
		return TSA{}, fmt.Errorf("policy: unknown time-stamp authority %q", e.Name)
	}
	cert := func(s string) (*x509.Certificate, error) {
		block, _ := pem.Decode([]byte(s))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("policy: time-stamp authority %s: not a PEM certificate", e.Name)
		}
		return x509.ParseCertificate(block.Bytes)
	}
	t := TSA{Name: e.Name}
	var err error
	if t.Root, err = cert(e.Root); err != nil {
		return t, err
	}
	for _, s := range e.Intermediates {
		c, err := cert(s)
		if err != nil {
			return t, err
		}
		t.Intermediates = append(t.Intermediates, c)
	}
	for _, s := range e.SigningCertificates {
		c, err := cert(s)
		if err != nil {
			return t, err
		}
		t.Signers = append(t.Signers, c)
	}
	return t, nil
}

func drandChain(name string) (DrandChain, error) {
	switch name {
	case "quicknet":
		return DrandQuicknet()
	}
	return DrandChain{}, fmt.Errorf("policy: unknown drand chain %q", name)
}
