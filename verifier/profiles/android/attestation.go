package android

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// OIDKeyAttestation is the Android key attestation extension.
var OIDKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// SecurityLevel is where a key lives.
type SecurityLevel int

const (
	Software  SecurityLevel = 0
	TEE       SecurityLevel = 1
	StrongBox SecurityLevel = 2
)

func (l SecurityLevel) String() string {
	switch l {
	case Software:
		return "Software"
	case TEE:
		return "TEE"
	case StrongBox:
		return "StrongBox"
	}
	return fmt.Sprintf("SecurityLevel(%d)", int(l))
}

// BootState is the verified boot state.
type BootState int

const (
	Verified   BootState = 0
	SelfSigned BootState = 1
	Unverified BootState = 2
	Failed     BootState = 3
)

func (s BootState) String() string {
	switch s {
	case Verified:
		return "Verified"
	case SelfSigned:
		return "SelfSigned"
	case Unverified:
		return "Unverified"
	case Failed:
		return "Failed"
	}
	return fmt.Sprintf("BootState(%d)", int(s))
}

// KeyDescription is the part of the attestation extension a verifier needs.
type KeyDescription struct {
	AttestationVersion       int64
	AttestationSecurityLevel SecurityLevel
	KeyMintVersion           int64
	KeyMintSecurityLevel     SecurityLevel
	Challenge                []byte
	Software                 AuthorizationList
	Hardware                 AuthorizationList
}

// AuthorizationList holds the tags a verifier needs; others are skipped.
type AuthorizationList struct {
	Purposes         []int64 // nil if absent
	Algorithm        *int64
	Digests          []int64
	ECCurve          *int64
	Origin           *int64
	RootOfTrust      *RootOfTrust
	OSVersion        *int64
	OSPatchLevel     *int64
	ApplicationID    *ApplicationID
	VendorPatchLevel *int64
	BootPatchLevel   *int64
	CreationDateTime *int64 // milliseconds since the epoch
	// HasValidityDates is set if any of activeDateTime, originationExpireDateTime or usageExpireDateTime is present.
	HasValidityDates bool
}

type RootOfTrust struct {
	VerifiedBootKey  []byte
	DeviceLocked     bool
	BootState        BootState
	VerifiedBootHash []byte
}

type ApplicationID struct {
	Packages         []PackageInfo
	SignatureDigests [][]byte
}

type PackageInfo struct {
	Name        string
	VersionCode int64
}

const (
	tagPurpose           = 1
	tagAlgorithm         = 2
	tagDigest            = 5
	tagECCurve           = 10
	tagActiveDateTime    = 400
	tagOriginationExpire = 401
	tagUsageExpire       = 402
	tagCreationDateTime  = 701
	tagOrigin            = 702
	tagRootOfTrust       = 704
	tagOSVersion         = 705
	tagOSPatchLevel      = 706
	tagApplicationID     = 709
	tagVendorPatchLevel  = 718
	tagBootPatchLevel    = 719
	originGenerated      = 0
	purposeSign          = 2
	algorithmEC          = 3
	digestSHA256         = 4
	curveP256            = 1
)

// ParseKeyDescription reads the attestation extension of an attested key's certificate.
func ParseKeyDescription(cert *x509.Certificate) (*KeyDescription, error) {
	var raw []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(OIDKeyAttestation) {
			if raw != nil {
				return nil, errors.New("attestation extension appears twice")
			}
			raw = e.Value
		}
	}
	if raw == nil {
		return nil, errors.New("no attestation extension")
	}
	return parseKeyDescription(raw)
}

func parseKeyDescription(raw []byte) (*KeyDescription, error) {
	top, err := parseOne(raw)
	if err != nil {
		return nil, err
	}
	if err := top.expect(classUniversal, tagSequence); err != nil {
		return nil, err
	}
	f, err := top.children()
	if err != nil {
		return nil, err
	}
	if len(f) != 8 {
		return nil, fmt.Errorf("KeyDescription has %d fields, expected 8", len(f))
	}
	kd := &KeyDescription{}
	ints := []*int64{&kd.AttestationVersion, nil, &kd.KeyMintVersion, nil}
	levels := []*SecurityLevel{nil, &kd.AttestationSecurityLevel, nil, &kd.KeyMintSecurityLevel}
	for i := 0; i < 4; i++ {
		v, err := f[i].int64()
		if err != nil {
			return nil, fmt.Errorf("KeyDescription field %d: %w", i, err)
		}
		if ints[i] != nil {
			*ints[i] = v
		} else {
			*levels[i] = SecurityLevel(v)
		}
	}
	if kd.Challenge, err = f[4].octets(); err != nil {
		return nil, fmt.Errorf("attestationChallenge: %w", err)
	}
	if _, err = f[5].octets(); err != nil {
		return nil, fmt.Errorf("uniqueId: %w", err)
	}
	if kd.Software, err = parseAuthorizationList(f[6]); err != nil {
		return nil, fmt.Errorf("softwareEnforced: %w", err)
	}
	if kd.Hardware, err = parseAuthorizationList(f[7]); err != nil {
		return nil, fmt.Errorf("hardwareEnforced: %w", err)
	}
	return kd, nil
}

func parseAuthorizationList(e element) (AuthorizationList, error) {
	var a AuthorizationList
	if err := e.expect(classUniversal, tagSequence); err != nil {
		return a, err
	}
	entries, err := e.children()
	if err != nil {
		return a, err
	}
	seen := map[int]bool{}
	for _, entry := range entries {
		if entry.class != classContext || !entry.constructed {
			return a, errors.New("entry is not an explicitly tagged field")
		}
		if seen[entry.tag] {
			return a, fmt.Errorf("tag %d appears twice", entry.tag)
		}
		seen[entry.tag] = true
		value, err := parseOne(entry.content)
		if err != nil {
			return a, fmt.Errorf("tag %d: %w", entry.tag, err)
		}
		integer := func(dst **int64) error {
			v, err := value.int64()
			if err == nil {
				*dst = &v
			}
			return err
		}
		set := func(dst *[]int64) error {
			if !value.is(classUniversal, tagSet) {
				return errors.New("expected a set")
			}
			items, err := value.children()
			if err != nil {
				return err
			}
			*dst = []int64{}
			for _, it := range items {
				v, err := it.int64()
				if err != nil {
					return err
				}
				*dst = append(*dst, v)
			}
			return nil
		}
		switch entry.tag {
		case tagPurpose:
			err = set(&a.Purposes)
		case tagAlgorithm:
			err = integer(&a.Algorithm)
		case tagDigest:
			err = set(&a.Digests)
		case tagECCurve:
			err = integer(&a.ECCurve)
		case tagActiveDateTime, tagOriginationExpire, tagUsageExpire:
			a.HasValidityDates = true
		case tagCreationDateTime:
			err = integer(&a.CreationDateTime)
		case tagOrigin:
			err = integer(&a.Origin)
		case tagOSVersion:
			err = integer(&a.OSVersion)
		case tagOSPatchLevel:
			err = integer(&a.OSPatchLevel)
		case tagVendorPatchLevel:
			err = integer(&a.VendorPatchLevel)
		case tagBootPatchLevel:
			err = integer(&a.BootPatchLevel)
		case tagRootOfTrust:
			a.RootOfTrust, err = parseRootOfTrust(value)
		case tagApplicationID:
			a.ApplicationID, err = parseApplicationID(value)
		}
		if err != nil {
			return a, fmt.Errorf("tag %d: %w", entry.tag, err)
		}
	}
	return a, nil
}

func parseRootOfTrust(e element) (*RootOfTrust, error) {
	if err := e.expect(classUniversal, tagSequence); err != nil {
		return nil, err
	}
	f, err := e.children()
	if err != nil {
		return nil, err
	}
	if len(f) != 3 && len(f) != 4 {
		return nil, fmt.Errorf("RootOfTrust has %d fields", len(f))
	}
	r := &RootOfTrust{}
	if r.VerifiedBootKey, err = f[0].octets(); err != nil {
		return nil, fmt.Errorf("verifiedBootKey: %w", err)
	}
	if r.DeviceLocked, err = f[1].bool(); err != nil {
		return nil, fmt.Errorf("deviceLocked: %w", err)
	}
	state, err := f[2].int64()
	if err != nil {
		return nil, fmt.Errorf("verifiedBootState: %w", err)
	}
	r.BootState = BootState(state)
	if len(f) == 4 {
		if r.VerifiedBootHash, err = f[3].octets(); err != nil {
			return nil, fmt.Errorf("verifiedBootHash: %w", err)
		}
	}
	return r, nil
}

// The application ID is an OCTET STRING holding a DER AttestationApplicationId.
func parseApplicationID(e element) (*ApplicationID, error) {
	raw, err := e.octets()
	if err != nil {
		return nil, err
	}
	top, err := parseOne(raw)
	if err != nil {
		return nil, err
	}
	if err := top.expect(classUniversal, tagSequence); err != nil {
		return nil, err
	}
	f, err := top.children()
	if err != nil {
		return nil, err
	}
	if len(f) != 2 || !f[0].is(classUniversal, tagSet) || !f[1].is(classUniversal, tagSet) {
		return nil, errors.New("AttestationApplicationId is not two sets")
	}
	id := &ApplicationID{}
	pkgs, err := f[0].children()
	if err != nil {
		return nil, err
	}
	for _, p := range pkgs {
		pf, err := p.children()
		if err != nil || len(pf) != 2 {
			return nil, errors.New("bad AttestationPackageInfo")
		}
		name, err := pf[0].octets()
		if err != nil {
			return nil, fmt.Errorf("package name: %w", err)
		}
		version, err := pf[1].int64()
		if err != nil {
			return nil, fmt.Errorf("package version: %w", err)
		}
		id.Packages = append(id.Packages, PackageInfo{Name: string(name), VersionCode: version})
	}
	digests, err := f[1].children()
	if err != nil {
		return nil, err
	}
	for _, d := range digests {
		b, err := d.octets()
		if err != nil {
			return nil, fmt.Errorf("signature digest: %w", err)
		}
		id.SignatureDigests = append(id.SignatureDigests, b)
	}
	return id, nil
}

func (l SecurityLevel) MarshalText() ([]byte, error) { return []byte(l.String()), nil }
func (s BootState) MarshalText() ([]byte, error)     { return []byte(s.String()), nil }
