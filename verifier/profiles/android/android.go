// Package android is the Android key attestation profile (spec/profiles/android.md).
package android

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
)

const (
	Name         = "android"
	KeyChallenge = "hardware-attested-statement/v0.1/android/key"
)

// Evidence is the profile's key evidence: the attestation certificate chain, leaf first, without the root.
type Evidence struct {
	Profile      string           `json:"profile"`
	Certificates []verifier.Bytes `json:"certificates"`
}

// Signer is a policy entry: an app, by package and signing certificates, optionally only some versions.
type Signer struct {
	Profile             string   `json:"profile"`
	Package             string   `json:"package"`
	SigningCertificates []string `json:"signingCertificates"`
	VersionCodes        []int64  `json:"versionCodes,omitzero"`
}

// Settings are the policy's "android" profile settings.
type Settings struct {
	RequireStrongBox        bool       `json:"requireStrongBox"`
	AllowFactoryProvisioned bool       `json:"allowFactoryProvisioned"`
	MinOSPatchLevel         int64      `json:"minOsPatchLevel"`
	MinVendorPatchLevel     int64      `json:"minVendorPatchLevel"`
	MinBootPatchLevel       int64      `json:"minBootPatchLevel"`
	OS                      *OSSetting `json:"os"`
	MaxListAgeHours         *int64     `json:"maxListAgeHours"`
	MaxKeyAgeHours          int64      `json:"maxKeyAgeHours"`
}

// OSSetting says which operating systems to accept: the device's stock OS (verified by its own boot chain), and
// alternative OSes whose verified boot key is on one of the named lists. Both members are required.
type OSSetting struct {
	Stock        *bool     `json:"stock"`
	BootKeyLists *[]string `json:"bootKeyLists"`
}

// AOSP's published test keys (external/avb/test/data), as verifiedBootKey: a device whose stock OS is signed with
// one boots anyone's OS as Verified.
var aospTestKeys = map[string]string{
	"22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c": "testkey_rsa2048",
	"7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6": "testkey_rsa4096",
	"e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614": "testkey_rsa8192",
}

// App is what the attestation says about the signing app.
type App struct {
	Package             string   `json:"package"`
	VersionCode         int64    `json:"versionCode"`
	SigningCertificates []string `json:"signingCertificates"`
}

// Device is what the attestation says about the device, as of the key's creation.
type Device struct {
	KeyStorage       SecurityLevel `json:"keyStorage"`
	Provisioning     Provisioning  `json:"provisioning"`
	BootState        BootState     `json:"bootState"`
	BootKey          string        `json:"bootKey"`
	OS               string        `json:"os"` // "stock" or the name of the boot key list
	OSVersion        int64         `json:"osVersion"`
	OSPatchLevel     int64         `json:"osPatchLevel"`
	VendorPatchLevel int64         `json:"vendorPatchLevel"`
	BootPatchLevel   int64         `json:"bootPatchLevel"`
	KeyCreated       *time.Time    `json:"keyCreated,omitzero"` // as the OS stated it
}

// Profile verifies Android key attestation.
type Profile struct {
	trust *Trust
}

// New makes the profile from its trust store.
func New(trust *Trust) *Profile { return &Profile{trust: trust} }

func (p *Profile) Name() string { return Name }

// settings reads the profile's settings; nil gives the defaults, which accept the stock OS and GrapheneOS, and TEE
// or StrongBox keys on remotely provisioned devices.
func (p *Profile) settings(raw jsontext.Value) (*Settings, error) {
	s := &Settings{}
	if len(raw) > 0 {
		if err := verifier.UnmarshalStrict(raw, s); err != nil {
			return nil, fmt.Errorf("android settings: %w", err)
		}
	}
	if s.OS == nil {
		s.OS = &OSSetting{Stock: new(true), BootKeyLists: &[]string{"grapheneos"}}
	}
	if s.OS.Stock == nil || s.OS.BootKeyLists == nil {
		return nil, errors.New("android settings: os needs both stock and bootKeyLists")
	}
	if !*s.OS.Stock && len(*s.OS.BootKeyLists) == 0 {
		return nil, errors.New("android settings: os accepts no operating system")
	}
	for _, l := range *s.OS.BootKeyLists {
		if _, ok := p.trust.BootKeyLists[l]; !ok {
			return nil, fmt.Errorf("android settings: unknown boot key list %q", l)
		}
	}
	if s.MaxListAgeHours == nil {
		s.MaxListAgeHours = new(int64(48))
	}
	if *s.MaxListAgeHours <= 0 || s.MaxKeyAgeHours < 0 {
		return nil, errors.New("android settings: maxListAgeHours must be positive, and maxKeyAgeHours not negative")
	}
	for _, m := range []int64{s.MinOSPatchLevel, s.MinVendorPatchLevel, s.MinBootPatchLevel} {
		if m != 0 && (m < 190001 || m > 999912 || m%100 < 1 || m%100 > 12) {
			return nil, fmt.Errorf("android settings: patch level minimum %d isn't YYYYMM", m)
		}
	}
	return s, nil
}

func parseSigner(raw jsontext.Value) (*Signer, error) {
	var s Signer
	if err := verifier.UnmarshalStrict(raw, &s); err != nil {
		return nil, fmt.Errorf("android signer: %w", err)
	}
	if s.Package == "" || len(s.SigningCertificates) == 0 {
		return nil, errors.New("android signer: needs a package and signingCertificates")
	}
	if s.VersionCodes != nil && len(s.VersionCodes) == 0 {
		return nil, errors.New("android signer: versionCodes is empty (leave it out to accept any version)")
	}
	for i, c := range s.SigningCertificates {
		c = strings.ToLower(strings.ReplaceAll(c, ":", ""))
		if b, err := hex.DecodeString(c); err != nil || len(b) != 32 {
			return nil, fmt.Errorf("android signer: %q isn't a SHA-256", s.SigningCertificates[i])
		}
		s.SigningCertificates[i] = c
	}
	return &s, nil
}

func (p *Profile) CheckPolicy(trusted []jsontext.Value, settings jsontext.Value) error {
	for _, raw := range trusted {
		if _, err := parseSigner(raw); err != nil {
			return err
		}
	}
	_, err := p.settings(settings)
	return err
}

func parseEvidence(raw jsontext.Value) ([]*x509.Certificate, error) {
	var ev Evidence
	if err := verifier.UnmarshalStrict(raw, &ev); err != nil {
		return nil, fmt.Errorf("android key evidence: %w", err)
	}
	if len(ev.Certificates) == 0 {
		return nil, errors.New("android key evidence: no certificates")
	}
	var chain []*x509.Certificate
	for i, der := range ev.Certificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("attestation certificate %d: %w", i, err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

// Binding is the leaf certificate's tbsCertificate (spec: profiles/android.md): it holds the key and the
// attestation, and unlike the certificate's own signature can't be altered.
func (p *Profile) Binding(raw jsontext.Value) ([]byte, error) {
	chain, err := parseEvidence(raw)
	if err != nil {
		return nil, err
	}
	return chain[0].RawTBSCertificate, nil
}

func (p *Profile) VerifyKey(raw jsontext.Value, trusted []jsontext.Value, settings jsontext.Value, kc verifier.KeyContext) (*verifier.Key, error) {
	now := kc.Now
	s, err := p.settings(settings)
	if err != nil {
		return nil, err
	}
	chain, err := parseEvidence(raw)
	if err != nil {
		return nil, err
	}
	ci, err := verifyChain(chain, p.trust.Roots)
	if err != nil {
		return nil, err
	}
	maxAge := time.Duration(*s.MaxListAgeHours) * time.Hour
	if t := p.trust.RevocationProduced; t.IsZero() || now.Sub(t) > maxAge {
		return nil, fmt.Errorf("the revocation list is older than %d hours: fetch it again", *s.MaxListAgeHours)
	}
	all := append(slices.Clone(ci.certs), ci.root)
	for _, c := range all[1:] { // the leaf is the app's key, issued by the device: Google revokes attestation keys
		if status, revoked := p.trust.revoked(c.SerialNumber); revoked {
			return nil, fmt.Errorf("attestation certificate %s is %s", c.SerialNumber.Text(16), status)
		}
	}
	pub, ok := ci.certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("the attested key is not a P-256 key")
	}
	kd, err := ParseKeyDescription(ci.certs[0])
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	if err := checkKey(kd); err != nil {
		return nil, err
	}
	dev, err := p.checkDevice(kd, ci, s, now)
	if err != nil {
		return nil, err
	}
	app, err := checkApp(kd, trusted)
	if err != nil {
		return nil, err
	}
	key := &verifier.Key{PublicKey: pub, Signer: app, Device: dev, ValidFrom: all[0].NotBefore, ValidUntil: all[0].NotAfter,
		Created: dev.KeyCreated, MaxAge: time.Duration(s.MaxKeyAgeHours) * time.Hour}
	for _, c := range all {
		if c.NotBefore.After(key.ValidFrom) {
			key.ValidFrom = c.NotBefore
		}
		if c.NotAfter.Before(key.ValidUntil) {
			key.ValidUntil = c.NotAfter
		}
	}
	created := "unknown"
	if dev.KeyCreated != nil {
		created = dev.KeyCreated.UTC().Format("2006-01-02 15:04:05 MST")
	}
	key.Description = []string{
		fmt.Sprintf("app %s, versionCode %d (signing certificate %s)", app.Package, app.VersionCode, strings.Join(app.SigningCertificates, ", ")),
		fmt.Sprintf("key in %s (%s attestation), created %s; bootloader locked; %s OS (%s); patches: OS %d, vendor %d, boot %d",
			dev.KeyStorage, dev.Provisioning, created, dev.OS, dev.BootState, dev.OSPatchLevel, dev.VendorPatchLevel, dev.BootPatchLevel),
	}
	return key, nil
}

// checkKey checks the key's own properties: made for this format, in the hardware, for signing only.
func checkKey(kd *KeyDescription) error {
	if !bytes.Equal(kd.Challenge, []byte(KeyChallenge)) {
		return errors.New("the key wasn't made for this version of hardware-attested statements (wrong attestation challenge)")
	}
	hw := kd.Hardware
	if o := hw.Origin; o == nil || *o != originGenerated {
		return errors.New("the key wasn't generated in the secure hardware")
	}
	if hw.Algorithm == nil || *hw.Algorithm != algorithmEC || hw.ECCurve == nil || *hw.ECCurve != curveP256 {
		return errors.New("the attestation doesn't say the key is EC P-256")
	}
	if !slices.Equal(hw.Purposes, []int64{purposeSign}) {
		return fmt.Errorf("the key's purposes are %v, not only SIGN", hw.Purposes)
	}
	if !slices.Contains(hw.Digests, digestSHA256) {
		return errors.New("the key can't be used with SHA-256")
	}
	if hw.HasValidityDates || kd.Software.HasValidityDates {
		return errors.New("the key has validity dates, which this profile doesn't allow")
	}
	return nil
}

func (p *Profile) checkDevice(kd *KeyDescription, ci *chainInfo, s *Settings, now time.Time) (*Device, error) {
	level := kd.AttestationSecurityLevel
	if level != kd.KeyMintSecurityLevel || (level != TEE && level != StrongBox) {
		return nil, fmt.Errorf("the key isn't hardware-backed (attestation %v, KeyMint %v)", kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel)
	}
	if ci.level != level {
		return nil, fmt.Errorf("the attestation says %v but its certificates say %v", level, ci.level)
	}
	d := &Device{KeyStorage: level, Provisioning: ci.provisioning}
	if s.RequireStrongBox && level != StrongBox {
		return nil, errors.New("the key is not in StrongBox, which the policy requires")
	}
	if ci.provisioning != RemotelyProvisioned && !s.AllowFactoryProvisioned {
		return nil, errors.New("the device's attestation key was provisioned at the factory, which the policy rejects")
	}

	rot := kd.Hardware.RootOfTrust
	if rot == nil {
		return nil, errors.New("no hardware-enforced root of trust")
	}
	d.BootState, d.BootKey = rot.BootState, hex.EncodeToString(rot.VerifiedBootKey)
	if !rot.DeviceLocked {
		return nil, errors.New("the bootloader is unlocked")
	}
	if len(rot.VerifiedBootKey) != 32 {
		return nil, fmt.Errorf("the verified boot key is %d bytes, not 32", len(rot.VerifiedBootKey))
	}
	switch rot.BootState {
	case Verified:
		if !*s.OS.Stock {
			return nil, errors.New("the device runs its stock OS, which the policy doesn't accept")
		}
		if name, ok := aospTestKeys[d.BootKey]; ok {
			return nil, fmt.Errorf("the device's OS is signed with AOSP's public test key %s, so anyone can sign one it boots", name)
		}
		d.OS = "stock"
	case SelfSigned:
		var reasons []string
		for _, name := range *s.OS.BootKeyLists {
			l := p.trust.BootKeyLists[name]
			switch {
			case l.Err != nil:
				reasons = append(reasons, l.Err.Error())
			case now.Sub(l.Produced) > time.Duration(*s.MaxListAgeHours)*time.Hour:
				reasons = append(reasons, fmt.Sprintf("the %s list is older than %d hours", name, *s.MaxListAgeHours))
			case l.Keys[d.BootKey]:
				d.OS = name
			}
		}
		if d.OS == "" {
			return nil, fmt.Errorf("the device runs a self-signed OS whose boot key is on no trusted list %v", reasons)
		}
	default:
		return nil, fmt.Errorf("verified boot state is %v", rot.BootState)
	}
	get := func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	}
	hw := kd.Hardware
	d.OSVersion, d.OSPatchLevel = get(hw.OSVersion), get(hw.OSPatchLevel)
	d.VendorPatchLevel, d.BootPatchLevel = get(hw.VendorPatchLevel), get(hw.BootPatchLevel)
	for _, c := range []struct {
		name string
		got  *int64
		min  int64
	}{{"OS", hw.OSPatchLevel, s.MinOSPatchLevel}, {"vendor", hw.VendorPatchLevel, s.MinVendorPatchLevel},
		{"boot", hw.BootPatchLevel, s.MinBootPatchLevel}} {
		if c.got == nil {
			if c.min > 0 {
				return nil, fmt.Errorf("no %s patch level, and the policy requires %d", c.name, c.min)
			}
			continue
		}
		month := *c.got // YYYYMM or YYYYMMDD
		switch {
		case month >= 100000 && month <= 999999:
		case month >= 10000000 && month <= 99999999:
			month /= 100
		default:
			return nil, fmt.Errorf("%s patch level %d is neither YYYYMM nor YYYYMMDD", c.name, *c.got)
		}
		if c.min > 0 && month < c.min {
			return nil, fmt.Errorf("%s patch level %d is older than %d", c.name, *c.got, c.min)
		}
	}
	for _, list := range []AuthorizationList{kd.Software, kd.Hardware} {
		if ms := list.CreationDateTime; ms != nil {
			t := time.UnixMilli(*ms)
			d.KeyCreated = &t
		}
	}
	return d, nil
}

func checkApp(kd *KeyDescription, trusted []jsontext.Value) (*App, error) {
	id := kd.Software.ApplicationID
	if id == nil || len(id.Packages) != 1 || len(id.SignatureDigests) == 0 {
		return nil, errors.New("the attestation doesn't name exactly one app and its signing certificates")
	}
	pkg := id.Packages[0]
	app := &App{Package: pkg.Name, VersionCode: pkg.VersionCode}
	for _, d := range id.SignatureDigests {
		app.SigningCertificates = append(app.SigningCertificates, hex.EncodeToString(d))
	}
	var reason error = fmt.Errorf("app %s is not trusted for this predicate type", pkg.Name)
	for _, raw := range trusted {
		s, err := parseSigner(raw)
		if err != nil {
			return nil, err
		}
		if s.Package != pkg.Name {
			continue
		}
		ok := true
		for _, d := range app.SigningCertificates {
			ok = ok && slices.Contains(s.SigningCertificates, d)
		}
		switch {
		case !ok:
			reason = fmt.Errorf("%s is signed by a key the policy doesn't trust", pkg.Name)
		case len(s.VersionCodes) > 0 && !slices.Contains(s.VersionCodes, pkg.VersionCode):
			reason = fmt.Errorf("%s versionCode %d is not one the policy accepts", pkg.Name, pkg.VersionCode)
		default:
			return app, nil
		}
	}
	return nil, reason
}
