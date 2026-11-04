package verifier_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/predicates/httpresponse"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/profiles/android"
)

// --- A minimal DER encoder, to build fake attestation extensions.

func tlv(class, tag int, constructed bool, content []byte) []byte {
	id := byte(class << 6)
	if constructed {
		id |= 0x20
	}
	var out []byte
	if tag < 31 {
		out = []byte{id | byte(tag)}
	} else {
		var t []byte
		for n := tag; n > 0; n >>= 7 {
			t = append([]byte{byte(n&0x7f) | 0x80}, t...)
		}
		t[len(t)-1] &= 0x7f
		out = append([]byte{id | 0x1f}, t...)
	}
	switch n := len(content); {
	case n < 128:
		out = append(out, byte(n))
	case n < 256:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func cat(parts ...[]byte) (out []byte) {
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
func seq(parts ...[]byte) []byte        { return tlv(0, 16, true, cat(parts...)) }
func set(parts ...[]byte) []byte        { return tlv(0, 17, true, cat(parts...)) }
func octets(b []byte) []byte            { return tlv(0, 4, false, b) }
func explicit(tag int, v []byte) []byte { return tlv(2, tag, true, v) }
func integer(n int64) []byte {
	b := big.NewInt(n).Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(0, 2, false, b)
}
func enumerated(n int64) []byte { return tlv(0, 10, false, integer(n)[2:]) }

// keyDescription is an attestation of a StrongBox EC P-256 signing key for pkg, signed by signer, on a locked
// device running its stock OS; extra entries go into the hardware-enforced list.
func keyDescription(pkg string, versionCode int64, signer []byte, purposes []byte, extra ...[]byte) []byte {
	appID := seq(set(seq(octets([]byte(pkg)), integer(versionCode))), set(octets(signer)))
	rot := seq(octets(make([]byte, 32)), tlv(0, 1, false, []byte{0xff}), enumerated(0), octets(make([]byte, 32)))
	hw := cat(explicit(1, purposes), explicit(2, integer(3)), explicit(5, set(integer(4))), explicit(10, integer(1)))
	hw = cat(hw, cat(extra...), explicit(702, integer(0)), explicit(704, rot), explicit(705, integer(160000)),
		explicit(706, integer(202610)), explicit(718, integer(20261005)), explicit(719, integer(20261005)))
	return seq(integer(300), enumerated(2), integer(300), enumerated(2), octets([]byte(android.KeyChallenge)), octets(nil),
		seq(explicit(701, integer(1762130000000)), explicit(709, octets(appID))), tlv(0, 16, true, hw))
}

type fakeOptions struct {
	pkg       string
	signer    []byte
	factory   bool             // factory-provisioned chain instead of RKP
	publicKey *ecdsa.PublicKey // attest this key instead of a new one (no private key then)
	extension []byte           // instead of keyDescription(pkg, 1, signer, {SIGN})
	notBefore time.Time        // of every certificate
	notAfter  time.Time
}

type fakeKey struct {
	key   *ecdsa.PrivateKey
	leaf  *x509.Certificate
	chain [][]byte // leaf first, without the root
	root  *x509.Certificate
}

// newFakeKey makes a key with a StrongBox attestation chain under a fake root, as Keystore would.
func newFakeKey(t *testing.T, o fakeOptions) *fakeKey {
	t.Helper()
	now := time.Now()
	if o.notBefore.IsZero() {
		o.notBefore, o.notAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
	}
	if o.extension == nil {
		o.extension = keyDescription(o.pkg, 1, o.signer, set(integer(2)))
	}
	serial := int64(0)
	cert := func(subject pkix.Name, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey, ca bool,
		ext []pkix.Extension) (*x509.Certificate, *ecdsa.PrivateKey) {
		var key *ecdsa.PrivateKey
		if pub == nil {
			key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			pub = &key.PublicKey
		}
		serial++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano() + serial), Subject: subject,
			NotBefore: o.notBefore, NotAfter: o.notAfter, BasicConstraintsValid: true, IsCA: ca, ExtraExtensions: ext}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	root, rootKey := cert(pkix.Name{CommonName: "FAKE root (test only)"}, nil, nil, nil, true, nil)
	top := pkix.Name{CommonName: "Droid CA2", Organization: []string{"Google LLC"}}
	att := pkix.Name{CommonName: "f00d", Organization: []string{"StrongBox"}}
	if o.factory {
		title := func(serial string) pkix.Name {
			return pkix.Name{SerialNumber: serial, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 12}, Value: "StrongBox"}}}
		}
		top, att = title("0a"), title("0b")
	}
	topCert, topKey := cert(top, root, rootKey, nil, true, nil)
	attCert, attKey := cert(att, topCert, topKey, nil, true, nil)
	leaf, leafKey := cert(pkix.Name{CommonName: "Android Keystore Key"}, attCert, attKey, o.publicKey, false,
		[]pkix.Extension{{Id: android.OIDKeyAttestation, Value: o.extension}})
	return &fakeKey{leafKey, leaf, [][]byte{leaf.Raw, attCert.Raw, topCert.Raw}, root}
}

// testTSA is a time-stamp authority for tests.
type testTSA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	root *x509.Certificate
}

func newTestTSA(t *testing.T) *testTSA {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test TSA root"},
		NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// RFC 3161 requires the extended key usage to be critical, which Go's ExtKeyUsage field doesn't make it.
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test TSA"},
		NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testTSA{cert, key, root}
}

// policyEntry is the TSA as a policy's timestampAuthorities entry.
func (ts *testTSA) policyEntry() string {
	p := func(c *x509.Certificate) string {
		s, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
		return string(s)
	}
	return `{"name": "test TSA", "root": ` + p(ts.root) + `, "signingCertificates": [` + p(ts.cert) + `]}`
}

// signedID is b's signed-statement ID, with the Android profile's key binding.
func signedID(t *testing.T, b *verifier.Bundle) [32]byte {
	t.Helper()
	binding, err := android.New(nil).Binding(b.VerificationMaterial.Key.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return verifier.SignedStatementID(android.Name, verifier.StatementID(b.DSSEEnvelope.Payload), binding, b.DSSEEnvelope.Signatures[0].Sig)
}

// stamp time-stamps b alone (a tree of one leaf, whose root is the leaf's hash).
func (ts *testTSA) stamp(t *testing.T, b *verifier.Bundle, at time.Time, accuracy time.Duration) {
	t.Helper()
	id := signedID(t, b)
	resp, err := (&timestamp.Timestamp{HashAlgorithm: crypto.SHA256, HashedMessage: rfc6962.DefaultHasher.HashLeaf(id[:]),
		Time: at, Accuracy: accuracy, Policy: asn1.ObjectIdentifier{1, 2, 3, 4}}).CreateResponseWithOpts(ts.cert, ts.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	b.VerificationMaterial.Timestamp = &verifier.Timestamp{Token: resp, Tree: verifier.Tree{Size: 1, Index: 0, Path: []verifier.Bytes{}}}
}

// signBundle signs statement with key, as an app would (low-S), with chain as its evidence.
func signBundle(t *testing.T, statement []byte, key *ecdsa.PrivateKey, chain [][]byte) *verifier.Bundle {
	t.Helper()
	digest := sha256.Sum256(verifier.PAE(verifier.InTotoPayload, statement))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return bundleWith(t, statement, lowS(r, s), chain)
}

func lowS(r, s *big.Int) []byte {
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	sig, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	return sig
}

func bundleWith(t *testing.T, statement, sig []byte, chain [][]byte) *verifier.Bundle {
	t.Helper()
	b := &verifier.Bundle{MediaType: verifier.BundleMediaType,
		DSSEEnvelope: verifier.DSSEEnvelope{PayloadType: verifier.InTotoPayload, Payload: statement,
			Signatures: []verifier.DSSESignature{{Sig: sig}}}}
	ev := android.Evidence{Profile: android.Name}
	for _, c := range chain {
		ev.Certificates = append(ev.Certificates, c)
	}
	raw, _ := json.Marshal(ev)
	if err := json.Unmarshal(raw, &b.VerificationMaterial.Key); err != nil {
		t.Fatal(err)
	}
	return b
}

const derivedType = "urn:test:derived:v1"

// listing is a predicate.inputs entry naming b.
func listing(t *testing.T, b *verifier.Bundle) string {
	id := verifier.StatementID(b.DSSEEnvelope.Payload)
	sid := signedID(t, b)
	return listingOf(hex.EncodeToString(id[:]), hex.EncodeToString(sid[:]))
}

func listingOf(id, signedStatementID string) string {
	return `{"mediaType":"application/vnd.in-toto+json","digest":{"sha256":"` + id +
		`"},"annotations":{"signedStatementId":"` + signedStatementID + `"}}`
}

func statement(predicateType, predicate string) []byte {
	return []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"text","digest":{"sha256":"` +
		strings.Repeat("00", 32) + `"}}],"predicateType":"` + predicateType + `","predicate":{` + predicate + `}}`)
}

// derivedSetup is a capture and a trusted app that makes statements from captures.
type derivedSetup struct {
	capture *verifier.Bundle
	key     *fakeKey
	tsa     *testTSA
	params  policyParams
	trust   *android.Trust
}

func newDerivedSetup(t *testing.T, derivedPolicy string) *derivedSetup {
	t.Helper()
	_, capture, err := verifier.ParseHTTPResponse(readCapture(t, "example.http"))
	if err != nil {
		t.Fatal(err)
	}
	signer := sha256.Sum256([]byte("derived app signing certificate"))
	key := newFakeKey(t, fakeOptions{pkg: "org.example.derived", signer: signer[:]})
	tsa := newTestTSA(t)
	trust := testTrust(t)
	trust.Roots = append(trust.Roots, key.root)
	params := defaultParams()
	params.tsas = `["freetsa", ` + tsa.policyEntry() + `]`
	params.extraTypes = `"` + derivedType + `": {` + derivedPolicy + ` "trustedSigners": [{"profile": "android",
	  "package": "org.example.derived", "signingCertificates": ["` + hex.EncodeToString(signer[:]) + `"]}]}`
	return &derivedSetup{capture, key, tsa, params, trust}
}

// derived signs a statement with the given predicate members, time-stamped at stampAt unless it's zero.
func (s *derivedSetup) derived(t *testing.T, predicate string, stampAt time.Time, inputs ...*verifier.Bundle) *verifier.Bundle {
	t.Helper()
	b := signBundle(t, statement(derivedType, predicate), s.key.key, s.key.chain)
	if !stampAt.IsZero() {
		s.tsa.stamp(t, b, stampAt, 0)
	}
	b.VerificationMaterial.InputBundles = inputs
	return b
}

// A statement derived from a capture, with the capture's bundle nested in it: one time-stamp at the end bounds the
// capture from above, and the capture's drand round bounds the derived statement from below.
func TestNestedInputsPropagateTimeBounds(t *testing.T) {
	s := newDerivedSetup(t, `"requireTimestamp": true, "requireStartedAfter": true,`)
	v := mustVerifier(t, s.params.policy(t), s.trust)
	inputs := `"inputs":[` + listing(t, s.capture) + `]`
	now := time.Now().Truncate(time.Second)

	d, err := v.Verify(s.derived(t, inputs, now, s.capture))
	if err != nil {
		t.Fatal(err)
	}
	c := d.Inputs[0].Result
	if c == nil {
		t.Fatal("input not verified")
	}
	// The derived statement has no startedAfter of its own: its lower bound comes from the capture. Tokens
	// without an accuracy count as accurate to one second.
	if !d.NotAfter.Equal(now.Add(time.Second)) || d.StartedAfter != nil || !d.NotBefore.Equal(c.NotBefore) || c.NotBefore.IsZero() {
		t.Errorf("derived bounds %v – %v; capture from %v", d.NotBefore, d.NotAfter, c.NotBefore)
	}
	if !c.NotAfter.Equal(c.Timestamp.Add(time.Second)) {
		t.Errorf("capture's upper bound %v, want its own time-stamp %v", c.NotAfter, *c.Timestamp)
	}
	if d.Key.Device.(*android.Device).KeyStorage != android.StrongBox || d.Key.Signer.(*android.App).Package != "org.example.derived" {
		t.Errorf("derived: %+v %+v", d.Key.Device, d.Key.Signer)
	}

	// The input bundle presented separately works the same way.
	if d, err := v.Verify(s.derived(t, inputs, now), s.capture); err != nil || d.Inputs[0].Result == nil {
		t.Errorf("presented input: %v", err)
	}
	// Not presented: reported as not verified, and so gives no lower bound, which this policy requires.
	if _, err := v.Verify(s.derived(t, inputs, now)); err == nil || !strings.Contains(err.Error(), "startedAfter is required") {
		t.Errorf("unverified input gave a lower bound: %v", err)
	}
	// A bundle that isn't one of the listed inputs, nested or presented.
	other := `"inputs":[` + listingOf(strings.Repeat("11", 32), strings.Repeat("22", 32)) + `]`
	if _, err := v.Verify(s.derived(t, other, now, s.capture)); err == nil {
		t.Error("unlisted nested input accepted")
	}
	if _, err := v.Verify(s.derived(t, other, now), s.capture); err == nil {
		t.Error("unlisted presented input accepted")
	}
	// Listed with another signature's hash: the same statement signed again isn't the listed input.
	captureID := verifier.StatementID(s.capture.DSSEEnvelope.Payload)
	wrongSig := `"inputs":[` + listingOf(hex.EncodeToString(captureID[:]), strings.Repeat("22", 32)) + `]`
	if _, err := v.Verify(s.derived(t, wrongSig, now, s.capture)); err == nil {
		t.Error("input with a different signature accepted")
	}
	// Time-stamped before the capture could have been made.
	if _, err := v.Verify(s.derived(t, inputs, c.NotBefore.Add(-time.Hour), s.capture)); err == nil {
		t.Error("derived statement time-stamped before its input accepted")
	}
	// The capture's own time-stamp is not needed: the derived statement's bounds it from above.
	stripped := *s.capture
	stripped.VerificationMaterial.Timestamp = nil
	if d, err := v.Verify(s.derived(t, inputs, now, &stripped)); err != nil || !d.Inputs[0].Result.NotAfter.Equal(now.Add(time.Second)) {
		t.Errorf("input without its own time-stamp: %v", err)
	}
	// A predicate type the policy doesn't list isn't accepted, even from a trusted key.
	b := signBundle(t, statement("urn:test:other", inputs), s.key.key, s.key.chain)
	if _, err := v.Verify(b); err == nil {
		t.Error("unknown predicate type accepted")
	}
}

// A time-stamp that passes gives its bound even if another bundle of the same node fails, whichever comes first
// (spec section 4).
func TestBoundsDontDependOnBundleOrder(t *testing.T) {
	s := newDerivedSetup(t, "")
	v := mustVerifier(t, s.params.policy(t), s.trust)
	now := time.Now().Truncate(time.Second)
	// Without its own time-stamp, the capture's upper bound can only come from the statement naming it.
	capture := *s.capture
	capture.VerificationMaterial.Timestamp = nil
	good := s.derived(t, `"inputs":[`+listing(t, s.capture)+`]`, now, &capture)
	bad := *good
	bad.VerificationMaterial.Timestamp = s.derived(t, "", now).VerificationMaterial.Timestamp // another statement's
	for name, order := range map[string][2]*verifier.Bundle{"failing copy last": {good, &bad}, "failing copy first": {&bad, good}} {
		r, err := v.Verify(order[0], order[1])
		if err == nil || r == nil {
			t.Fatalf("%s: a node with a failing bundle: result %v, error %v", name, r, err)
		}
		if c := r.Inputs[0].Result; c == nil {
			t.Errorf("%s: input not linked", name)
		} else if !c.NotAfter.Equal(now.Add(time.Second)) {
			t.Errorf("%s: input's upper bound %v, want the passing time-stamp's %v", name, c.NotAfter, now.Add(time.Second))
		}
	}
}

// A startedAfter that passes gives its bound even if the statement's inputs fail (spec section 4).
func TestLowerBoundDespiteBadInputs(t *testing.T) {
	s := newDerivedSetup(t, "")
	v := mustVerifier(t, s.params.policy(t), s.trust)
	st, err := verifier.ParseStatement(s.capture.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	after, err := st.StartedAfter()
	if err != nil || after == nil {
		t.Fatalf("capture's startedAfter: %v %v", after, err)
	}
	sa, _ := json.Marshal(after)
	x := s.derived(t, `"inputs":[{"mediaType":"text/plain"}], "startedAfter":`+string(sa), time.Time{})
	r, err := v.Verify(s.derived(t, `"inputs":[`+listing(t, x)+`]`, time.Time{}, x))
	if err == nil || r == nil || r.Inputs[0].Result == nil || r.Inputs[0].Result.Passed {
		t.Fatalf("statement with a malformed input: result %v, error %v", r, err)
	}
	if r.NotBefore.IsZero() || !r.NotBefore.Equal(*r.Inputs[0].Result.StartedAfter) {
		t.Errorf("lower bound %v, want the failing input's startedAfter", r.NotBefore)
	}
}

// A time-stamp's accuracy widens the upper bound.
func TestTimestampAccuracy(t *testing.T) {
	s := newDerivedSetup(t, "")
	v := mustVerifier(t, s.params.policy(t), s.trust)
	b := s.derived(t, "", time.Time{})
	now := time.Now().Truncate(time.Second)
	s.tsa.stamp(t, b, now, 3*time.Second)
	r, err := v.Verify(b)
	if err != nil {
		t.Fatal(err)
	}
	if !r.NotAfter.Equal(now.Add(3 * time.Second)) {
		t.Errorf("upper bound %v, want %v", r.NotAfter, now.Add(3*time.Second))
	}
}

// Without a time-stamp anywhere, the key evidence must be valid at verification time; with one, at signing time.
func TestExpiredEvidence(t *testing.T) {
	s := newDerivedSetup(t, "")
	signer := sha256.Sum256([]byte("derived app signing certificate"))
	past := time.Now().Add(-30 * 24 * time.Hour)
	old := newFakeKey(t, fakeOptions{pkg: "org.example.derived", signer: signer[:], notBefore: past, notAfter: past.Add(24 * time.Hour)})
	s.trust.Roots = append(s.trust.Roots, old.root)
	v := mustVerifier(t, s.params.policy(t), s.trust)
	b := signBundle(t, statement(derivedType, ""), old.key, old.chain)
	if _, err := v.Verify(b); err == nil || !strings.Contains(err.Error(), "isn't valid now") {
		t.Errorf("expired evidence without a time-stamp: %v", err)
	}
	s.tsa.stamp(t, b, past.Add(time.Hour), 0)
	if _, err := v.Verify(b); err != nil {
		t.Errorf("expired evidence, time-stamped while valid: %v", err)
	}
}

// The Android profile's checks on the key and its chain.
func TestAndroidKeyChecks(t *testing.T) {
	signer := sha256.Sum256([]byte("derived app signing certificate"))
	o := fakeOptions{pkg: "org.example.derived", signer: signer[:]}
	kd := func(purposes []byte, extra ...[]byte) []byte {
		return keyDescription(o.pkg, 1, o.signer, purposes, extra...)
	}
	cases := map[string]struct {
		opts    fakeOptions
		ok      bool
		setting string
	}{
		"rkp StrongBox":                          {opts: o, ok: true},
		"factory provisioned":                    {opts: fakeOptions{pkg: o.pkg, signer: o.signer, factory: true}},
		"factory provisioned, allowed":           {opts: fakeOptions{pkg: o.pkg, signer: o.signer, factory: true}, ok: true, setting: `{"allowFactoryProvisioned": true}`},
		"purposes SIGN and VERIFY":               {opts: fakeOptions{pkg: o.pkg, signer: o.signer, extension: kd(set(integer(2), integer(3)))}},
		"usage expiry":                           {opts: fakeOptions{pkg: o.pkg, signer: o.signer, extension: kd(set(integer(2)), explicit(402, integer(1)))}},
		"active date":                            {opts: fakeOptions{pkg: o.pkg, signer: o.signer, extension: kd(set(integer(2)), explicit(400, integer(1)))}},
		"vendor patch too old":                   {opts: o, setting: `{"minVendorPatchLevel": 202611}`},
		"boot patch too old":                     {opts: o, setting: `{"minBootPatchLevel": 202611}`},
		"boot patch new enough":                  {opts: o, ok: true, setting: `{"minBootPatchLevel": 202610}`},
		"stock OS not accepted (per-type empty)": {opts: o, setting: `{"os": {"stock": false, "bootKeyLists": ["grapheneos"]}}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			k := newFakeKey(t, c.opts)
			s := newDerivedSetup(t, "")
			if c.setting != "" {
				// Per predicate type, replacing the (default) global settings.
				s.params.extraTypes = strings.Replace(s.params.extraTypes, `"trustedSigners"`, `"profiles": {"android": `+c.setting+`}, "trustedSigners"`, 1)
			}
			s.trust.Roots = append(s.trust.Roots, k.root)
			v := mustVerifier(t, s.params.policy(t), s.trust)
			r, err := v.Verify(signBundle(t, statement(derivedType, ""), k.key, k.chain))
			if c.ok != (err == nil) {
				t.Fatalf("ok %v, err %v", c.ok, err)
			}
			if err == nil && r.Key.Device.(*android.Device).KeyCreated == nil {
				t.Error("no key creation time")
			}
			t.Log(err)
		})
	}
}

// Regression (review F1): anyone with an attested key could sign a certificate with a forged attestation for
// another app and put it in front of their real chain.
func TestChainExtensionForgery(t *testing.T) {
	attacker := sha256.Sum256([]byte("attacker cert"))
	k := newFakeKey(t, fakeOptions{pkg: "org.attacker.app", signer: attacker[:]})
	trust := testTrust(t)
	trust.Roots = append(trust.Roots, k.root)
	victimSigner, _ := hex.DecodeString(testSigner)
	forgedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: android.OIDKeyAttestation,
			Value: keyDescription("org.signedcapture.headless", 16, victimSigner, set(integer(2)))}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, k.leaf, &forgedKey.PublicKey, k.key)
	if err != nil {
		t.Fatal(err)
	}
	p := defaultParams()
	p.requireTimestamp, p.requireStartedAfter = false, false
	st := statement(httpresponse.PredicateType, "")
	_, err = mustVerifier(t, p.policy(t), trust).Verify(signBundle(t, st, forgedKey, append([][]byte{der}, k.chain...)))
	if err == nil || !strings.Contains(err.Error(), "only the leaf") {
		t.Fatalf("forged attestation below a real one: %v", err)
	}
}

// Regression (review F2): a time-stamp over a bare signature could be moved to another statement, under a key
// solved from the signature and the new statement, and attested (by a leaked attestation key, say).
func TestTimestampTransplant(t *testing.T) {
	trust := testTrust(t)
	_, victim, err := verifier.ParseHTTPResponse(readCapture(t, "example.http"))
	if err != nil {
		t.Fatal(err)
	}
	sig := victim.DSSEEnvelope.Signatures[0].Sig
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		t.Fatal(err)
	}
	forged := []byte(strings.ReplaceAll(string(victim.DSSEEnvelope.Payload), "example.com", "forged.test"))
	// Q' = r⁻¹(sR − eG) verifies (r, s) on the forged statement.
	c := elliptic.P256()
	n, p := c.Params().N, c.Params().P
	x := new(big.Int).Set(rs.R)
	y2 := new(big.Int).Exp(x, big.NewInt(3), p)
	y2.Sub(y2, new(big.Int).Mul(big.NewInt(3), x)).Add(y2, c.Params().B).Mod(y2, p)
	y := new(big.Int).ModSqrt(y2, p)
	h := sha256.Sum256(verifier.PAE(verifier.InTotoPayload, forged))
	e := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), n)
	sRx, sRy := c.ScalarMult(x, y, rs.S.Bytes())
	eGx, eGy := c.ScalarBaseMult(e.Bytes())
	px, py := c.Add(sRx, sRy, eGx, new(big.Int).Sub(p, eGy))
	qx, qy := c.ScalarMult(px, py, new(big.Int).ModInverse(rs.R, n).Bytes())
	q := &ecdsa.PublicKey{Curve: c, X: qx, Y: qy}
	if !ecdsa.VerifyASN1(q, h[:], sig) {
		t.Fatal("key solving failed")
	}
	victimSigner, _ := hex.DecodeString(testSigner)
	k := newFakeKey(t, fakeOptions{publicKey: q,
		extension: keyDescription("org.signedcapture.headless", 16, victimSigner, set(integer(2)))})
	trust.Roots = append(trust.Roots, k.root)
	b := bundleWith(t, forged, sig, k.chain)
	b.VerificationMaterial.Timestamp = victim.VerificationMaterial.Timestamp
	_, err = mustVerifier(t, defaultParams().policy(t), trust).Verify(b)
	if err == nil || !strings.Contains(err.Error(), "isn't in the time-stamped tree") {
		t.Fatalf("transplanted time-stamp: %v", err)
	}
}

// Unverified inputs fail the statement that lists them, unless its type allows them; they are always reported.
func TestUnverifiedInputs(t *testing.T) {
	s := newDerivedSetup(t, "")
	now := time.Now().Truncate(time.Second)
	inputs := `"inputs":[` + listing(t, s.capture) + `]`
	v := mustVerifier(t, s.params.policy(t), s.trust)
	r, err := v.Verify(s.derived(t, inputs, now))
	if err == nil || r == nil || !r.Passed || r.Accepted || len(r.UnverifiedInputs()) != 1 {
		t.Fatalf("missing input: %v %+v", err, r)
	}
	allow := newDerivedSetup(t, `"allowUnverifiedInputs": true,`)
	v = mustVerifier(t, allow.params.policy(t), allow.trust)
	r, err = v.Verify(allow.derived(t, inputs, now))
	if err != nil || !r.Accepted || r.Inputs[0].Verified || r.Inputs[0].Reason == "" {
		t.Fatalf("allowUnverifiedInputs: %v %+v", err, r.Inputs)
	}
	// An input that fails (here: its predicate type isn't in the policy) is reported, not dropped.
	p := allow.params
	p.noCaptureType = true
	v = mustVerifier(t, p.policy(t), allow.trust)
	r, err = v.Verify(allow.derived(t, inputs, now, allow.capture))
	if err != nil || r.Inputs[0].Result == nil || r.Inputs[0].Result.Passed || r.Inputs[0].Verified {
		t.Fatalf("failed input: %v %+v", err, r.Inputs)
	}
}

// The same statement presented twice is one node; a presented bundle nobody lists is an error.
func TestPresentedBundles(t *testing.T) {
	s := newDerivedSetup(t, "")
	v := mustVerifier(t, s.params.policy(t), s.trust)
	now := time.Now().Truncate(time.Second)
	d := s.derived(t, `"inputs":[`+listing(t, s.capture)+`]`, now, s.capture)
	if r, err := v.Verify(d, s.capture); err != nil || !r.Inputs[0].Verified {
		t.Fatalf("input nested and presented: %v", err)
	}
	other := s.derived(t, "", now)
	if _, err := v.Verify(d, other); err == nil {
		t.Error("unlisted presented bundle accepted")
	}
}

// Signatures must be low-S, strict DER, and without keyid (spec section 2).
func TestSignatureForm(t *testing.T) {
	s := newDerivedSetup(t, "")
	v := mustVerifier(t, s.params.policy(t), s.trust)
	b := s.derived(t, "", time.Time{})
	if _, err := v.Verify(b); err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(b.DSSEEnvelope.Signatures[0].Sig, &rs); err != nil {
		t.Fatal(err)
	}
	high, _ := asn1.Marshal(struct{ R, S *big.Int }{rs.R, new(big.Int).Sub(elliptic.P256().Params().N, rs.S)})
	// A bad signature fails the node; an error in the envelope fails the whole verification, with no result
	// (spec section 0, Errors).
	for name, tc := range map[string]struct {
		edit     func(*verifier.Bundle)
		noResult bool
	}{
		"high-S": {edit: func(b *verifier.Bundle) { b.DSSEEnvelope.Signatures[0].Sig = high }},
		"trailing": {edit: func(b *verifier.Bundle) {
			b.DSSEEnvelope.Signatures[0].Sig = append(slices.Clone(b.DSSEEnvelope.Signatures[0].Sig), 0)
		}},
		"keyid":       {edit: func(b *verifier.Bundle) { b.DSSEEnvelope.Signatures[0].KeyID = new("") }, noResult: true},
		"payloadType": {edit: func(b *verifier.Bundle) { b.DSSEEnvelope.PayloadType = "application/json" }, noResult: true},
	} {
		c := *b
		c.DSSEEnvelope.Signatures = slices.Clone(b.DSSEEnvelope.Signatures)
		tc.edit(&c)
		r, err := v.Verify(&c)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if (r == nil) != tc.noResult {
			t.Errorf("%s: result %v, want none: %v", name, r, tc.noResult)
		}
	}
}

// A time-stamp from a distrusted TSA gives no bound but doesn't fail the statement; from an unknown one, it does.
func TestDistrustedTimestampAuthority(t *testing.T) {
	_, capture, err := verifier.ParseHTTPResponse(readCapture(t, "example.http"))
	if err != nil {
		t.Fatal(err)
	}
	p := defaultParams()
	p.requireTimestamp = false
	p.tsas = "[]"
	p.distrustedTSAs = `["freetsa"]`
	r, err := mustVerifier(t, p.policy(t), testTrust(t)).Verify(capture)
	if err != nil || r.Timestamp != nil || len(r.Notes) != 1 {
		t.Fatalf("distrusted TSA: %v %+v", err, r)
	}
	p.distrustedTSAs = ""
	if _, err := mustVerifier(t, p.policy(t), testTrust(t)).Verify(capture); err == nil {
		t.Error("time-stamp by an untrusted TSA accepted")
	}
}

// An input whose ID can't be computed (here: a profile this verifier doesn't know) has failed; it is not a broken
// set of bundles (spec section 2).
func TestInputOfUnknownProfile(t *testing.T) {
	for _, allow := range []bool{false, true} {
		policy := ""
		if allow {
			policy = `"allowUnverifiedInputs": true,`
		}
		s := newDerivedSetup(t, policy)
		v := mustVerifier(t, s.params.policy(t), s.trust)
		other := *s.capture
		other.VerificationMaterial.Key = verifier.KeyEvidence{Profile: "sgx", Raw: []byte(`{"profile":"sgx"}`)}
		d := s.derived(t, `"inputs":[`+listing(t, s.capture)+`]`, time.Now().Truncate(time.Second), &other)
		r, err := v.Verify(d)
		if r == nil || (err == nil) != allow || r.Inputs[0].Verified || r.Inputs[0].Result == nil {
			t.Fatalf("allowUnverifiedInputs %v: %v %+v", allow, err, r)
		}
		if _, err := v.Verify(s.derived(t, "", time.Time{}), &other); err == nil {
			t.Error("unlisted presented bundle of an unknown profile accepted")
		}
	}
}
