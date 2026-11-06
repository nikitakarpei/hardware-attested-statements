package awsnitro

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"math/big"
	"testing"
	"time"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
)

// A test root and documents made like AWS's (spec: profiles/awsnitro.md), so each rule can be broken alone: a
// fixture passes every step, and each negative test changes one thing.

// testRound is a real drand quicknet round (from ../../testdata/capture), the keys' startedAfter.
var testRound = verifier.DrandRound{
	Chain:     "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
	Round:     33667957,
	Signature: "ace44ad88121ed26163c00acaa4c89522295c4fb066a8e9712138c63644e43cadac17e3f29aa8056f8f4ef5449d6e16e",
}

// nextRoundSignature is round 33667958's signature.
const nextRoundSignature = "af4a49c0a3dacedbe3790d4ba7a8a77ebbd58ce5d69d712ec15299d12db0d6d57f3ff8ee1f3e4887ea8b73ffb755560f"

const testModuleID = "i-0123456789abcdef0-enc0123456789abcdef"

func quicknet(t testing.TB) verifier.DrandChain {
	t.Helper()
	c, err := verifier.DrandQuicknet()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testRoundTime is when testRound became known; documents are made an hour later.
func testRoundTime(t testing.TB) time.Time { return quicknet(t).RoundTime(testRound.Round) }

// chainOptions break one property of a test chain.
type chainOptions struct {
	leafLifetime       time.Duration // default 3 hours, as AWS's
	leafName           string        // default testModuleID + ".us-east-1.aws"
	leafExtraCN        bool
	leafIsCA           bool
	leafP256           bool // a P-256 key instead of P-384
	leafSHA256         bool // signed with SHA-256 instead of SHA-384
	leafImpostorSigner bool // signed by another key, under the instance CA's name
	instanceNotCA      bool
	zonalPathLen0      bool // the zonal CA allows no CA below it, but the instance CA is
}

// testChain is a root, regional, zonal and instance CAs, and a signing certificate, like AWS's.
type testChain struct {
	root, regional, zonal, instance, leaf *x509.Certificate
	leafKey                               *ecdsa.PrivateKey
}

func newTestChain(t testing.TB, start time.Time, o chainOptions) *testChain {
	t.Helper()
	newKey := func(curve elliptic.Curve) *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	serial := int64(1)
	issue := func(tmpl *x509.Certificate, parent *x509.Certificate, parentKey, key *ecdsa.PrivateKey) *x509.Certificate {
		serial++
		tmpl.SerialNumber = big.NewInt(serial)
		if tmpl.SignatureAlgorithm == 0 {
			tmpl.SignatureAlgorithm = x509.ECDSAWithSHA384
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	name := func(cn string) pkix.Name {
		return pkix.Name{CommonName: cn, OrganizationalUnit: []string{"AWS"}, Organization: []string{"Amazon"}, Country: []string{"US"}}
	}
	ca := func(cn string, lifetime time.Duration, pathLen int, pathLenZero bool) *x509.Certificate {
		return &x509.Certificate{Subject: name(cn), NotBefore: start.Add(-time.Hour), NotAfter: start.Add(lifetime),
			IsCA: true, BasicConstraintsValid: true, MaxPathLen: pathLen, MaxPathLenZero: pathLenZero,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	}
	rootKey, regionalKey, zonalKey, instanceKey := newKey(elliptic.P384()), newKey(elliptic.P384()), newKey(elliptic.P384()), newKey(elliptic.P384())
	c := &testChain{}
	c.root = issue(ca("test.nitro-enclaves", 30*365*24*time.Hour, -1, false), nil, nil, rootKey)
	c.regional = issue(ca("0123456789abcdef.us-east-1.aws.nitro-enclaves", 20*24*time.Hour, 2, false), c.root, rootKey, regionalKey)
	zonalPathLen := 1
	c.zonal = issue(ca("0123456789abcdef.zonal.us-east-1.aws.nitro-enclaves", 5*24*time.Hour, zonalPathLen, false), c.regional, regionalKey, zonalKey)
	if o.zonalPathLen0 {
		c.zonal = issue(ca("0123456789abcdef.zonal.us-east-1.aws.nitro-enclaves", 5*24*time.Hour, 0, true), c.regional, regionalKey, zonalKey)
	}
	instance := ca("i-0123456789abcdef0.us-east-1.aws.nitro-enclaves", 24*time.Hour, 0, true)
	if o.instanceNotCA {
		instance.IsCA, instance.MaxPathLen, instance.MaxPathLenZero = false, -1, false
	}
	c.instance = issue(instance, c.zonal, zonalKey, instanceKey)

	lifetime := o.leafLifetime
	if lifetime == 0 {
		lifetime = 3 * time.Hour
	}
	leafName := o.leafName
	if leafName == "" {
		leafName = testModuleID + ".us-east-1.aws"
	}
	leaf := &x509.Certificate{Subject: name(leafName), NotBefore: start.Add(-time.Minute), NotAfter: start.Add(lifetime),
		BasicConstraintsValid: true, IsCA: o.leafIsCA, KeyUsage: x509.KeyUsageDigitalSignature}
	if o.leafExtraCN {
		rdns := leaf.Subject.ToRDNSequence()
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: oidCommonName, Value: leafName}})
		raw, err := asn1.Marshal(rdns)
		if err != nil {
			t.Fatal(err)
		}
		leaf.RawSubject = raw
	}
	if o.leafSHA256 {
		leaf.SignatureAlgorithm = x509.ECDSAWithSHA256
	}
	c.leafKey = newKey(elliptic.P384())
	if o.leafP256 {
		c.leafKey = newKey(elliptic.P256())
	}
	parent, parentKey := c.instance, instanceKey
	if o.leafImpostorSigner {
		impostorKey := newKey(elliptic.P384())
		parent, parentKey = issue(ca("i-0123456789abcdef0.us-east-1.aws.nitro-enclaves", 24*time.Hour, 0, true), c.zonal, zonalKey, impostorKey), impostorKey
	}
	c.leaf = issue(leaf, parent, parentKey, c.leafKey)
	return c
}

// CBOR encoding, for building documents.

func cborUint(n uint64) []byte  { return appendHead(nil, 0, n) }
func cborBytes(b []byte) []byte { return append(appendHead(nil, 2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(appendHead(nil, 3, uint64(len(s))), s...) }
func cborArray(items ...[]byte) []byte {
	b := appendHead(nil, 4, uint64(len(items)))
	for _, it := range items {
		b = append(b, it...)
	}
	return b
}

var cborNull = []byte{0xf6}

// entry is a map entry, encoded.
type entry struct{ key, value []byte }

func cborMap(indefinite bool, entries ...entry) []byte {
	b := appendHead(nil, 5, uint64(len(entries)))
	if indefinite {
		b = []byte{0xbf}
	}
	for _, e := range entries {
		b = append(append(b, e.key...), e.value...)
	}
	if indefinite {
		b = append(b, 0xff)
	}
	return b
}

// fixture is a key's evidence and what checking it needs, built so that it passes every step.
type fixture struct {
	chain      *testChain
	signingKey *ecdsa.PrivateKey // the attested P-256 key
	pcrs       map[int][]byte
	// The document's entries, in order, and whether its map has indefinite length (as AWS's since 2025).
	entries    []entry
	indefinite bool
	// COSE structure: the protected header, unprotected header and signature, as encoded; nil for the defaults.
	protected, unprotected []byte
	tag18, highS           bool
	signatureLength        int // 0: 96
	extraItem, trailing    []byte
	// evidence overrides the key evidence JSON, if set.
	evidence string
	trusted  []string // policy entries, as JSON
	roots    []*x509.Certificate
	kc       verifier.KeyContext
}

func newFixture(t testing.TB, o chainOptions) *fixture {
	t.Helper()
	made := testRoundTime(t).Add(time.Hour)
	f := &fixture{chain: newTestChain(t, made, o), indefinite: true, pcrs: map[int][]byte{}}
	var err error
	if f.signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	for i := range 16 {
		f.pcrs[i] = make([]byte, 48)
	}
	for _, i := range []int{0, 1, 2, 3, 4, 8} {
		v := sha512.Sum384([]byte{byte(i)})
		f.pcrs[i] = v[:]
	}
	spki, err := x509.MarshalPKIXPublicKey(f.signingKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	userData, err := UserData(testRound)
	if err != nil {
		t.Fatal(err)
	}
	f.entries = []entry{
		{cborText("module_id"), cborText(testModuleID)},
		{cborText("digest"), cborText("SHA384")},
		{cborText("timestamp"), cborUint(uint64(made.UnixMilli()))},
		{cborText("pcrs"), f.pcrMap()},
		{cborText("certificate"), cborBytes(f.chain.leaf.Raw)},
		{cborText("cabundle"), cborArray(cborBytes(f.chain.root.Raw), cborBytes(f.chain.regional.Raw),
			cborBytes(f.chain.zonal.Raw), cborBytes(f.chain.instance.Raw))},
		{cborText("public_key"), cborBytes(spki)},
		{cborText("user_data"), cborBytes(userData)},
		{cborText("nonce"), cborNull},
	}
	f.trusted = []string{f.signer(0, 1, 2)}
	f.roots = []*x509.Certificate{f.chain.root}
	f.kc = verifier.KeyContext{Now: made, Drand: map[string]verifier.DrandChain{testRound.Chain: quicknet(t)}}
	return f
}

func (f *fixture) pcrMap() []byte {
	var es []entry
	for i := range 16 {
		if v, ok := f.pcrs[i]; ok {
			es = append(es, entry{cborUint(uint64(i)), cborBytes(v)})
		}
	}
	return cborMap(false, es...)
}

// signer is a policy entry naming these PCRs, as the fixture has them.
func (f *fixture) signer(pcrs ...int) string {
	m := map[string]string{}
	for _, i := range pcrs {
		m[big.NewInt(int64(i)).String()] = hex.EncodeToString(f.pcrs[i])
	}
	b, _ := json.Marshal(map[string]any{"profile": Name, "pcrs": m})
	return string(b)
}

// set replaces a document entry's value (or adds the entry); remove drops it.
func (f *fixture) set(key string, value []byte) {
	for i, e := range f.entries {
		if string(e.key) == string(cborText(key)) {
			f.entries[i].value = value
			return
		}
	}
	f.entries = append(f.entries, entry{cborText(key), value})
}

func (f *fixture) remove(key string) {
	for i, e := range f.entries {
		if string(e.key) == string(cborText(key)) {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			return
		}
	}
}

func (f *fixture) payload() []byte { return cborMap(f.indefinite, f.entries...) }

// document is the COSE_Sign1 structure, signed with the chain's signing key.
func (f *fixture) document(t testing.TB) []byte {
	t.Helper()
	protected, unprotected := protectedES384, cborMap(false)
	if f.protected != nil {
		protected = f.protected
	}
	if f.unprotected != nil {
		unprotected = f.unprotected
	}
	payload := f.payload()
	digest := sha512.Sum384(sigStructure(protected, payload))
	r, s, err := ecdsa.Sign(rand.Reader, f.chain.leafKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	n := f.chain.leafKey.Curve.Params().N
	if high := s.Cmp(new(big.Int).Rsh(n, 1)) > 0; high != f.highS {
		s.Sub(n, s)
	}
	const size = 48 // a P-256 signature too, to reach the chain check
	sig := append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	if f.signatureLength != 0 {
		sig = append(sig, make([]byte, 100)...)[:f.signatureLength]
	}
	items := [][]byte{cborBytes(protected), unprotected, cborBytes(payload), cborBytes(sig)}
	if f.extraItem != nil {
		items = append(items, f.extraItem)
	}
	b := cborArray(items...)
	if f.tag18 {
		b = append([]byte{0xd2}, b...)
	}
	return append(b, f.trailing...)
}

// keyEvidence is the bundle's key object.
func (f *fixture) keyEvidence(t testing.TB) jsontext.Value {
	t.Helper()
	if f.evidence != "" {
		return jsontext.Value(f.evidence)
	}
	b, err := json.Marshal(map[string]any{"profile": Name, "attestationDocument": base64.StdEncoding.EncodeToString(f.document(t)),
		"keyStartedAfter": map[string]any{"drand": testRound}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verify checks the fixture's key evidence as the profile does.
func (f *fixture) verify(t testing.TB) (*verifier.Key, error) {
	t.Helper()
	var trusted []jsontext.Value
	for _, s := range f.trusted {
		trusted = append(trusted, jsontext.Value(s))
	}
	return New(&Trust{Roots: f.roots}).VerifyKey(f.keyEvidence(t), trusted, nil, f.kc)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// evidenceWith is the fixture's key evidence with another attestation document.
func evidenceWith(f *fixture, doc []byte) string {
	b, _ := json.Marshal(map[string]any{"profile": Name, "attestationDocument": b64(doc),
		"keyStartedAfter": map[string]any{"drand": testRound}})
	return string(b)
}

// pcrMapWith encodes the fixture's PCRs 0–15 and also index.
func pcrMapWith(f *fixture, index int) []byte {
	var es []entry
	for i := range 16 {
		if v, ok := f.pcrs[i]; ok {
			es = append(es, entry{cborUint(uint64(i)), cborBytes(v)})
		}
	}
	return cborMap(false, append(es, entry{cborUint(uint64(index)), cborBytes(f.pcrs[index])})...)
}

func bundleOf(certs ...*x509.Certificate) []byte {
	var items [][]byte
	for _, c := range certs {
		items = append(items, cborBytes(c.Raw))
	}
	return cborArray(items...)
}

func reversedBundle(f *fixture) []byte {
	return bundleOf(f.chain.instance, f.chain.zonal, f.chain.regional, f.chain.root)
}

func mustSPKI(t testing.TB, pub any) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rsaSPKI(t testing.TB) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return mustSPKI(t, &k.PublicKey)
}

// compressedSPKI is the fixture's key as a SubjectPublicKeyInfo with a compressed point.
func compressedSPKI(t testing.TB, f *fixture) []byte {
	t.Helper()
	spki := mustSPKI(t, f.signingKey.Public())
	compressed := elliptic.MarshalCompressed(elliptic.P256(), f.signingKey.X, f.signingKey.Y)
	// The BIT STRING shrinks by 32 bytes, and so do the lengths of it and of the outer SEQUENCE.
	out := append(append([]byte{}, spki[:len(spki)-65]...), compressed...)
	out[1] -= 32
	out[len(out)-len(compressed)-2] -= 32
	return out
}

// indefinite re-encodes a definite-length map of fewer than 24 entries with indefinite length.
func indefinite(m []byte) []byte { return append(append([]byte{0xbf}, m[1:]...), 0xff) }
