package awsnitro

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFixturePasses(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"indefinite-length map, as AWS's since 2025": func(*fixture) {},
		"definite-length map, as AWS's before":       func(f *fixture) { f.indefinite = false },
		"high s, which the NSM produces":             func(f *fixture) { f.highS = true },
		"null user_data in another order":            func(f *fixture) { f.entries[0], f.entries[8] = f.entries[8], f.entries[0] },
		// The profile doesn't check validity against the verification time: the core spec checks it against the
		// statement's upper bound, which a time-stamp can put long before.
		"verified a year after the chain expired": func(f *fixture) { f.kc.Now = f.kc.Now.AddDate(1, 0, 0) },
		"an entry naming PCR 3 as well":           func(f *fixture) { f.trusted = []string{f.signer(0, 1, 2, 3)} },
		"the second of two entries":               func(f *fixture) { f.trusted = []string{f.otherSigner(), f.signer(0, 1, 2)} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, chainOptions{})
			change(f)
			key, err := f.verify(t)
			if err != nil {
				t.Fatal(err)
			}
			if !key.PublicKey.Equal(f.signingKey.Public()) {
				t.Error("the key isn't the attested one")
			}
			if want := testRoundTime(t); key.Created == nil || !key.Created.Equal(want) {
				t.Errorf("created %v, want the round's time %v", key.Created, want)
			}
			if key.MaxAge != DefaultMaxKeyAgeHours*time.Hour {
				t.Errorf("max age %v", key.MaxAge)
			}
			if !key.ValidUntil.Equal(f.chain.leaf.NotAfter) || !key.ValidFrom.Equal(f.chain.leaf.NotBefore) {
				t.Errorf("valid %v to %v, want the leaf's %v to %v", key.ValidFrom, key.ValidUntil, f.chain.leaf.NotBefore, f.chain.leaf.NotAfter)
			}
			enclave := key.Device.(*Enclave)
			if enclave.ModuleID != testModuleID || enclave.Region != "us-east-1" {
				t.Errorf("enclave %+v", enclave)
			}
			image := key.Signer.(*Image)
			if len(image.PCRs) != 16 || image.PCRs["0"] != hex.EncodeToString(f.pcrs[0]) {
				t.Errorf("image %+v", image)
			}
		})
	}
}

// otherSigner is a valid entry for another image.
func (f *fixture) otherSigner() string {
	return `{"profile":"awsnitro","pcrs":{"0":"` + strings.Repeat("11", 48) + `","1":"` + strings.Repeat("22", 48) +
		`","2":"` + strings.Repeat("33", 48) + `"}}`
}

// Each case breaks one rule of a fixture that passes, and must fail with that rule's error.
func TestRejections(t *testing.T) {
	type rejection struct {
		chain  chainOptions
		change func(*fixture)
		want   error
	}
	cases := map[string]rejection{
		// The key evidence.
		"evidence with an unknown member": {change: func(f *fixture) {
			f.evidence = strings.Replace(string(f.keyEvidence(t)), `{`, `{"x":1,`, 1)
		}, want: ErrEvidence},
		"evidence without keyStartedAfter": {change: func(f *fixture) {
			f.evidence = `{"profile":"awsnitro","attestationDocument":"` + b64(f.document(t)) + `"}`
		}, want: ErrEvidence},
		"evidence without its document": {change: func(f *fixture) {
			f.evidence = `{"profile":"awsnitro","keyStartedAfter":{"drand":{"chain":"` + testRound.Chain + `","round":1,"signature":"00"}}}`
		}, want: ErrEvidence},

		// Step 1: the COSE_Sign1 structure.
		"tagged COSE_Sign1":            {change: func(f *fixture) { f.tag18 = true }, want: ErrCBOR},
		"five items":                   {change: func(f *fixture) { f.extraItem = cborNull }, want: ErrCOSE},
		"protected header for ES256":   {change: func(f *fixture) { f.protected = []byte{0xa1, 0x01, 0x26} }, want: ErrCOSE},
		"non-empty unprotected header": {change: func(f *fixture) { f.unprotected = cborMap(false, entry{cborUint(4), cborBytes([]byte{1})}) }, want: ErrCOSE},
		"a 95-byte signature":          {change: func(f *fixture) { f.signatureLength = 95 }, want: ErrCOSE},
		"a 97-byte signature":          {change: func(f *fixture) { f.signatureLength = 97 }, want: ErrCOSE},
		"bytes after the structure":    {change: func(f *fixture) { f.trailing = []byte{0} }, want: ErrCBOR},

		// Step 2: the CBOR.
		"non-shortest integer": {change: func(f *fixture) { f.set("timestamp", []byte{0x19, 0, 5}) }, want: ErrCBOR},
		"non-shortest length":  {change: func(f *fixture) { f.set("digest", append([]byte{0x78, 6}, "SHA384"...)) }, want: ErrCBOR},
		"chunked byte string": {change: func(f *fixture) {
			f.set("certificate", append(append([]byte{0x5f}, cborBytes(f.chain.leaf.Raw)...), 0xff))
		}, want: ErrCBOR},
		"indefinite-length PCR map":            {change: func(f *fixture) { f.set("pcrs", indefinite(f.pcrMap())) }, want: ErrCBOR},
		"indefinite-length unprotected header": {change: func(f *fixture) { f.unprotected = []byte{0xbf, 0xff} }, want: ErrCBOR},
		"indefinite-length array":              {change: func(f *fixture) { f.set("cabundle", []byte{0x9f, 0x40, 0xff}) }, want: ErrCBOR},
		"duplicate key":                        {change: func(f *fixture) { f.entries = append(f.entries, f.entries[1]) }, want: ErrCBOR},
		"a tag":                                {change: func(f *fixture) { f.set("timestamp", append([]byte{0xc1}, cborUint(1)...)) }, want: ErrCBOR},
		"a float":                              {change: func(f *fixture) { f.set("nonce", []byte{0xf9, 0, 0}) }, want: ErrCBOR},
		"a boolean":                            {change: func(f *fixture) { f.set("nonce", []byte{0xf4}) }, want: ErrCBOR},
		"invalid UTF-8":                        {change: func(f *fixture) { f.set("digest", []byte{0x62, 0xff, 0xfe}) }, want: ErrCBOR},

		// Step 3: the document.
		"no module_id":         {change: func(f *fixture) { f.remove("module_id") }, want: ErrDocument},
		"no nonce":             {change: func(f *fixture) { f.remove("nonce") }, want: ErrDocument},
		"an unknown key":       {change: func(f *fixture) { f.set("extra", cborNull) }, want: ErrDocument},
		"nitrotpm_pcrs":        {change: func(f *fixture) { f.remove("pcrs"); f.set("nitrotpm_pcrs", f.pcrMap()) }, want: ErrDocument},
		"a NitroTPM module_id": {change: func(f *fixture) { f.set("module_id", cborText("i-0123456789abcdef0-tpm0000000000000000")) }, want: ErrDocument},
		"uppercase module_id":  {change: func(f *fixture) { f.set("module_id", cborText(strings.ToUpper(testModuleID))) }, want: ErrDocument},
		"short module_id":      {change: func(f *fixture) { f.set("module_id", cborText("i-0123-enc0123456789abcdef")) }, want: ErrDocument},
		"module_id as bytes":   {change: func(f *fixture) { f.set("module_id", cborBytes([]byte(testModuleID))) }, want: ErrDocument},
		"timestamp 0":          {change: func(f *fixture) { f.set("timestamp", cborUint(0)) }, want: ErrDocument},
		"negative timestamp":   {change: func(f *fixture) { f.set("timestamp", []byte{0x20}) }, want: ErrDocument},
		"digest SHA256":        {change: func(f *fixture) { f.set("digest", cborText("SHA256")) }, want: ErrDocument},
		"PCR 32":               {change: func(f *fixture) { f.pcrs[32] = f.pcrs[0]; f.set("pcrs", pcrMapWith(f, 32)) }, want: ErrDocument},
		"a 32-byte PCR":        {change: func(f *fixture) { f.pcrs[5] = make([]byte, 32); f.set("pcrs", f.pcrMap()) }, want: ErrDocument},
		"no PCRs":              {change: func(f *fixture) { f.set("pcrs", cborMap(false)) }, want: ErrDocument},
		"empty cabundle":       {change: func(f *fixture) { f.set("cabundle", cborArray()) }, want: ErrDocument},
		"cabundle of text":     {change: func(f *fixture) { f.set("cabundle", cborArray(cborText("x"))) }, want: ErrDocument},
		"public_key as text":   {change: func(f *fixture) { f.set("public_key", cborText("x")) }, want: ErrDocument},

		// Step 4: the chain.
		"a root that isn't trusted":        {change: func(f *fixture) { f.roots = []*x509.Certificate{mustAWSRoot(t)} }, want: ErrChain},
		"cabundle in reverse order":        {change: func(f *fixture) { f.set("cabundle", reversedBundle(f)) }, want: ErrChain},
		"a missing intermediate":           {change: func(f *fixture) { f.set("cabundle", bundleOf(f.chain.root, f.chain.regional, f.chain.instance)) }, want: ErrChain},
		"an instance CA that isn't a CA":   {chain: chainOptions{instanceNotCA: true}, want: ErrChain},
		"a path length exceeded":           {chain: chainOptions{zonalPathLen0: true}, want: ErrChain},
		"a leaf that is a CA":              {chain: chainOptions{leafIsCA: true}, want: ErrChain},
		"a P-256 leaf":                     {chain: chainOptions{leafP256: true}, want: ErrChain},
		"a leaf signed with SHA-256":       {chain: chainOptions{leafSHA256: true}, want: ErrChain},
		"a leaf signed by an impostor":     {chain: chainOptions{leafImpostorSigner: true}, want: ErrChain},
		"a leaf with two common names":     {chain: chainOptions{leafExtraCN: true}, want: ErrChain},
		"a leaf named for another enclave": {chain: chainOptions{leafName: "i-0123456789abcdef0-enc0000000000000000.us-east-1.aws"}, want: ErrChain},
		"a leaf named for NitroTPM":        {chain: chainOptions{leafName: "i-0123456789abcdef0-tpm0000000000000000.us-east-1.aws"}, want: ErrChain},
		"a leaf with a malformed region":   {chain: chainOptions{leafName: testModuleID + ".US_EAST.aws"}, want: ErrChain},
		"a leaf that isn't DER":            {change: func(f *fixture) { f.set("certificate", cborBytes([]byte{0x30, 0})) }, want: ErrChain},

		// Step 5: the signature.
		"a signature that doesn't verify": {change: func(f *fixture) {
			doc := f.document(t)
			doc[len(doc)-1] ^= 1 // the signature is the structure's last item
			f.evidence = evidenceWith(f, doc)
		}, want: ErrSignature},

		// Step 6: the key.
		"null public_key":   {change: func(f *fixture) { f.set("public_key", cborNull) }, want: ErrKey},
		"an RSA public_key": {change: func(f *fixture) { f.set("public_key", cborBytes(rsaSPKI(t))) }, want: ErrKey},
		"a P-384 public_key": {change: func(f *fixture) {
			f.set("public_key", cborBytes(mustSPKI(t, f.chain.leafKey.Public())))
		}, want: ErrKey},
		"a compressed point": {change: func(f *fixture) { f.set("public_key", cborBytes(compressedSPKI(t, f))) }, want: ErrKey},
		"null user_data":     {change: func(f *fixture) { f.set("user_data", cborNull) }, want: ErrKey},
		"the bare challenge in user_data": {change: func(f *fixture) {
			f.set("user_data", cborBytes([]byte(KeyChallenge)))
		}, want: ErrKey},
		"user_data for another round": {change: func(f *fixture) {
			other := testRound
			other.Round--
			ud, _ := UserData(other)
			f.set("user_data", cborBytes(ud))
		}, want: ErrKey},
		"a forged round": {change: func(f *fixture) {
			// The next round's signature: a valid point, but not this round's.
			f.evidence = strings.Replace(string(f.keyEvidence(t)), testRound.Signature, nextRoundSignature, 1)
		}, want: ErrKey},
		"a round from a chain the policy doesn't trust": {change: func(f *fixture) { f.kc.Drand = nil }, want: ErrKey},
		"a nonce": {change: func(f *fixture) { f.set("nonce", cborBytes([]byte{1})) }, want: ErrKey},

		// Step 7: debug mode.
		"no PCR1":   {change: func(f *fixture) { delete(f.pcrs, 1); f.set("pcrs", f.pcrMap()) }, want: ErrDebug},
		"zero PCR0": {change: func(f *fixture) { f.pcrs[0] = make([]byte, 48); f.set("pcrs", f.pcrMap()) }, want: ErrDebug},
		"zero PCR2": {change: func(f *fixture) { f.pcrs[2] = make([]byte, 48); f.set("pcrs", f.pcrMap()) }, want: ErrDebug},

		// Step 8: the signer.
		"another image": {change: func(f *fixture) { f.trusted = []string{f.otherSigner()} }, want: ErrSigner},
		"a PCR that differs": {change: func(f *fixture) {
			f.trusted = []string{strings.Replace(f.signer(0, 1, 2, 3), hex.EncodeToString(f.pcrs[3]), strings.Repeat("ab", 48), 1)}
		}, want: ErrSigner},
		"a named PCR missing from the document": {change: func(f *fixture) {
			f.trusted = []string{f.signer(0, 1, 2, 9)}
			delete(f.pcrs, 9)
			f.set("pcrs", f.pcrMap())
		}, want: ErrSigner},

		// The document's time.
		"a document made after its certificate expired": {change: func(f *fixture) {
			f.set("timestamp", cborUint(uint64(f.chain.leaf.NotAfter.Add(time.Second).UnixMilli())))
		}, want: ErrTimestamp},
		"a document made before its certificate": {change: func(f *fixture) {
			f.set("timestamp", cborUint(uint64(f.chain.leaf.NotBefore.Add(-time.Second).UnixMilli())))
		}, want: ErrTimestamp},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, c.chain)
			if c.change != nil {
				c.change(f)
			}
			_, err := f.verify(t)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			t.Log(err)
		})
	}
}

// The payload's map must be the last thing in the payload.
func TestRejectsBytesAfterTheDocument(t *testing.T) {
	for _, indefinite := range []bool{false, true} {
		f := newFixture(t, chainOptions{})
		f.indefinite = indefinite
		if _, err := parseDocument(append(f.payload(), 0)); !errors.Is(err, ErrCBOR) {
			t.Errorf("indefinite %v: got %v, want %v", indefinite, err, ErrCBOR)
		}
		if _, err := parseDocument(f.payload()); err != nil {
			t.Errorf("indefinite %v: %v", indefinite, err)
		}
	}
}

// The key binding is the payload's content: the same whatever else in the structure changes, and computable as
// soon as the structure is readable, before anything is verified.
func TestBinding(t *testing.T) {
	f := newFixture(t, chainOptions{})
	p := New(&Trust{})
	got, err := p.Binding(f.keyEvidence(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.payload()) {
		t.Error("the binding isn't the payload")
	}
	f.highS = true // another valid signature: the same binding
	if again, err := p.Binding(f.keyEvidence(t)); err != nil || !bytes.Equal(again, got) {
		t.Errorf("binding changed with the signature (%v)", err)
	}
	f.set("extra", cborNull) // a document that fails step 3 still has a binding
	if _, err := p.Binding(f.keyEvidence(t)); err != nil {
		t.Errorf("no binding for a structurally sound document: %v", err)
	}
	f.tag18 = true
	if _, err := p.Binding(f.keyEvidence(t)); err == nil {
		t.Error("a binding for an unreadable structure")
	}
}

func TestCheckPolicy(t *testing.T) {
	p := New(&Trust{})
	pcr := func(s string) string { return strings.Repeat(s, 48) }
	good := `{"profile":"awsnitro","pcrs":{"0":"` + pcr("01") + `","1":"` + pcr("02") + `","2":"` + pcr("03") + `"`
	for name, c := range map[string]struct {
		signer, settings string
		ok               bool
	}{
		"defaults":           {signer: good + `}}`, ok: true},
		"PCR 15":             {signer: good + `,"15":"` + pcr("04") + `"}}`, ok: true},
		"maxKeyAgeHours 1":   {signer: good + `}}`, settings: `{"maxKeyAgeHours":1}`, ok: true},
		"PCR 16":             {signer: good + `,"16":"` + pcr("04") + `"}}`},
		"PCR 32":             {signer: good + `,"32":"` + pcr("04") + `"}}`},
		"PCR 01":             {signer: good + `,"01":"` + pcr("04") + `"}}`},
		"PCR -1":             {signer: good + `,"-1":"` + pcr("04") + `"}}`},
		"uppercase hex":      {signer: good + `,"3":"` + pcr("AB") + `"}}`},
		"a short value":      {signer: good + `,"3":"abcd"}}`},
		"no PCR2":            {signer: `{"profile":"awsnitro","pcrs":{"0":"` + pcr("01") + `","1":"` + pcr("02") + `"}}`},
		"a zero PCR1":        {signer: `{"profile":"awsnitro","pcrs":{"0":"` + pcr("01") + `","1":"` + pcr("00") + `","2":"` + pcr("03") + `"}}`},
		"an unknown member":  {signer: good + `},"x":1}`},
		"maxKeyAgeHours 0":   {signer: good + `}}`, settings: `{"maxKeyAgeHours":0}`},
		"an unknown setting": {signer: good + `}}`, settings: `{"maxKeyAge":1}`},
	} {
		t.Run(name, func(t *testing.T) {
			err := p.CheckPolicy([]jsontext.Value{jsontext.Value(c.signer)}, jsontext.Value(c.settings))
			if (err == nil) != c.ok {
				t.Fatalf("got %v, want ok %v", err, c.ok)
			}
		})
	}
	if err := p.CheckPolicy(nil, nil); err != nil {
		t.Errorf("no entries and no settings: %v", err)
	}
}

func mustAWSRoot(t testing.TB) *x509.Certificate {
	t.Helper()
	r, err := AWSRoot()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAWSRoot(t *testing.T) {
	r := mustAWSRoot(t)
	if r.Subject.CommonName != "aws.nitro-enclaves" || r.NotAfter.Year() != 2049 {
		t.Errorf("unexpected root %v until %v", r.Subject, r.NotAfter)
	}
	tr, err := DefaultTrust()
	if err != nil || len(tr.Roots) != 1 || !tr.Roots[0].Equal(r) {
		t.Errorf("default trust: %v", err)
	}
}
