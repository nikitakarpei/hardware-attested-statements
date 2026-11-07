package verifier_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/predicates/httpresponse"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/profiles/android"
)

const testSigner = "d66a722561948c23fca5f90a758008dc4b2a11100db466e75e58d4f3ee4ffb99"

// policyParams build a test policy for the test captures' predicate type (and, in chain tests, more).
type policyParams struct {
	signingCertificate  string
	versionCodes        string // JSON array, or "" for any
	requireTimestamp    bool
	requireStartedAfter bool
	androidSettings     string // JSON object, or "" for defaults
	extraTypes          string // more "type": {…} members
	noCaptureType       bool
	tsas, drand         string // JSON arrays, or "" for ["freetsa"] and ["quicknet"]
	distrustedTSAs      string // JSON array, or ""
}

func defaultParams() policyParams {
	return policyParams{signingCertificate: testSigner, versionCodes: "[1]", requireTimestamp: true, requireStartedAfter: true}
}

func (p policyParams) policy(t *testing.T) *verifier.Policy {
	t.Helper()
	var types []string
	if !p.noCaptureType {
		versions := ""
		if p.versionCodes != "" {
			versions = `, "versionCodes": ` + p.versionCodes
		}
		types = append(types, fmt.Sprintf(`%q: { "trustedSigners": [{ "profile": "android", "package": %q,
		  "signingCertificates": [%q]%s }], "requireTimestamp": %v, "requireStartedAfter": %v }`,
			httpresponse.PredicateType, capturePackage, p.signingCertificate, versions, p.requireTimestamp, p.requireStartedAfter))
	}
	if p.extraTypes != "" {
		types = append(types, p.extraTypes)
	}
	profiles := "{}"
	if p.androidSettings != "" {
		profiles = `{ "android": ` + p.androidSettings + ` }`
	}
	tsas, drand := p.tsas, p.drand
	if tsas == "" {
		tsas = `["freetsa"]`
	}
	if drand == "" {
		drand = `["quicknet"]`
	}
	distrusted := ""
	if p.distrustedTSAs != "" {
		distrusted = ` "distrustedTimestampAuthorities": ` + p.distrustedTSAs + `,`
	}
	pol, err := verifier.ParsePolicy([]byte(`{ "policy": "hardware-attested-statement/policy/v0.1",
	  "timestampAuthorities": ` + tsas + `, "drandChains": ` + drand + `,` + distrusted + `
	  "predicateTypes": {` + strings.Join(types, ",") + `}, "profiles": ` + profiles + ` }`))
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func testTrust(t *testing.T) *android.Trust {
	t.Helper()
	trust, err := android.NewTrust(read(t, "testdata/trust/status.json"), read(t, "testdata/trust/attestation.json"),
		read(t, "testdata/trust/attestation.json.sig"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(read(t, "testdata/capture/fake_root.pem"))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	trust.Roots = append(trust.Roots, root)
	return trust
}

func newVerifier(t *testing.T, policy *verifier.Policy, trust *android.Trust) (*verifier.Verifier, error) {
	t.Helper()
	return verifier.New(policy, android.New(trust))
}

func mustVerifier(t *testing.T, policy *verifier.Policy, trust *android.Trust) *verifier.Verifier {
	t.Helper()
	v, err := newVerifier(t, policy, trust)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readCapture(t *testing.T, name string) []byte { return read(t, "testdata/capture/"+name) }

// verifyCapture runs what `attested-verify http` does.
func verifyCapture(v *verifier.Verifier, raw []byte) (*verifier.Result, error) {
	resp, b, err := verifier.ParseHTTPResponse(raw)
	if err != nil {
		return nil, err
	}
	r, err := v.Verify(b)
	if err != nil {
		return nil, err
	}
	if err := verifier.CheckHTTPBody(r.Statement, resp); err != nil {
		return nil, err
	}
	p, err := httpresponse.Parse(r.Statement)
	if err != nil {
		return nil, err
	}
	return r, httpresponse.CheckResponse(r.Statement, p, resp)
}

func TestCapturesVerify(t *testing.T) {
	v := mustVerifier(t, defaultParams().policy(t), testTrust(t))
	names := []string{"example.http", "redirect.http"}
	for i := 1; i <= 8; i++ {
		names = append(names, fmt.Sprintf("parallel-%d.http", i))
	}
	sizes := map[uint64]bool{}
	for _, name := range names {
		r, err := verifyCapture(v, readCapture(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// From the drand round's time to the time-stamp: the fetch, plus up to two rounds (3 s each).
		if w := r.NotAfter.Sub(r.NotBefore); r.NotBefore.IsZero() || w <= 0 || w > 30*time.Second {
			t.Errorf("%s: window %v – %v", name, r.NotBefore, r.NotAfter)
		}
		dev, app := r.Key.Device.(*android.Device), r.Key.Signer.(*android.App)
		if dev.KeyStorage != android.StrongBox || dev.Provisioning != android.RemotelyProvisioned || dev.OS != "grapheneos" {
			t.Errorf("%s: device %+v", name, dev)
		}
		if app.Package != capturePackage || app.VersionCode != 1 {
			t.Errorf("%s: app %+v", name, app)
		}
		_, b, _ := verifier.ParseHTTPResponse(readCapture(t, name))
		sizes[b.VerificationMaterial.Timestamp.Tree.Size] = true
	}
	// The parallel captures share time-stamps, so trees with several leaves were checked too.
	multi := false
	for s := range sizes {
		multi = multi || s > 1
	}
	if !multi {
		t.Errorf("no capture shared its time-stamp (tree sizes %v)", sizes)
	}
	t.Logf("tree sizes seen: %v", sizes)
}

// Each change to a capture, or to what the verifier trusts, must make verification fail.
func TestCaptureTampering(t *testing.T) {
	example, redirect := readCapture(t, "example.http"), readCapture(t, "redirect.http")
	var shared []byte // a capture whose time-stamp tree has more than one leaf
	for i := 1; i <= 8 && shared == nil; i++ {
		raw := readCapture(t, fmt.Sprintf("parallel-%d.http", i))
		if _, b, _ := verifier.ParseHTTPResponse(raw); b.VerificationMaterial.Timestamp.Tree.Size > 1 {
			shared = raw
		}
	}
	if shared == nil {
		t.Fatal("no capture with a shared time-stamp")
	}
	header := func(raw []byte, name string) string {
		for _, l := range strings.Split(string(raw[:bytes.Index(raw, []byte("\r\n\r\n"))]), "\r\n") {
			if strings.HasPrefix(l, name+": ") {
				return l
			}
		}
		t.Fatalf("no %s header", name)
		return ""
	}
	replace := func(raw []byte, old, new string) []byte {
		if !bytes.Contains(raw, []byte(old)) {
			t.Fatalf("%q not found", old)
		}
		return bytes.Replace(raw, []byte(old), []byte(new), 1)
	}
	withoutHeader := func(raw []byte, name string) []byte { return replace(raw, header(raw, name)+"\r\n", "") }
	// Flip one bit in the middle of a header's first byte sequence.
	flip := func(raw []byte, name string) []byte {
		line := header(raw, name)
		i := len(name) + 2 // after "Name: "
		start := i + strings.Index(line[i:], ":") + 1
		end := start + strings.Index(line[start:], ":")
		d, err := base64.StdEncoding.DecodeString(line[start:end])
		if err != nil {
			t.Fatal(err)
		}
		d[len(d)/2] ^= 1
		return replace(raw, line, line[:start]+base64.StdEncoding.EncodeToString(d)+line[end:])
	}
	body := bytes.Index(example, []byte("\r\n\r\n")) + 4
	params := func(edit func(p *policyParams)) policyParams {
		p := defaultParams()
		edit(&p)
		return p
	}

	cases := map[string]struct {
		raw      []byte
		params   policyParams
		trust    func(*android.Trust)
		verifier func(*verifier.Verifier)
	}{
		"body changed":                 {raw: append(append([]byte{}, example[:body]...), append([]byte("X"), example[body+1:]...)...)},
		"status changed":               {raw: replace(example, "HTTP/1.1 200 OK", "HTTP/1.1 404 OK")},
		"header changed":               {raw: replace(example, "Content-Type: text/html", "Content-Type: text/plain")},
		"header added":                 {raw: replace(example, "\r\n\r\n", "\r\nX-Extra: 1\r\n\r\n")},
		"attested header twice":        {raw: replace(example, "\r\n\r\n", "\r\n"+header(example, "Attested-Timestamp")+"\r\n\r\n")},
		"statement changed":            {raw: flip(example, "Attested-Statement")},
		"signature changed":            {raw: flip(example, "Attested-Signature")},
		"key evidence changed":         {raw: flip(example, "Attested-Key")},
		"time-stamp changed":           {raw: flip(example, "Attested-Timestamp")},
		"tree path changed":            {raw: flip(shared, "Attested-Timestamp-Tree")},
		"tree index changed":           {raw: replace(shared, "index=", "index=1")},
		"tree size changed":            {raw: replace(shared, "size=", "size=1")},
		"tree path emptied":            {raw: replace(shared, header(shared, "Attested-Timestamp-Tree"), strings.SplitN(header(shared, "Attested-Timestamp-Tree"), "path=", 2)[0]+"path=()")},
		"time-stamp without its tree":  {raw: withoutHeader(example, "Attested-Timestamp")},
		"tree without its time-stamp":  {raw: withoutHeader(example, "Attested-Timestamp-Tree")},
		"time-stamp removed":           {raw: withoutHeader(withoutHeader(example, "Attested-Timestamp"), "Attested-Timestamp-Tree")},
		"no version header":            {raw: withoutHeader(example, "Attested-Version")},
		"other version":                {raw: replace(example, "Attested-Version: v0.1", "Attested-Version: v0.2")},
		"two byte sequences":           {raw: replace(example, header(example, "Attested-Signature"), header(example, "Attested-Signature")+", :AA==:")},
		"URL-safe base64":              {raw: replace(example, header(example, "Attested-Signature"), strings.NewReplacer("+", "-", "/", "_").Replace(header(example, "Attested-Signature")))},
		"statement from other capture": {raw: replace(example, header(example, "Attested-Statement"), header(redirect, "Attested-Statement"))},
		"signer not trusted":           {raw: example, params: params(func(p *policyParams) { p.signingCertificate = strings.Repeat("ab", 32) })},
		"version not accepted":         {raw: example, params: params(func(p *policyParams) { p.versionCodes = "[17]" })},
		"predicate type not in policy": {raw: example, params: params(func(p *policyParams) {
			p.noCaptureType = true
			p.extraTypes = `"urn:x": {"trustedSigners": [{"profile": "android", "package": "x", "signingCertificates": ["` + testSigner + `"]}]}`
		})},
		"patch level too old": {raw: example, params: params(func(p *policyParams) { p.androidSettings = `{"minOsPatchLevel": 202611}` })},
		"Android too old":     {raw: example, params: params(func(p *policyParams) { p.androidSettings = `{"minOsVersion": 170000}` })},
		"stock OS only":       {raw: example, params: params(func(p *policyParams) { p.androidSettings = `{"os": {"stock": true, "bootKeyLists": []}}` })},
		"boot key on no list": {raw: example, trust: func(tr *android.Trust) {
			tr.BootKeyLists["grapheneos"] = &android.BootKeyList{Keys: map[string]bool{}, Produced: time.Now()}
		}},
		"GrapheneOS list unavailable": {raw: example, trust: func(tr *android.Trust) {
			tr.BootKeyLists["grapheneos"] = &android.BootKeyList{Err: errors.New("not given")}
		}},
		"GrapheneOS list too old": {raw: example, trust: func(tr *android.Trust) {
			tr.BootKeyLists["grapheneos"].Produced = time.Now().Add(-49 * time.Hour)
		}},
		"Content-Type twice":          {raw: replace(example, "\r\n\r\n", "\r\nContent-Type: text/plain\r\n\r\n")},
		"content-type changed":        {raw: replace(example, "Content-Type: text/html", "content-type: text/plain")},
		"bare LF in a header":         {raw: replace(example, "\r\n\r\n", "\r\nX-A: 1\nX-B: 2\r\n\r\n")},
		"Transfer-Encoding":           {raw: replace(example, "\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n")},
		"body longer than its length": {raw: append(append([]byte{}, example...), "<script>"...)},
		"space before colon":          {raw: replace(example, "Content-Type:", "Content-Type :")},
		"root not trusted":            {raw: example, trust: func(tr *android.Trust) { tr.Roots = tr.Roots[:2] }},
		"no TSA trusted":              {raw: example, params: params(func(p *policyParams) { p.tsas = "[]" })},
		"drand chain not trusted":     {raw: example, params: params(func(p *policyParams) { p.drand = "[]" })},
		"lists too old":               {raw: example, trust: func(tr *android.Trust) { tr.RevocationProduced = time.Now().Add(-49 * time.Hour) }},
		"lists too old for policy": {raw: example, params: params(func(p *policyParams) { p.androidSettings = `{"maxListAgeHours": 1}` }),
			trust: func(tr *android.Trust) { tr.RevocationProduced = time.Now().Add(-2 * time.Hour) }},
		"vendor patch too old": {raw: example, params: params(func(p *policyParams) { p.androidSettings = `{"minVendorPatchLevel": 202611}` })},
		"key too old":          {raw: example, params: params(func(p *policyParams) { p.androidSettings = `{"maxKeyAgeHours": 1}` })},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			trust := testTrust(t)
			if c.trust != nil {
				c.trust(trust)
			}
			p := c.params
			if p.signingCertificate == "" {
				p = defaultParams()
			}
			v, err := newVerifier(t, p.policy(t), trust)
			if err == nil {
				if c.verifier != nil {
					c.verifier(v)
				}
				_, err = verifyCapture(v, c.raw)
			}
			if err == nil {
				t.Fatal("verified, but shouldn't")
			}
			t.Log(err)
		})
	}
	// And the unchanged capture passes under a GrapheneOS-only policy (the fake device runs GrapheneOS).
	p := params(func(p *policyParams) { p.androidSettings = `{"os": {"stock": false, "bootKeyLists": ["grapheneos"]}}` })
	if _, err := verifyCapture(mustVerifier(t, p.policy(t), testTrust(t)), example); err != nil {
		t.Errorf("GrapheneOS-only policy rejected a GrapheneOS device: %v", err)
	}
}

// A revoked certificate anywhere in the chain fails verification.
func TestRevokedCertificate(t *testing.T) {
	_, b, err := verifier.ParseHTTPResponse(readCapture(t, "example.http"))
	if err != nil {
		t.Fatal(err)
	}
	var ev android.Evidence
	if err := verifier.UnmarshalStrict(b.VerificationMaterial.Key.Raw, &ev); err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(ev.Certificates[1])
	if err != nil {
		t.Fatal(err)
	}
	trust := testTrust(t)
	trust.Revoked = map[string]string{c.SerialNumber.Text(16): "REVOKED"}
	if _, err := mustVerifier(t, defaultParams().policy(t), trust).Verify(b); err == nil || !strings.Contains(err.Error(), "REVOKED") {
		t.Fatalf("revoked certificate accepted: %v", err)
	}
}

// Without a time-stamp, a capture only gets its lower bound, from drand; its evidence is checked at verification time.
func TestWithoutTimestampOnlyLowerBound(t *testing.T) {
	raw := readCapture(t, "example.http")
	for _, name := range []string{"Attested-Timestamp: ", "Attested-Timestamp-Tree: "} {
		i := bytes.Index(raw, []byte(name))
		j := i + bytes.Index(raw[i:], []byte("\r\n")) + 2
		raw = append(append([]byte{}, raw[:i]...), raw[j:]...)
	}
	p := defaultParams()
	p.requireTimestamp = false
	v := mustVerifier(t, p.policy(t), testTrust(t))
	now := time.Now()
	v.Now = func() time.Time { return now }
	r, err := verifyCapture(v, raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.Timestamp != nil || r.StartedAfter == nil || !r.NotBefore.Equal(*r.StartedAfter) || !r.NotAfter.IsZero() {
		t.Fatalf("bounds %v – %v", r.NotBefore, r.NotAfter)
	}
}

func TestBundleJSONRoundTrip(t *testing.T) {
	_, b, err := verifier.ParseHTTPResponse(readCapture(t, "example.http"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := verifier.ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mustVerifier(t, defaultParams().policy(t), testTrust(t)).Verify(b2); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string][2]string{
		"duplicate member":     {`"mediaType"`, `"mediaType": "x", "mediaType"`},
		"unknown member":       {`"mediaType"`, `"x": 1, "mediaType"`},
		"case-folded name":     {`"mediaType"`, `"MEDIATYPE"`},
		"unpadded base64":      {`=="`, `"`},
		"keyid":                {`"sig"`, `"keyid": "k", "sig"`},
		"unknown key member":   {`"profile"`, `"x": 1, "profile"`},
		"tree size over 2^53":  {`"size":`, `"size": 9007199254740992, "x":`},
		"unknown root member":  {`{"mediaType"`, `{"inputs": [], "mediaType"`},
		"nested unknown in vm": {`"key"`, `"timestamps": 1, "key"`},
	} {
		changed := bytes.Replace(raw, []byte(edit[0]), []byte(edit[1]), 1)
		if bytes.Equal(changed, raw) {
			t.Fatalf("%s: nothing changed", name)
		}
		b, err := verifier.ParseBundle(changed)
		if err == nil {
			_, err = mustVerifier(t, defaultParams().policy(t), testTrust(t)).Verify(b)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Statements ignore unknown members, as in-toto requires, but not case variants of defined ones, which some
// parsers would read as those members (review F3, G7, H10).
func TestStatementNames(t *testing.T) {
	st := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"` + strings.Repeat("00", 32) +
		`"}}],"predicateType":"urn:x","extra":1,"predicate":{"other":{"Inputs":1}}}`
	s, err := verifier.ParseStatement([]byte(st))
	if err != nil || s.PredicateType != "urn:x" {
		t.Fatalf("%v %+v", err, s)
	}
	for name, changed := range map[string]string{
		"case variant":          strings.Replace(st, `"extra":1`, `"PREDICATETYPE":"urn:y"`, 1),
		"long s (U+017F)":       strings.Replace(st, `"extra":1`, `"ſubject":[]`, 1),
		"case variant in input": strings.Replace(st, `"other"`, `"Inputs":[],"other"`, 1),
		"null member":           strings.Replace(st, `"extra":1`, `"predicate":null`, 1),
		"duplicate member":      strings.Replace(st, `"extra":1`, `"predicateType":"urn:z"`, 1),
		"case variant digest":   strings.Replace(st, `"sha256"`, `"SHA256":"x","sha256"`, 1),
	} {
		if _, err := verifier.ParseStatement([]byte(changed)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPolicyMistakesAreErrors(t *testing.T) {
	const head = `{"policy": "hardware-attested-statement/policy/v0.1", "timestampAuthorities": ["freetsa"], "drandChains": ["quicknet"], `
	signer := `{"profile": "android", "package": "x", "signingCertificates": ["` + testSigner + `"]}`
	for name, raw := range map[string]string{
		"unknown field":            head + `"predicateTypes": {}, "profile": {}}`,
		"case-folded field":        head + `"predicateTypes": {}, "Profiles": {}}`,
		"no timestampAuthorities":  `{"policy": "hardware-attested-statement/policy/v0.1", "drandChains": [], "predicateTypes": {}}`,
		"no drandChains":           `{"policy": "hardware-attested-statement/policy/v0.1", "timestampAuthorities": [], "predicateTypes": {}}`,
		"unknown TSA":              `{"policy": "hardware-attested-statement/policy/v0.1", "timestampAuthorities": ["digicert"], "drandChains": [], "predicateTypes": {}}`,
		"incomplete TSA":           `{"policy": "hardware-attested-statement/policy/v0.1", "timestampAuthorities": [{"name": "x"}], "drandChains": [], "predicateTypes": {}}`,
		"unknown drand chain":      `{"policy": "hardware-attested-statement/policy/v0.1", "timestampAuthorities": [], "drandChains": ["mainnet"], "predicateTypes": {}}`,
		"unknown profile":          head + `"predicateTypes": {"x": {"trustedSigners": [{"profile": "ios"}]}}}`,
		"unknown profile settings": head + `"predicateTypes": {}, "profiles": {"andriod": {}}}`,
		"bad android signer":       head + `"predicateTypes": {"x": {"trustedSigners": [{"profile": "android", "package": "x", "signers": []}]}}}`,
		"bad android setting":      head + `"predicateTypes": {}, "profiles": {"android": {"requireStrongBoxx": true}}}`,
		"case-folded setting":      head + `"predicateTypes": {}, "profiles": {"android": {"requireStrongbox": true}}}`,
		"bad per-type setting":     head + `"predicateTypes": {"x": {"trustedSigners": [` + signer + `], "profiles": {"android": {"minOsPatch": 1}}}}}`,
		"zero list age":            head + `"predicateTypes": {}, "profiles": {"android": {"maxListAgeHours": 0}}}`,
		"no OS accepted":           head + `"predicateTypes": {}, "profiles": {"android": {"os": {"stock": false, "bootKeyLists": []}}}}`,
	} {
		p, err := verifier.ParsePolicy([]byte(raw))
		if err == nil {
			_, err = newVerifier(t, p, testTrust(t))
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
