package awsnitro

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/profiles/android"
)

const testPredicateType = "https://example.com/test/v1"

// bundle signs a statement with the fixture's attested key, as an enclave following the profile does.
func (f *fixture) bundle(t testing.TB) *verifier.Bundle {
	t.Helper()
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x","digest":{"sha256":"` +
		strings.Repeat("ab", 32) + `"}}],"predicateType":"` + testPredicateType + `","predicate":{}}`)
	digest := sha256.Sum256(verifier.PAE(verifier.InTotoPayload, statement))
	r, s, err := ecdsa.Sign(rand.Reader, f.signingKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if n := f.signingKey.Curve.Params().N; s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s.Sub(n, s)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"mediaType": verifier.BundleMediaType,
		"dsseEnvelope": map[string]any{"payloadType": verifier.InTotoPayload,
			"payload": base64.StdEncoding.EncodeToString(statement), "signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(sig)}}},
		"verificationMaterial": map[string]any{"key": jsontext.Value(f.keyEvidence(t))},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := verifier.ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifier makes a verifier for a policy trusting the fixture's image, with settings (JSON, or "" for none),
// and the Android profile registered too, as attested-verify does.
func (f *fixture) verifier(t testing.TB, settings string, now time.Time) *verifier.Verifier {
	t.Helper()
	profiles := ""
	if settings != "" {
		profiles = `, "profiles": {"awsnitro": ` + settings + `}`
	}
	policy, err := verifier.ParsePolicy([]byte(`{"policy": "hardware-attested-statement/policy/v0.1",
	  "timestampAuthorities": [], "drandChains": ["quicknet"],
	  "predicateTypes": {"` + testPredicateType + `": {"trustedSigners": [` + strings.Join(f.trusted, ",") + `]}}` + profiles + `}`))
	if err != nil {
		t.Fatal(err)
	}
	androidTrust := &android.Trust{BootKeyLists: map[string]*android.BootKeyList{"grapheneos": {}}}
	v, err := verifier.New(policy, android.New(androidTrust), New(&Trust{Roots: f.roots}))
	if err != nil {
		t.Fatal(err)
	}
	v.Now = func() time.Time { return now }
	return v
}

func TestVerifyBundle(t *testing.T) {
	f := newFixture(t, chainOptions{})
	made := f.kc.Now
	r, err := f.verifier(t, "", made.Add(time.Minute)).Verify(f.bundle(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Profile != Name || !r.Accepted || r.Key.Created == nil || !r.Key.Created.Equal(testRoundTime(t)) {
		t.Errorf("result %+v", r)
	}
	report, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"moduleId":"` + testModuleID + `"`, `"region":"us-east-1"`, `"documentTime":`, `"pcrs":{`,
		`"created":`, `"validFrom":`, `"validUntil":`} {
		if !strings.Contains(string(report), want) {
			t.Errorf("the result doesn't report %s: %s", want, report)
		}
	}

	// Without a time-stamp, the evidence must be valid at verification time: the signing certificate lives 3 hours.
	if _, err := f.verifier(t, "", f.chain.leaf.NotAfter.Add(time.Second)).Verify(f.bundle(t)); err == nil ||
		!strings.Contains(err.Error(), "isn't valid now") {
		t.Errorf("verified after the signing certificate expired: %v", err)
	}
}

// A key is usable for maxKeyAgeHours after its round, however often its evidence is renewed.
func TestKeyAge(t *testing.T) {
	f := newFixture(t, chainOptions{leafLifetime: 48 * time.Hour}) // the instance CA ends the chain a day after
	round := testRoundTime(t)
	for name, c := range map[string]struct {
		settings string
		now      time.Time
		ok       bool
	}{
		"24 hours, the default":         {now: round.Add(24 * time.Hour), ok: true},
		"a second more":                 {now: round.Add(24*time.Hour + time.Second)},
		"an hour, if the policy says 1": {settings: `{"maxKeyAgeHours": 1}`, now: round.Add(time.Hour), ok: true},
		"two hours, if it says 1":       {settings: `{"maxKeyAgeHours": 1}`, now: round.Add(2 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.verifier(t, c.settings, c.now).Verify(f.bundle(t))
			if (err == nil) != c.ok {
				t.Fatalf("got %v, want ok %v", err, c.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "more than the policy allows") {
				t.Errorf("rejected for another reason: %v", err)
			}
		})
	}
}

// A policy without awsnitro entries or settings loads with the profile registered, and one with them loads with
// Android registered too.
func TestPolicyLoading(t *testing.T) {
	policy, err := verifier.ParsePolicy([]byte(`{"policy": "hardware-attested-statement/policy/v0.1",
	  "timestampAuthorities": [], "drandChains": [], "predicateTypes": {"` + testPredicateType + `": {"trustedSigners": [
	  {"profile": "android", "package": "org.example", "signingCertificates": ["` + strings.Repeat("ab", 32) + `"]}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	androidTrust := &android.Trust{BootKeyLists: map[string]*android.BootKeyList{"grapheneos": {}}}
	if _, err := verifier.New(policy, android.New(androidTrust), New(&Trust{})); err != nil {
		t.Errorf("an Android-only policy: %v", err)
	}
	f := newFixture(t, chainOptions{})
	f.verifier(t, `{"maxKeyAgeHours": 48}`, f.kc.Now)
}
