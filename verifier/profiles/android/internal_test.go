package android

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real chains from Google's corpus reach Google's current roots and are classified as Google's verifier does.
func TestGoogleCorpusChains(t *testing.T) {
	roots, err := GoogleRoots()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Provisioning{
		"akita": RemotelyProvisioned, "caiman": RemotelyProvisioned, "frankel": RemotelyProvisioned,
		"tegu": RemotelyProvisioned, "blueline": FactoryProvisioned, "sony-xperia10-iii": FactoryProvisioned,
		"walleye": FactoryProvisioned,
	}
	paths, _ := filepath.Glob("testdata/google/*/*/*.pem")
	checked := 0
	for _, path := range paths {
		device := strings.Split(path, string(filepath.Separator))[2]
		if device == "marlin" { // under a retired root
			continue
		}
		chain := withoutRoot(readChain(t, path))
		ci, err := verifyChain(chain, roots)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		checked++
		if strings.Contains(path, "_RKP") || strings.Contains(path, "2026") {
			if ci.provisioning != RemotelyProvisioned {
				t.Errorf("%s: %s, want rkp", path, ci.provisioning)
			}
		} else if w, ok := want[device]; ok && !strings.Contains(path, "MLDSA") && ci.provisioning != w {
			t.Errorf("%s: %s, want %s", path, ci.provisioning, w)
		}
		kd, err := ParseKeyDescription(chain[0])
		if err != nil {
			t.Fatal(err)
		}
		// The security level the certificates state agrees with the attestation.
		if ci.level != kd.KeyMintSecurityLevel {
			t.Errorf("%s: certificates say %v, attestation %v", path, ci.level, kd.KeyMintSecurityLevel)
		}
	}
	if checked < 20 {
		t.Fatalf("only %d chains checked", checked)
	}
	chain := readChain(t, "testdata/google/caiman/sdk36/TEE_EC_RKP.pem")
	for name, c := range map[string][]*x509.Certificate{
		"link removed":  append(chain[:1:1], withoutRoot(chain)[2:]...),
		"root included": chain,
		"no leaf":       withoutRoot(chain)[1:],
	} {
		if _, err := verifyChain(c, roots); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

// Google's corpus files end with the root; bundles don't carry it.
func withoutRoot(chain []*x509.Certificate) []*x509.Certificate {
	if last := chain[len(chain)-1]; bytes.Equal(last.RawIssuer, last.RawSubject) {
		return chain[:len(chain)-1]
	}
	return chain
}

func TestGrapheneOSKeyListSignature(t *testing.T) {
	signers, _ := data.ReadFile("data/grapheneos-allowed_signers")
	list, _ := os.ReadFile("../../testdata/trust/attestation.json")
	sig, _ := os.ReadFile("../../testdata/trust/attestation.json.sig")
	if err := verifySSHSignature(signers, "contact@grapheneos.org", "attestation keys", list, sig); err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(list), "d8f879", "d8f87a", 1))
	if err := verifySSHSignature(signers, "contact@grapheneos.org", "attestation keys", tampered, sig); err == nil {
		t.Error("tampered list accepted")
	}
	if err := verifySSHSignature(signers, "contact@grapheneos.org", "other", list, sig); err == nil {
		t.Error("wrong namespace accepted")
	}
}

// Google's list keys most entries by decimal serial, despite documenting hex; both forms must match.
func TestRevocationSerialForms(t *testing.T) {
	revoked, err := parseRevocationList([]byte(`{"entries": {"12345678901234567890": {"status": "REVOKED"},
		"1f2e3d": {"status": "SUSPENDED"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	tr := &Trust{Revoked: revoked}
	dec, _ := new(big.Int).SetString("12345678901234567890", 10)
	for _, serial := range []*big.Int{dec, big.NewInt(0x1f2e3d)} {
		if _, ok := tr.revoked(serial); !ok {
			t.Errorf("serial %v not matched", serial)
		}
	}
	if _, ok := tr.revoked(big.NewInt(7)); ok {
		t.Error("unlisted serial matched")
	}
	if _, err := parseRevocationList([]byte(`{"entries": {"0xABC": {"status": "REVOKED"}}}`)); err == nil {
		t.Error("an entry that is neither hex nor decimal accepted")
	}
}

// A list's production time is the earlier of its Date and the time received minus its Age (spec section 3).
func TestListProducedTime(t *testing.T) {
	received := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	h := http.Header{}
	// As Google's cache served it: the original Date, and Age the time since (not counted twice).
	h.Set("Date", received.Add(-80555*time.Second).Format(http.TimeFormat))
	h.Set("Age", "80555")
	if got := produced(h, received); !got.Equal(received.Add(-80555 * time.Second)) {
		t.Errorf("produced %v", got)
	}
	h.Set("Date", received.Format(http.TimeFormat)) // a cache that rewrote Date
	if got := produced(h, received); !got.Equal(received.Add(-80555 * time.Second)) {
		t.Errorf("produced %v", got)
	}
}

// The AOSP test keys' fingerprints, as libavb hashes them: SHA-256 of the key in its own format.
func TestAOSPTestKeyFingerprints(t *testing.T) {
	if len(aospTestKeys) != 3 {
		t.Fatal(aospTestKeys)
	}
	for k := range aospTestKeys {
		if b, err := hex.DecodeString(k); err != nil || len(b) != 32 {
			t.Errorf("%s isn't a SHA-256", k)
		}
	}
}

// Settings outside their ranges are policy errors, among them a minOsVersion written as a major version.
func TestSettingsRanges(t *testing.T) {
	p := New(&Trust{BootKeyLists: map[string]*BootKeyList{"grapheneos": {}}})
	for raw, ok := range map[string]bool{
		`{}`: true, `{"minOsVersion": 0}`: true, `{"minOsVersion": 10000}`: true, `{"minOsVersion": 999999}`: true,
		`{"minOsVersion": 14}`: false, `{"minOsVersion": 9999}`: false, `{"minOsVersion": 1000000}`: false,
		`{"minOsVersion": -1}`: false, `{"maxPatchAgeMonths": 0}`: true, `{"maxPatchAgeMonths": 1200}`: true,
		`{"maxPatchAgeMonths": -1}`: false, `{"maxPatchAgeMonths": 1201}`: false,
	} {
		if err := p.CheckPolicy(nil, []byte(raw)); (err == nil) != ok {
			t.Errorf("%s: ok %v, err %v", raw, ok, err)
		}
	}
}
