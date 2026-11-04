package android

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func readChain(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	chain := readChainForFuzz(path)
	if len(chain) == 0 {
		t.Fatalf("%s: no certificates", path)
	}
	return chain
}

func readChainForFuzz(path string) []*x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		chain = append(chain, c)
	}
	return chain
}

func corpus(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("testdata/google/*/*/*.json")
	if err != nil || len(paths) < 20 {
		t.Fatalf("Google's corpus is missing (%d files, %v)", len(paths), err)
	}
	return paths
}

// Our parser must read every real attestation in Google's corpus as Google's library does.
func TestParseMatchesGoogleCorpus(t *testing.T) {
	levels := map[string]SecurityLevel{"SOFTWARE": Software, "TRUSTED_ENVIRONMENT": TEE, "STRONG_BOX": StrongBox}
	states := map[string]BootState{"VERIFIED": Verified, "SELF_SIGNED": SelfSigned, "UNVERIFIED": Unverified, "FAILED": Failed}
	num := func(s string) int64 {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("expected value %q: %v", s, err)
		}
		return n
	}
	b64 := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("expected value %q: %v", s, err)
		}
		return b
	}
	for _, path := range corpus(t) {
		t.Run(strings.TrimPrefix(path, "testdata/google/"), func(t *testing.T) {
			var want struct {
				AttestationVersion, AttestationSecurityLevel, KeyMintVersion, KeyMintSecurityLevel string
				AttestationChallenge                                                               string
				SoftwareEnforced, HardwareEnforced                                                 map[string]json.RawMessage
			}
			data, _ := os.ReadFile(path)
			var lines []string // a few files carry // comments
			for _, l := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(strings.TrimSpace(l), "//") {
					lines = append(lines, l)
				}
			}
			if err := json.Unmarshal([]byte(strings.Join(lines, "\n")), &want); err != nil {
				t.Fatal(err)
			}
			kd, err := ParseKeyDescription(readChain(t, strings.TrimSuffix(path, ".json")+".pem")[0])
			if err != nil {
				t.Fatal(err)
			}
			if kd.AttestationVersion != num(want.AttestationVersion) || kd.KeyMintVersion != num(want.KeyMintVersion) {
				t.Errorf("versions %d/%d, want %s/%s", kd.AttestationVersion, kd.KeyMintVersion, want.AttestationVersion, want.KeyMintVersion)
			}
			if kd.AttestationSecurityLevel != levels[want.AttestationSecurityLevel] || kd.KeyMintSecurityLevel != levels[want.KeyMintSecurityLevel] {
				t.Errorf("levels %v/%v, want %s/%s", kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel, want.AttestationSecurityLevel, want.KeyMintSecurityLevel)
			}
			if !bytes.Equal(kd.Challenge, b64(want.AttestationChallenge)) {
				t.Errorf("challenge %q", kd.Challenge)
			}
			for _, side := range []struct {
				got  AuthorizationList
				want map[string]json.RawMessage
			}{{kd.Software, want.SoftwareEnforced}, {kd.Hardware, want.HardwareEnforced}} {
				str := func(key string) (string, bool) {
					raw, ok := side.want[key]
					var s string
					if ok {
						_ = json.Unmarshal(raw, &s)
					}
					return s, ok
				}
				for key, got := range map[string]*int64{"osVersion": side.got.OSVersion, "osPatchLevel": side.got.OSPatchLevel,
					"vendorPatchLevel": side.got.VendorPatchLevel, "bootPatchLevel": side.got.BootPatchLevel} {
					s, ok := str(key)
					if ok != (got != nil) || (ok && *got != num(s)) {
						t.Errorf("%s: got %v, want %q (present %v)", key, got, s, ok)
					}
				}
				ints := func(key string) ([]int64, bool) {
					raw, ok := side.want[key]
					var ss []string
					if ok {
						_ = json.Unmarshal(raw, &ss)
					}
					var out []int64
					for _, s := range ss {
						out = append(out, num(s))
					}
					return out, ok
				}
				if w, ok := ints("purposes"); ok != (side.got.Purposes != nil) || !slices.Equal(w, side.got.Purposes) {
					t.Errorf("purposes: got %v, want %v", side.got.Purposes, w)
				}
				if w, ok := ints("digests"); ok != (side.got.Digests != nil) || !slices.Equal(w, side.got.Digests) {
					t.Errorf("digests: got %v, want %v", side.got.Digests, w)
				}
				for key, got := range map[string]*int64{"algorithms": side.got.Algorithm, "ecCurve": side.got.ECCurve,
					"creationDateTime": side.got.CreationDateTime} {
					s, ok := str(key)
					if ok != (got != nil) || (ok && *got != num(s)) {
						t.Errorf("%s: got %v, want %q (present %v)", key, got, s, ok)
					}
				}
				_, active := side.want["activeDateTime"]
				_, origination := side.want["originationExpireDateTime"]
				_, usage := side.want["usageExpireDateTime"]
				if side.got.HasValidityDates != (active || origination || usage) {
					t.Errorf("validity dates: got %v", side.got.HasValidityDates)
				}
				if s, ok := str("origin"); ok != (side.got.Origin != nil) || (ok && (s == "GENERATED") != (*side.got.Origin == originGenerated)) {
					t.Errorf("origin: got %v, want %q", side.got.Origin, s)
				}
				if raw, ok := side.want["rootOfTrust"]; ok != (side.got.RootOfTrust != nil) {
					t.Errorf("rootOfTrust presence: got %v, want %v", side.got.RootOfTrust != nil, ok)
				} else if ok {
					var r struct {
						VerifiedBootKey, VerifiedBootState, VerifiedBootHash string
						DeviceLocked                                         bool
					}
					_ = json.Unmarshal(raw, &r)
					g := side.got.RootOfTrust
					if !bytes.Equal(g.VerifiedBootKey, b64(r.VerifiedBootKey)) || g.DeviceLocked != r.DeviceLocked ||
						g.BootState != states[r.VerifiedBootState] || !bytes.Equal(g.VerifiedBootHash, b64(r.VerifiedBootHash)) {
						t.Errorf("rootOfTrust: got %+v, want %+v", g, r)
					}
				}
				if raw, ok := side.want["attestationApplicationId"]; ok != (side.got.ApplicationID != nil) {
					t.Errorf("attestationApplicationId presence: got %v, want %v", side.got.ApplicationID != nil, ok)
				} else if ok {
					var a struct {
						Packages   []struct{ Name, Version string }
						Signatures []string
					}
					_ = json.Unmarshal(raw, &a)
					g := side.got.ApplicationID
					if len(g.Packages) != len(a.Packages) || len(g.SignatureDigests) != len(a.Signatures) {
						t.Fatalf("application ID: got %+v, want %+v", g, a)
					}
					for i, p := range a.Packages {
						if g.Packages[i].Name != p.Name || g.Packages[i].VersionCode != num(p.Version) {
							t.Errorf("package %d: got %+v, want %+v", i, g.Packages[i], p)
						}
					}
					for i, s := range a.Signatures {
						if !bytes.Equal(g.SignatureDigests[i], b64(s)) {
							t.Errorf("signature digest %d differs", i)
						}
					}
				}
			}
		})
	}
}

// Google's two deliberately broken samples: a non-DER boolean is rejected; tags out of ascending order are
// accepted (the schema doesn't make order meaningful, and Google's library also only rejects it on request).
func TestParseGoogleInvalidSamples(t *testing.T) {
	if _, err := ParseKeyDescription(readChain(t, "testdata/google/invalid/malformed_rot_device_locked.pem")[0]); err == nil {
		t.Error("malformed deviceLocked accepted")
	} else {
		t.Log("malformed deviceLocked:", err)
	}
	if _, err := ParseKeyDescription(readChain(t, "testdata/google/invalid/tags_not_in_ascending_order.pem")[0]); err != nil {
		t.Error("tags out of order rejected:", err)
	}
}
