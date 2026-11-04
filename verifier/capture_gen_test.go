package verifier_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/predicates/httpresponse"
)

// The test captures in testdata/capture are HTTP responses carrying their bundle in headers (spec section 6), as a
// capturing program makes them: signed with a fake StrongBox attestation chain of a GrapheneOS device, with a real
// drand round and real FreeTSA time-stamps, some shared by a batch. To make them again (needs the network):
//
//	go test -run '^TestGenerateCaptures$' -generate-captures .
var generateCaptures = flag.Bool("generate-captures", false, "make testdata/capture again (needs the network)")

// capturePackage is the capturing program the test captures name; testSigner is its signing certificate.
const capturePackage = "org.example.capture"

const quicknet = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

type origin struct {
	name, url, statusLine string
	status                int
	headers               [][2]string // without Content-Length, which is added
	body                  string
}

func TestGenerateCaptures(t *testing.T) {
	if !*generateCaptures {
		t.Skip("run with -generate-captures to make testdata/capture again")
	}
	var list struct {
		VerifiedBootKeys []string `json:"verifiedBootKeys"`
	}
	if err := json.Unmarshal(read(t, "testdata/trust/attestation.json"), &list, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	bootKey, _ := hex.DecodeString(list.VerifiedBootKeys[0]) // so the fake device runs GrapheneOS
	signer, _ := hex.DecodeString(testSigner)
	now := time.Now()
	rot := seq(octets(bootKey), tlv(0, 1, false, []byte{0xff}), enumerated(1), octets(make([]byte, 32))) // locked, SelfSigned
	key := newFakeKey(t, fakeOptions{pkg: capturePackage, signer: signer, notBefore: now.Add(-time.Hour),
		notAfter: now.AddDate(20, 0, 0), extension: keyDescriptionWithRoot(capturePackage, 1, signer, set(integer(2)), rot)})
	if err := os.WriteFile("testdata/capture/fake_root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: key.root.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}

	html := [][2]string{{"Content-Type", "text/html; charset=UTF-8"}, {"Date", "Tue, 03 Nov 2026 23:00:00 GMT"}}
	page := func(name, path, title string) origin {
		return origin{name, "https://example.com" + path, "HTTP/1.1 200 OK", 200, html,
			"<!doctype html>\n<html><head><title>" + title + "</title></head><body><p>" + title + "</p></body></html>\n"}
	}
	var parallel []origin
	for i := 1; i <= 8; i++ {
		parallel = append(parallel, page(fmt.Sprintf("parallel-%d.http", i), fmt.Sprintf("/page/%d", i), fmt.Sprintf("Page %d", i)))
	}
	redirect := origin{"redirect.http", "https://example.com/old", "HTTP/1.1 301 Moved Permanently", 301,
		append([][2]string{{"Location", "https://example.com/new"}}, html...), "<a href=\"https://example.com/new\">Moved</a>\n"}
	// Time-stamped alone, alone, and in batches of 5 and 3: trees of one leaf and of several.
	for _, batch := range [][]origin{{page("example.http", "/", "Example Domain")}, {redirect}, parallel[:5], parallel[5:]} {
		round, roundSig := latestRound(t)
		var bundles []*verifier.Bundle
		var leaves [][]byte
		for _, o := range batch {
			b := signBundle(t, captureStatement(t, o, round, roundSig), key.key, key.chain)
			id := signedID(t, b)
			bundles, leaves = append(bundles, b), append(leaves, rfc6962.DefaultHasher.HashLeaf(id[:]))
		}
		token := freeTSA(t, treeHash(leaves))
		for i, o := range batch {
			bundles[i].VerificationMaterial.Timestamp = &verifier.Timestamp{Token: token,
				Tree: verifier.Tree{Size: uint64(len(batch)), Index: uint64(i), Path: inclusionPath(i, leaves)}}
			raw := savedResponse(t, o, bundles[i])
			if _, err := verifyCapture(mustVerifier(t, defaultParams().policy(t), testTrust(t)), raw); err != nil {
				t.Fatalf("%s doesn't verify: %v", o.name, err)
			}
			if err := os.WriteFile("testdata/capture/"+o.name, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(1100 * time.Millisecond) // FreeTSA answers one request per second
	}
}

// captureStatement is the statement a capturing program signs for o (predicate type http-response, v1).
func captureStatement(t *testing.T, o origin, round uint64, roundSig string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(o.body))
	cert := sha256.Sum256([]byte("test server certificate"))
	headers := append(append([][2]string{}, o.headers...), [2]string{"Content-Length", fmt.Sprint(len(o.body))})
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "body", "digest": map[string]string{"sha256": hex.EncodeToString(sum[:])}, "mediaType": headerValue(o.headers, "Content-Type")}},
		"predicateType": httpresponse.PredicateType,
		"predicate": map[string]any{
			"request": map[string]any{"method": "GET", "url": o.url, "cookies": "none",
				"headers": [][2]string{{"User-Agent", "curl/8.5.0"}, {"Accept-Encoding", "identity"}, {"Host", "example.com"}}},
			"connection": map[string]any{"route": "direct", "connectedTo": "192.0.2.1:443", "protocol": "http/1.1",
				"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "serverCertificateSha256": hex.EncodeToString(cert[:])},
			"response":     map[string]any{"statusLine": o.statusLine, "status": o.status, "headers": headers},
			"startedAfter": map[string]any{"drand": map[string]any{"chain": quicknet, "round": round, "signature": roundSig}},
		},
	}
	raw, err := json.Marshal(st, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func headerValue(headers [][2]string, name string) string {
	for _, h := range headers {
		if h[0] == name {
			return h[1]
		}
	}
	return ""
}

// savedResponse is o as a saved response, carrying b in its headers.
func savedResponse(t *testing.T, o origin, b *verifier.Bundle) []byte {
	t.Helper()
	seq := func(v []byte) string { return ":" + base64.StdEncoding.EncodeToString(v) + ":" }
	ts := b.VerificationMaterial.Timestamp
	var path []string
	for _, p := range ts.Tree.Path {
		path = append(path, seq(p))
	}
	var out strings.Builder
	out.WriteString(o.statusLine + "\r\n")
	for _, h := range o.headers {
		out.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	fmt.Fprintf(&out, "Content-Length: %d\r\n", len(o.body))
	for _, h := range [][2]string{{"Attested-Version", "v0.1"}, {"Attested-Statement", seq(b.DSSEEnvelope.Payload)},
		{"Attested-Signature", seq(b.DSSEEnvelope.Signatures[0].Sig)}, {"Attested-Key", seq(b.VerificationMaterial.Key.Raw)},
		{"Attested-Timestamp", seq(ts.Token)},
		{"Attested-Timestamp-Tree", fmt.Sprintf("size=%d, index=%d, path=(%s)", ts.Tree.Size, ts.Tree.Index, strings.Join(path, " "))}} {
		out.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	out.WriteString("\r\n" + o.body)
	return []byte(out.String())
}

// treeHash is the RFC 9162 tree hash of leaf hashes; inclusionPath is the inclusion proof of leaf m, leaf first.
func treeHash(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return rfc6962.DefaultHasher.HashChildren(treeHash(leaves[:k]), treeHash(leaves[k:]))
}

func inclusionPath(m int, leaves [][]byte) []verifier.Bytes {
	if len(leaves) == 1 {
		return []verifier.Bytes{}
	}
	if k := split(len(leaves)); m < k {
		return append(inclusionPath(m, leaves[:k]), treeHash(leaves[k:]))
	} else {
		return append(inclusionPath(m-k, leaves[k:]), treeHash(leaves[:k]))
	}
}

// split is the largest power of two smaller than n.
func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// latestRound is quicknet's latest round and its signature.
func latestRound(t *testing.T) (uint64, string) {
	t.Helper()
	resp, err := http.Get("https://api.drand.sh/" + quicknet + "/public/latest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r struct {
		Round     uint64 `json:"round"`
		Signature string `json:"signature"`
	}
	if err := json.UnmarshalRead(resp.Body, &r, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	return r.Round, r.Signature
}

// freeTSA is FreeTSA's time-stamp over root, requested without certificates (spec section 2).
func freeTSA(t *testing.T, root []byte) []byte {
	t.Helper()
	nonce, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	req, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: root, Nonce: nonce}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post("https://freetsa.org/tsr", "application/timestamp-query", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("FreeTSA: %v %s", err, resp.Status)
	}
	return body
}
