package awsnitro

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
)

// Real AWS attestation documents (testdata/aws/README.md). None is made for this profile, so none can pass: each
// is checked step by step, and every step's outcome is asserted, so that each rule is shown to hold, or to
// reject, on what AWS really produces.
type sample struct {
	name     string
	nitroTPM bool
	debug    bool
	highS    bool
}

var samples = []sample{
	{name: "aws-iot"},
	{name: "wappie"},
	{name: "ppmag", debug: true, highS: true},
	{name: "tca", debug: true},
	{name: "evervault-go", debug: true, highS: true},
	{name: "biomodel", nitroTPM: true, highS: true},
	{name: "eternis", nitroTPM: true},
}

func readSample(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "aws", name+".cose"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var p384HalfOrder = new(big.Int).Rsh(elliptic.P384().Params().N, 1)

func TestRealDocuments(t *testing.T) {
	awsRoot := mustAWSRoot(t)
	kc := verifier.KeyContext{Drand: map[string]verifier.DrandChain{testRound.Chain: quicknet(t)}}
	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			cose, err := parseCOSE(readSample(t, s.name)) // steps 1 and 2, for the structure
			if err != nil {
				t.Fatalf("structure: %v", err)
			}
			if high := new(big.Int).SetBytes(cose.signature[48:]).Cmp(p384HalfOrder) > 0; high != s.highS {
				t.Errorf("high s: %v, want %v", high, s.highS)
			}
			d, err := parseDocument(cose.payload) // steps 2 and 3
			if s.nitroTPM {
				if !errors.Is(err, ErrDocument) {
					t.Fatalf("a NitroTPM document: got %v, want %v", err, ErrDocument)
				}
				// Step 4 rejects it as well, by its signing certificate's name.
				d = nitroTPMDocument(t, cose.payload)
				if _, err := d.verifyChain([]*x509.Certificate{awsRoot}); !errors.Is(err, ErrChain) {
					t.Errorf("its chain: got %v, want %v", err, ErrChain)
				}
				return
			}
			if err != nil {
				t.Fatalf("document: %v", err)
			}
			ch, err := d.verifyChain([]*x509.Certificate{awsRoot}) // step 4
			if err != nil {
				t.Fatalf("chain: %v", err)
			}
			if err := cose.verify(leafKey(ch)); err != nil { // step 5
				t.Errorf("signature: %v", err)
			}
			if d.timestamp.Before(ch.leaf.NotBefore) || d.timestamp.After(ch.leaf.NotAfter) {
				t.Errorf("document time %v outside its certificate's validity", d.timestamp)
			}
			if _, _, err := d.checkKey(testRound, kc); !errors.Is(err, ErrKey) { // step 6
				t.Errorf("key: got %v, want %v", err, ErrKey)
			}
			err = d.checkNotDebug() // step 7
			if s.debug && !errors.Is(err, ErrDebug) || !s.debug && err != nil {
				t.Errorf("debug: got %v, want debug %v", err, s.debug)
			}
		})
	}
}

// nitroTPMDocument reads a NitroTPM document's module ID and chain, which parseDocument rejects.
func nitroTPMDocument(t testing.TB, payload []byte) *document {
	t.Helper()
	it, err := decodeCBOR(payload, true)
	if err != nil {
		t.Fatal(err)
	}
	d := &document{}
	for i := 0; i < len(it.items); i += 2 {
		v := it.items[i+1]
		switch it.items[i].text() {
		case "module_id":
			d.moduleID = v.text()
		case "certificate":
			d.certificate = v.bytes
		case "cabundle":
			for _, c := range v.items {
				d.cabundle = append(d.cabundle, c.bytes)
			}
		}
	}
	if d.moduleID == "" || len(d.cabundle) == 0 {
		t.Fatal("not a NitroTPM document")
	}
	return d
}
