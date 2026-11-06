package awsnitro

import (
	"bytes"
	"encoding/json/jsontext"
	"testing"
)

// The parsers read untrusted bytes before anything is verified and must never panic. `go test -fuzz <name>`
// fuzzes; plain `go test` runs the seeds: every real document, and a document from the test root.

func seedDocuments(f *testing.F) {
	for _, s := range samples {
		f.Add(readSample(f, s.name))
	}
	f.Add(newFixture(f, chainOptions{}).document(f))
}

func FuzzParseDocument(f *testing.F) {
	seedDocuments(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		cose, err := parseCOSE(raw)
		if err != nil {
			return
		}
		d, err := parseDocument(cose.payload)
		if err != nil {
			return
		}
		_, _ = d.verifyChain(nil)
		_ = d.checkNotDebug()
		_, _ = parseP256(d.publicKey)
	})
}

// What the reader accepts with definite lengths, it accepts in exactly one encoding: encoding it again gives the
// same bytes.
func FuzzDecodeCBOR(f *testing.F) {
	seedDocuments(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		it, err := decodeCBOR(raw, false)
		if err != nil {
			return
		}
		if again := encodeItem(it); !bytes.Equal(again, raw) {
			t.Fatalf("%x encodes again as %x", raw, again)
		}
	})
}

func FuzzBinding(f *testing.F) {
	for _, s := range samples {
		f.Add([]byte(`{"profile":"awsnitro","attestationDocument":"` + b64(readSample(f, s.name)) +
			`","keyStartedAfter":{"drand":{"chain":"` + testRound.Chain + `","round":1,"signature":"00"}}}`))
	}
	f.Add([]byte(newFixture(f, chainOptions{}).keyEvidence(f)))
	p := New(&Trust{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = p.Binding(jsontext.Value(raw))
	})
}

func encodeItem(it item) []byte {
	switch it.kind {
	case kindUnsigned:
		return appendHead(nil, 0, it.value)
	case kindNegative:
		return appendHead(nil, 1, it.value)
	case kindBytes:
		return cborBytes(it.bytes)
	case kindText:
		return cborText(it.text())
	case kindNull:
		return cborNull
	}
	major, n := byte(4), len(it.items)
	if it.kind == kindMap {
		major, n = 5, n/2
	}
	b := appendHead(nil, major, uint64(n))
	for _, e := range it.items {
		b = append(b, encodeItem(e)...)
	}
	return b
}
