package verifier

import (
	"os"
	"testing"
)

// The parsers of untrusted bytes must never panic. `go test -fuzz FuzzParseHTTPResponse` fuzzes; plain `go test`
// runs the seeds.
func FuzzParseHTTPResponse(f *testing.F) {
	for _, name := range []string{"example.http", "redirect.http"} {
		raw, err := os.ReadFile("testdata/capture/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if _, b, err := ParseHTTPResponse(raw); err == nil {
			_, _ = ParseStatement(b.DSSEEnvelope.Payload)
		}
	})
}

func FuzzParseBundle(f *testing.F) {
	f.Add([]byte(`{"mediaType":"application/vnd.hardware-attested-statement.bundle.v0.1+json","dsseEnvelope":{"payload":"e30="}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseBundle(raw)
		_, _ = ParseStatement(raw)
	})
}
