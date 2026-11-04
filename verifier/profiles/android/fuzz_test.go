package android

import (
	"path/filepath"
	"testing"
)

// The attestation parser reads untrusted bytes and must never panic. `go test -fuzz FuzzParseKeyDescription`
// fuzzes; plain `go test` runs the seeds (every attestation in Google's corpus).
func FuzzParseKeyDescription(f *testing.F) {
	paths, _ := filepath.Glob("testdata/google/*/*/*.pem")
	for _, p := range paths {
		chain := readChainForFuzz(p)
		for _, e := range chain[0].Extensions {
			if e.Id.Equal(OIDKeyAttestation) {
				f.Add(e.Value)
			}
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseKeyDescription(raw)
	})
}
