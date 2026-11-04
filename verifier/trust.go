package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

//go:embed data
var data embed.FS

// Pinned in the binary (spec appendix A): FreeTSA's root and signing certificate.
var freeTSAFingerprints = map[string]string{
	"data/freetsa/root-ca.pem":  "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc",
	"data/freetsa/tsa-2026.pem": "32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc",
}

// FreeTSA returns FreeTSA's root and signing certificates, checked against their fingerprints.
func FreeTSA() (TSA, error) {
	load := func(path string) (*x509.Certificate, error) {
		raw, err := data.ReadFile(path)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("not PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(c.Raw); hex.EncodeToString(sum[:]) != freeTSAFingerprints[path] {
			return nil, fmt.Errorf("%s doesn't match its pinned fingerprint", path)
		}
		return c, nil
	}
	tsa := TSA{Name: "freetsa"}
	var err error
	if tsa.Root, err = load("data/freetsa/root-ca.pem"); err != nil {
		return tsa, err
	}
	for _, p := range []string{"data/freetsa/tsa-2026.pem"} { // the 2016 certificate expired in 2026-03
		c, err := load(p)
		if err != nil {
			return tsa, err
		}
		tsa.Signers = append(tsa.Signers, c)
	}
	return tsa, nil
}

func timeOrNow(f func() time.Time) time.Time {
	if f == nil {
		return time.Now()
	}
	return f()
}
