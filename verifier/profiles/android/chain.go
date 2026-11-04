package android

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// Provisioning is how the device got its attestation key.
type Provisioning string

const (
	// FactoryProvisioned keys were installed at the factory; leaked attestation keys come from these.
	FactoryProvisioned Provisioning = "factory"
	// RemotelyProvisioned (RKP) keys get short-lived certificates from Google.
	RemotelyProvisioned Provisioning = "rkp"
)

type chainInfo struct {
	root         *x509.Certificate
	certs        []*x509.Certificate // as given, leaf first, without the root
	provisioning Provisioning
	level        SecurityLevel // as the certificates state it
}

// verifyChain checks each certificate is signed by the next and the last by one of roots, that only the leaf
// carries the attestation extension, and what the chain says about provisioning and security level (spec:
// profiles/android.md). Attestation chains don't follow web PKI conventions (leaf certificates are issued by keys
// marked as non-CAs on some devices, odd validity periods), so the links are checked directly rather than with
// x509.Verify; validity periods are checked against the time bounds separately.
func verifyChain(chain []*x509.Certificate, roots []*x509.Certificate) (*chainInfo, error) {
	if len(chain) < 2 {
		return nil, errors.New("attestation chain is too short")
	}
	for i, c := range chain {
		isRoot := func(r *x509.Certificate) bool {
			return bytes.Equal(r.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo)
		}
		if bytes.Equal(c.RawIssuer, c.RawSubject) || slices.ContainsFunc(roots, isRoot) {
			return nil, fmt.Errorf("certificate %d is self-issued or a root: the chain must not include one", i)
		}
		if !slices.Contains(allowedSignatureAlgorithms, c.SignatureAlgorithm) {
			return nil, fmt.Errorf("certificate %d is signed with %v, not SHA-256 or stronger", i, c.SignatureAlgorithm)
		}
		if i > 0 && slices.ContainsFunc(c.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(OIDKeyAttestation) }) {
			return nil, fmt.Errorf("certificate %d carries an attestation extension: only the leaf may", i)
		}
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := issuedBy(chain[i], chain[i+1]); err != nil {
			return nil, fmt.Errorf("certificate %d isn't issued by certificate %d: %w", i, i+1, err)
		}
	}
	var root *x509.Certificate
	for _, r := range roots {
		if issuedBy(chain[len(chain)-1], r) == nil {
			root = r
			break
		}
	}
	if root == nil {
		return nil, errors.New("chain doesn't end at a trusted attestation root")
	}
	ci := &chainInfo{root: root, certs: chain}
	top := chain[len(chain)-1].Subject
	if top.CommonName == "Droid CA2" && slices.Equal(top.Organization, []string{"Google LLC"}) && len(top.Names) == 2 {
		ci.provisioning = RemotelyProvisioned
		switch o := chain[1].Subject.Organization; {
		case slices.Equal(o, []string{"TEE"}):
			ci.level = TEE
		case slices.Equal(o, []string{"StrongBox"}):
			ci.level = StrongBox
		default:
			return nil, fmt.Errorf("remotely provisioned chain whose attestation certificate names no security level (O=%v)", o)
		}
	} else {
		ci.provisioning, ci.level = FactoryProvisioned, TEE
		for _, c := range chain[1:] {
			if slices.Contains(titles(c), "StrongBox") {
				ci.level = StrongBox
			}
		}
	}
	return ci, nil
}

var oidTitle = asn1.ObjectIdentifier{2, 5, 4, 12}

var allowedSignatureAlgorithms = []x509.SignatureAlgorithm{x509.ECDSAWithSHA256, x509.ECDSAWithSHA384,
	x509.ECDSAWithSHA512, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS,
	x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS}

func titles(c *x509.Certificate) []string {
	var out []string
	for _, n := range c.Subject.Names {
		if s, ok := n.Value.(string); ok && n.Type.Equal(oidTitle) {
			out = append(out, s)
		}
	}
	return out
}

func issuedBy(child, parent *x509.Certificate) error {
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return errors.New("issuer name doesn't match")
	}
	return parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
}
