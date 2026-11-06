package awsnitro

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"regexp"
	"time"
)

// chain is a document's certificate chain, checked (verification step 4).
type chain struct {
	leaf   *x509.Certificate
	region string
	// The whole chain, the root included, is valid from validFrom to validUntil.
	validFrom, validUntil time.Time
}

// leafName is the signing certificate's common name: the enclave's module ID, its region, and ".aws".
var leafName = regexp.MustCompile(`^(i-[0-9a-f]{8,17}-enc[0-9a-f]{16})\.([a-z0-9-]+)\.aws$`)

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// verifyChain checks that cabundle starts at one of roots, each later certificate is issued and signed by the one
// before it and the signing certificate by the last, with ECDSA P-384 keys and SHA-384 signatures, CAs above
// the leaf within their path length constraints, and the leaf named after the document's enclave. The links are
// checked directly, not with x509.Verify, whose validity checks at one time don't fit: validity is checked
// against the statement's time bounds (core spec section 4).
func (d *document) verifyChain(roots []*x509.Certificate) (*chain, error) {
	var root *x509.Certificate
	for _, r := range roots {
		if bytes.Equal(r.Raw, d.cabundle[0]) {
			root = r
		}
	}
	if root == nil {
		return nil, fmt.Errorf("%w: cabundle doesn't start at a trusted root", ErrChain)
	}
	cas := []*x509.Certificate{root}
	for i, der := range d.cabundle[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: cabundle certificate %d: %v", ErrChain, i+1, err)
		}
		cas = append(cas, c)
	}
	leaf, err := x509.ParseCertificate(d.certificate)
	if err != nil {
		return nil, fmt.Errorf("%w: signing certificate: %v", ErrChain, err)
	}
	all := append(cas, leaf)
	ch := &chain{leaf: leaf, validFrom: root.NotBefore, validUntil: root.NotAfter}
	for i, c := range all[1:] {
		parent, name := all[i], certificateName(i+1, len(all))
		if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P384() {
			return nil, fmt.Errorf("%w: %s doesn't have a P-384 key", ErrChain, name)
		}
		if c.SignatureAlgorithm != x509.ECDSAWithSHA384 {
			return nil, fmt.Errorf("%w: %s isn't signed with ECDSA and SHA-384", ErrChain, name)
		}
		if !bytes.Equal(c.RawIssuer, parent.RawSubject) {
			return nil, fmt.Errorf("%w: %s's issuer isn't the certificate above it", ErrChain, name)
		}
		if err := parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			return nil, fmt.Errorf("%w: %s isn't signed by the certificate above it", ErrChain, name)
		}
		if c.NotBefore.After(ch.validFrom) {
			ch.validFrom = c.NotBefore
		}
		if c.NotAfter.Before(ch.validUntil) {
			ch.validUntil = c.NotAfter
		}
	}
	for i, c := range cas {
		if i > 0 && !(c.BasicConstraintsValid && c.IsCA) {
			return nil, fmt.Errorf("%w: %s isn't a CA", ErrChain, certificateName(i, len(all)))
		}
		below := len(cas) - 1 - i // CAs between it and the leaf
		if c.MaxPathLen > 0 || c.MaxPathLenZero {
			if below > c.MaxPathLen {
				return nil, fmt.Errorf("%w: %s's path length constraint is exceeded", ErrChain, certificateName(i, len(all)))
			}
		}
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return nil, fmt.Errorf("%w: the signing certificate is a CA", ErrChain)
	}
	var names []string
	for _, n := range leaf.Subject.Names {
		if n.Type.Equal(oidCommonName) {
			s, _ := n.Value.(string)
			names = append(names, s)
		}
	}
	if len(names) != 1 {
		return nil, fmt.Errorf("%w: the signing certificate has %d common names", ErrChain, len(names))
	}
	m := leafName.FindStringSubmatch(names[0])
	if m == nil || m[1] != d.moduleID {
		return nil, fmt.Errorf("%w: the signing certificate's name %q isn't the enclave's (%s)", ErrChain, names[0], d.moduleID)
	}
	ch.region = m[2]
	return ch, nil
}

func certificateName(i, n int) string {
	switch i {
	case 0:
		return "the root"
	case n - 1:
		return "the signing certificate"
	}
	return fmt.Sprintf("cabundle certificate %d", i)
}

// leafKey is the signing certificate's key, which verifyChain checked is ECDSA P-384.
func leafKey(ch *chain) *ecdsa.PublicKey { return ch.leaf.PublicKey.(*ecdsa.PublicKey) }
