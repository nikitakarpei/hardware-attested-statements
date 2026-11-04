package verifier

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// TSA is a time-stamp authority: its root, intermediates, and the signing certificates its tokens may use.
type TSA struct {
	Name          string
	Root          *x509.Certificate
	Intermediates []*x509.Certificate
	Signers       []*x509.Certificate
}

var (
	oidTSTInfo           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidExtKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	allowedDigests       = []asn1.ObjectIdentifier{oidSHA256, oidSHA384, oidSHA512}
	// For a CMS SignerInfo, rsaEncryption means RSA with the SignerInfo's digest algorithm.
	allowedSignatureAlgos = []asn1.ObjectIdentifier{
		{1, 2, 840, 113549, 1, 1, 1},  // rsaEncryption
		{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
		{1, 2, 840, 113549, 1, 1, 12}, // sha384WithRSAEncryption
		{1, 2, 840, 113549, 1, 1, 13}, // sha512WithRSAEncryption
		{1, 2, 840, 113549, 1, 1, 10}, // RSASSA-PSS
		{1, 2, 840, 10045, 4, 3, 2},   // ecdsa-with-SHA256
		{1, 2, 840, 10045, 4, 3, 3},   // ecdsa-with-SHA384
		{1, 2, 840, 10045, 4, 3, 4},   // ecdsa-with-SHA512
	}
)

type timeStampResp struct {
	Status struct {
		Status       int
		StatusString asn1.RawValue  `asn1:"optional"`
		FailInfo     asn1.BitString `asn1:"optional"`
	}
	Token asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos  []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type accuracy struct {
	Seconds int64 `asn1:"optional"`
	Millis  int64 `asn1:"optional,tag:0"`
	Micros  int64 `asn1:"optional,tag:1"`
}

// timestampResult is a checked time-stamp: its time, the latest time its accuracy allows, and its TSA.
type timestampResult struct {
	Time, Upper time.Time
	TSA         string
}

// verifyTimestamp checks ts as spec section 2.1 requires: an RFC 3161 time-stamp by one of tsas, whose
// certificates are valid at its time and now, over the root of an RFC 9162 tree whose leaf ts.Tree.Index is
// signedID.
func verifyTimestamp(ts *Timestamp, signedID [32]byte, tsas []TSA, now time.Time) (*timestampResult, error) {
	if ts.Tree.Size == 0 || ts.Tree.Index >= ts.Tree.Size {
		return nil, errors.New("time-stamp tree: bad size or index")
	}
	var resp timeStampResp
	if mustUnmarshal(ts.Token, &resp) != nil {
		return nil, errors.New("time-stamp: not a TimeStampResp")
	}
	if resp.Status.Status != 0 {
		return nil, fmt.Errorf("time-stamp status is %d, not granted (0)", resp.Status.Status)
	}
	var ci contentInfo
	if mustUnmarshal(resp.Token.FullBytes, &ci) != nil || !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("time-stamp token is not a CMS SignedData")
	}
	var sd signedData
	if err := mustUnmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("time-stamp token: %v", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, errors.New("time-stamp token's content isn't a TSTInfo")
	}
	var content []byte
	if mustUnmarshal(sd.EncapContentInfo.EContent.Bytes, &content) != nil {
		return nil, errors.New("time-stamp token's content isn't an octet string")
	}
	if len(sd.SignerInfos) != 1 {
		return nil, errors.New("time-stamp token must have exactly one signer")
	}
	si := sd.SignerInfos[0]
	if !slices.ContainsFunc(allowedDigests, si.DigestAlgorithm.Algorithm.Equal) ||
		!slices.ContainsFunc(allowedSignatureAlgos, si.SignatureAlgorithm.Algorithm.Equal) {
		return nil, errors.New("time-stamp signed with an algorithm weaker than SHA-256")
	}
	attr := func(oid asn1.ObjectIdentifier) ([]byte, bool) {
		for _, a := range si.SignedAttrs {
			if a.Type.Equal(oid) && len(a.Values) == 1 {
				return a.Values[0].FullBytes, true
			}
		}
		return nil, false
	}
	var ct asn1.ObjectIdentifier
	if raw, ok := attr(oidAttrContentType); !ok || mustUnmarshal(raw, &ct) != nil || !ct.Equal(oidTSTInfo) {
		return nil, errors.New("time-stamp's signed content-type attribute is missing or isn't TSTInfo")
	}
	var md []byte
	if raw, ok := attr(oidAttrMessageDigest); !ok || mustUnmarshal(raw, &md) != nil {
		return nil, errors.New("time-stamp has no signed message-digest attribute")
	}
	if !bytes.Equal(md, digest(si.DigestAlgorithm.Algorithm, content)) {
		return nil, errors.New("time-stamp's message digest doesn't match its content")
	}
	identifies, err := essIdentifier(attr)
	if err != nil {
		return nil, err
	}

	// TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, accuracy OPTIONAL, … }; the
	// time is read by digitorus/timestamp, which handles fractional seconds.
	var seq asn1.RawValue
	if mustUnmarshal(content, &seq) != nil || seq.Tag != asn1.TagSequence {
		return nil, errors.New("time-stamp TSTInfo is malformed")
	}
	var fields []asn1.RawValue
	for rest := seq.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return nil, errors.New("time-stamp TSTInfo is malformed")
		}
		fields = append(fields, f)
	}
	var version int
	var imprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	if len(fields) < 5 || mustUnmarshal(fields[0].FullBytes, &version) != nil || mustUnmarshal(fields[2].FullBytes, &imprint) != nil {
		return nil, errors.New("time-stamp TSTInfo is malformed")
	}
	if version != 1 {
		return nil, fmt.Errorf("TSTInfo version %d", version)
	}
	if !imprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return nil, errors.New("time-stamp imprint isn't SHA-256")
	}
	acc := time.Second // at least one second: times may be truncated to whole seconds
	if len(fields) > 5 && fields[5].Class == asn1.ClassUniversal && fields[5].Tag == asn1.TagSequence {
		var a accuracy
		if mustUnmarshal(fields[5].FullBytes, &a) != nil {
			return nil, errors.New("time-stamp accuracy is malformed")
		}
		if a.Seconds < 0 || a.Seconds > 86400 || a.Millis < 0 || a.Millis > 999 || a.Micros < 0 || a.Micros > 999 {
			return nil, errors.New("time-stamp accuracy out of range")
		}
		acc = time.Duration(a.Seconds)*time.Second + time.Duration(a.Millis)*time.Millisecond +
			time.Duration(a.Micros)*time.Microsecond
		if acc > 24*time.Hour {
			return nil, errors.New("time-stamp accuracy is over a day")
		}
	}
	parsed, err := timestamp.Parse(resp.Token.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("time-stamp: %w", err)
	}
	path := make([][]byte, len(ts.Tree.Path))
	for i, h := range ts.Tree.Path {
		path[i] = h
	}
	leaf := rfc6962.DefaultHasher.HashLeaf(signedID[:])
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, ts.Tree.Index, ts.Tree.Size, leaf, path, imprint.HashedMessage); err != nil {
		return nil, fmt.Errorf("this signed statement isn't in the time-stamped tree: %w", err)
	}

	lastErr := errors.New("the policy trusts no time-stamp authority")
	for _, tsa := range tsas {
		for _, signer := range tsa.Signers {
			if !identifies(signer) {
				lastErr = errors.New("the token's signing-certificate attribute names none of the trusted certificates")
				continue
			}
			if err := checkTSACertificate(signer); err != nil {
				return nil, err
			}
			p7, err := pkcs7.Parse(resp.Token.FullBytes)
			if err != nil {
				return nil, fmt.Errorf("time-stamp token: %w", err)
			}
			p7.Certificates = []*x509.Certificate{signer} // only the TSA's own certificates count
			roots, inter := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(tsa.Root)
			for _, c := range tsa.Intermediates {
				inter.AddCert(c)
			}
			opts := func(at time.Time) x509.VerifyOptions {
				return x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
			}
			if err := p7.VerifyWithOpts(opts(parsed.Time)); err != nil {
				lastErr = err
				continue
			}
			if _, err := signer.Verify(opts(now)); err != nil {
				return nil, fmt.Errorf("time-stamp authority %s's certificates aren't valid now: %w", tsa.Name, err)
			}
			return &timestampResult{Time: parsed.Time, Upper: parsed.Time.Add(max(acc, time.Second)), TSA: tsa.Name}, nil
		}
	}
	return nil, fmt.Errorf("time-stamp not signed by a trusted authority: %v", lastErr)
}

func mustUnmarshal(raw []byte, v any) error {
	rest, err := asn1.Unmarshal(raw, v)
	if err == nil && len(rest) > 0 {
		err = errors.New("trailing data")
	}
	return err
}

func digest(alg asn1.ObjectIdentifier, data []byte) []byte {
	h := map[string]crypto.Hash{oidSHA256.String(): crypto.SHA256, oidSHA384.String(): crypto.SHA384,
		oidSHA512.String(): crypto.SHA512}[alg.String()]
	if !h.Available() {
		return nil
	}
	w := h.New()
	w.Write(data)
	return w.Sum(nil)
}

// essIdentifier reads the ESS signing-certificate(-v2) attribute, returning whether a certificate is the one it
// names. The v1 hash is SHA-1; it only identifies a pinned certificate.
func essIdentifier(attr func(asn1.ObjectIdentifier) ([]byte, bool)) (func(*x509.Certificate) bool, error) {
	if raw, ok := attr(oidAttrSigningCertV2); ok {
		var sc struct {
			Certs    []asn1.RawValue
			Policies asn1.RawValue `asn1:"optional"`
		}
		if mustUnmarshal(raw, &sc) != nil || len(sc.Certs) == 0 {
			return nil, errors.New("time-stamp's signing-certificate-v2 attribute is malformed")
		}
		var fields []asn1.RawValue
		if mustUnmarshal(sc.Certs[0].FullBytes, &fields) != nil || len(fields) == 0 {
			return nil, errors.New("time-stamp's ESSCertIDv2 is malformed")
		}
		alg := oidSHA256
		if fields[0].Tag == asn1.TagSequence { // hashAlgorithm, when not the default
			var ai pkix.AlgorithmIdentifier
			if mustUnmarshal(fields[0].FullBytes, &ai) != nil {
				return nil, errors.New("time-stamp's ESSCertIDv2 is malformed")
			}
			alg, fields = ai.Algorithm, fields[1:]
		}
		var hash []byte
		if len(fields) == 0 || mustUnmarshal(fields[0].FullBytes, &hash) != nil {
			return nil, errors.New("time-stamp's ESSCertIDv2 is malformed")
		}
		return func(c *x509.Certificate) bool { return bytes.Equal(digest(alg, c.Raw), hash) }, nil
	}
	if raw, ok := attr(oidAttrSigningCert); ok {
		var sc struct {
			Certs []struct {
				CertHash     []byte
				IssuerSerial asn1.RawValue `asn1:"optional"`
			}
			Policies asn1.RawValue `asn1:"optional"`
		}
		if mustUnmarshal(raw, &sc) != nil || len(sc.Certs) == 0 {
			return nil, errors.New("time-stamp's signing-certificate attribute is malformed")
		}
		return func(c *x509.Certificate) bool {
			h := sha1.Sum(c.Raw)
			return bytes.Equal(h[:], sc.Certs[0].CertHash)
		}, nil
	}
	return nil, errors.New("time-stamp has no signing-certificate attribute")
}

// checkTSACertificate: the extended key usage is critical and exactly id-kp-timeStamping.
func checkTSACertificate(c *x509.Certificate) error {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtKeyUsage) && e.Critical && len(c.UnknownExtKeyUsage) == 0 &&
			slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}) {
			return nil
		}
	}
	return fmt.Errorf("TSA certificate %s isn't restricted to time-stamping (critical extended key usage)", c.Subject)
}
