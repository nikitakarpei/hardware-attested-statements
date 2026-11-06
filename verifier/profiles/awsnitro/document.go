package awsnitro

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"time"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
)

// coseSign1 is an attestation document's COSE_Sign1 structure (RFC 9052), as the NSM makes it.
type coseSign1 struct {
	protected []byte
	payload   []byte // the attestation document
	signature []byte
}

// protectedES384 is the only protected header accepted: {1: -35}, algorithm ES384.
var protectedES384 = []byte{0xa1, 0x01, 0x38, 0x22}

// parseCOSE checks the structure (verification step 1, and step 2 for the structure itself).
func parseCOSE(raw []byte) (*coseSign1, error) {
	it, err := decodeCBOR(raw, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCBOR, err)
	}
	if it.kind != kindArray || len(it.items) != 4 {
		return nil, fmt.Errorf("%w: not an untagged array of four items", ErrCOSE)
	}
	protected, unprotected, payload, signature := it.items[0], it.items[1], it.items[2], it.items[3]
	switch {
	case protected.kind != kindBytes || !bytes.Equal(protected.bytes, protectedES384):
		return nil, fmt.Errorf("%w: the protected header isn't {1: -35} (ES384)", ErrCOSE)
	case unprotected.kind != kindMap || len(unprotected.items) != 0:
		return nil, fmt.Errorf("%w: the unprotected header isn't an empty map", ErrCOSE)
	case payload.kind != kindBytes:
		return nil, fmt.Errorf("%w: the payload isn't a byte string", ErrCOSE)
	case signature.kind != kindBytes || len(signature.bytes) != 96:
		return nil, fmt.Errorf("%w: the signature isn't 96 bytes", ErrCOSE)
	}
	return &coseSign1{protected: protected.bytes, payload: payload.bytes, signature: signature.bytes}, nil
}

// verify checks the signature (verification step 5): ECDSA P-384 with SHA-384 over the COSE Sig_structure,
// r ‖ s. A high s is accepted: the NSM produces them.
func (c *coseSign1) verify(pub *ecdsa.PublicKey) error {
	digest := sha512.Sum384(sigStructure(c.protected, c.payload))
	r := new(big.Int).SetBytes(c.signature[:48])
	s := new(big.Int).SetBytes(c.signature[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("%w: the document's signature is invalid", ErrSignature)
	}
	return nil
}

// sigStructure is ["Signature1", protected, h”, payload] (RFC 9052 section 4.4).
func sigStructure(protected, payload []byte) []byte {
	b := append([]byte{0x84}, appendHead(nil, 3, uint64(len("Signature1")))...)
	b = append(b, "Signature1"...)
	b = append(appendHead(b, 2, uint64(len(protected))), protected...)
	b = appendHead(b, 2, 0)
	return append(appendHead(b, 2, uint64(len(payload))), payload...)
}

// appendHead appends a CBOR head of major type major and argument n, in shortest form.
func appendHead(b []byte, major byte, n uint64) []byte {
	switch {
	case n < 24:
		return append(b, major<<5|byte(n))
	case n < 1<<8:
		return append(b, major<<5|24, byte(n))
	case n < 1<<16:
		return binary.BigEndian.AppendUint16(append(b, major<<5|25), uint16(n))
	case n < 1<<32:
		return binary.BigEndian.AppendUint32(append(b, major<<5|26), uint32(n))
	}
	return binary.BigEndian.AppendUint64(append(b, major<<5|27), n)
}

// document is an enclave's attestation document (the COSE payload).
type document struct {
	moduleID    string
	timestamp   time.Time
	pcrs        map[int][]byte
	certificate []byte
	cabundle    [][]byte // from the root down
	// publicKey, userData and nonce are nil if null.
	publicKey, userData, nonce []byte
}

// moduleIDPattern is an enclave's module ID; a NitroTPM document's has -tpm instead of -enc.
var moduleIDPattern = regexp.MustCompile(`^i-[0-9a-f]{8,17}-enc[0-9a-f]{16}$`)

// parseDocument checks the document (verification step 2 for the payload, and step 3).
func parseDocument(payload []byte) (*document, error) {
	it, err := decodeCBOR(payload, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCBOR, err)
	}
	if it.kind != kindMap {
		return nil, fmt.Errorf("%w: not a map", ErrDocument)
	}
	d := &document{}
	members := map[string]item{}
	for i := 0; i < len(it.items); i += 2 {
		key := it.items[i]
		if key.kind != kindText {
			return nil, fmt.Errorf("%w: a key that isn't text", ErrDocument)
		}
		name := key.text()
		if !slices.Contains(documentKeys, name) { // NitroTPM documents have nitrotpm_pcrs instead of pcrs
			return nil, fmt.Errorf("%w: unknown key %q", ErrDocument, name)
		}
		members[name] = it.items[i+1]
	}
	for _, name := range documentKeys {
		if _, ok := members[name]; !ok {
			return nil, fmt.Errorf("%w: no %s", ErrDocument, name)
		}
	}
	want := func(name string, k kind) (item, error) {
		v := members[name]
		if v.kind != k {
			return item{}, fmt.Errorf("%w: %s is %v, not %v", ErrDocument, name, v.kind, k)
		}
		return v, nil
	}
	optional := func(name string) ([]byte, error) {
		v := members[name]
		switch v.kind {
		case kindNull:
			return nil, nil
		case kindBytes:
			return v.bytes, nil
		}
		return nil, fmt.Errorf("%w: %s is %v, not a byte string or null", ErrDocument, name, v.kind)
	}

	v, err := want("module_id", kindText)
	if err != nil {
		return nil, err
	}
	if d.moduleID = v.text(); !moduleIDPattern.MatchString(d.moduleID) {
		return nil, fmt.Errorf("%w: module_id %q isn't an enclave's", ErrDocument, d.moduleID)
	}
	if v, err = want("timestamp", kindUnsigned); err != nil {
		return nil, err
	}
	if v.value == 0 || v.value > 1<<53 {
		return nil, fmt.Errorf("%w: timestamp %d is out of range", ErrDocument, v.value)
	}
	d.timestamp = time.UnixMilli(int64(v.value)).UTC()
	if v, err = want("digest", kindText); err != nil {
		return nil, err
	}
	if v.text() != "SHA384" {
		return nil, fmt.Errorf("%w: digest %q isn't SHA384", ErrDocument, v.text())
	}
	if v, err = want("pcrs", kindMap); err != nil {
		return nil, err
	}
	if n := len(v.items) / 2; n < 1 || n > 32 {
		return nil, fmt.Errorf("%w: %d PCRs", ErrDocument, n)
	}
	d.pcrs = map[int][]byte{}
	for i := 0; i < len(v.items); i += 2 {
		index, value := v.items[i], v.items[i+1]
		if index.kind != kindUnsigned || index.value > 31 || value.kind != kindBytes || len(value.bytes) != 48 {
			return nil, fmt.Errorf("%w: a PCR that isn't an index 0–31 and 48 bytes", ErrDocument)
		}
		d.pcrs[int(index.value)] = value.bytes
	}
	if v, err = want("certificate", kindBytes); err != nil {
		return nil, err
	}
	d.certificate = v.bytes
	if v, err = want("cabundle", kindArray); err != nil {
		return nil, err
	}
	if len(v.items) == 0 {
		return nil, fmt.Errorf("%w: an empty cabundle", ErrDocument)
	}
	for _, c := range v.items {
		if c.kind != kindBytes {
			return nil, fmt.Errorf("%w: a cabundle element that isn't a byte string", ErrDocument)
		}
		d.cabundle = append(d.cabundle, c.bytes)
	}
	if d.publicKey, err = optional("public_key"); err != nil {
		return nil, err
	}
	if d.userData, err = optional("user_data"); err != nil {
		return nil, err
	}
	if d.nonce, err = optional("nonce"); err != nil {
		return nil, err
	}
	return d, nil
}

var documentKeys = []string{"module_id", "timestamp", "digest", "pcrs", "certificate", "cabundle", "public_key",
	"user_data", "nonce"}

// checkKey checks the attested key (verification step 6): a P-256 key, created no earlier than round, which
// user_data commits to. It returns the key and the round's time.
func (d *document) checkKey(round verifier.DrandRound, kc verifier.KeyContext) (*ecdsa.PublicKey, time.Time, error) {
	if d.publicKey == nil {
		return nil, time.Time{}, fmt.Errorf("%w: no public_key", ErrKey)
	}
	pub, err := parseP256(d.publicKey)
	if err != nil {
		return nil, time.Time{}, err
	}
	if d.nonce != nil {
		return nil, time.Time{}, fmt.Errorf("%w: the document has a nonce", ErrKey)
	}
	created, err := kc.VerifyRound(round)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: keyStartedAfter: %v", ErrKey, err)
	}
	want, err := UserData(round)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: %v", ErrKey, err)
	}
	if !bytes.Equal(d.userData, want) {
		return nil, time.Time{}, fmt.Errorf("%w: user_data doesn't commit to this profile, its version and the key's round", ErrKey)
	}
	return pub, created, nil
}

// parseP256 reads a SubjectPublicKeyInfo of a P-256 key. Go's parser takes only DER, named curves and
// uncompressed points.
func parseP256(spki []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("%w: public_key: %v", ErrKey, err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: public_key isn't a P-256 key", ErrKey)
	}
	return pub, nil
}

// UserData is the user_data a program asks the NSM to attest with its key (spec: profiles/awsnitro.md, Key):
// SHA-256 of the key challenge, the drand chain hash, the round (8 bytes, big-endian) and the round's signature.
func UserData(round verifier.DrandRound) ([]byte, error) {
	chain, err := hex.DecodeString(round.Chain)
	if err != nil || len(chain) != 32 {
		return nil, fmt.Errorf("drand chain hash %q isn't 32 bytes of hex", round.Chain)
	}
	signature, err := hex.DecodeString(round.Signature)
	if err != nil {
		return nil, fmt.Errorf("drand signature isn't hex")
	}
	h := sha256.New()
	h.Write([]byte(KeyChallenge))
	h.Write(chain)
	h.Write(binary.BigEndian.AppendUint64(nil, round.Round))
	h.Write(signature)
	return h.Sum(nil), nil
}

// checkNotDebug checks the enclave wasn't run in debug mode (verification step 7), which makes PCR0, PCR1 and
// PCR2 zero.
func (d *document) checkNotDebug() error {
	for _, i := range []int{0, 1, 2} {
		v, ok := d.pcrs[i]
		if !ok {
			return fmt.Errorf("%w: no PCR%d", ErrDebug, i)
		}
		if bytes.Equal(v, make([]byte, 48)) {
			return fmt.Errorf("%w: PCR%d is zero: the enclave runs in debug mode", ErrDebug, i)
		}
	}
	return nil
}
