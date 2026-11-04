package verifier

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	BundleMediaType  = "application/vnd.hardware-attested-statement.bundle.v0.1+json"
	InTotoPayload    = "application/vnd.in-toto+json"
	InTotoStatement1 = "https://in-toto.io/Statement/v1"
	SignedIDPrefix   = "hardware-attested-statement/v0.1/signed"
	HTTPVersion      = "v0.1"
	MaxJSONInteger   = 1<<53 - 1
	maxNesting       = 32
)

// strict is how bundles, key evidence and policies are read: names are case-sensitive (json/v2's default), and
// duplicate or unknown members are errors.
var strict = json.RejectUnknownMembers(true)

// UnmarshalStrict reads JSON as the spec requires for bundles, key evidence and policies (section 0).
func UnmarshalStrict(raw []byte, v any) error { return json.Unmarshal(raw, v, strict) }

// Bundle is a signed statement with the evidence to verify it (spec section 2).
type Bundle struct {
	MediaType            string               `json:"mediaType"`
	DSSEEnvelope         DSSEEnvelope         `json:"dsseEnvelope"`
	VerificationMaterial VerificationMaterial `json:"verificationMaterial"`
}

type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     Bytes           `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

type DSSESignature struct {
	KeyID *string `json:"keyid,omitzero"` // must be absent
	Sig   Bytes   `json:"sig"`
}

type VerificationMaterial struct {
	Key          KeyEvidence `json:"key"`
	Timestamp    *Timestamp  `json:"timestamp,omitzero"`
	InputBundles []*Bundle   `json:"inputBundles,omitzero"`
}

// KeyEvidence is a profile's evidence for the signing key (spec section 3): a JSON object whose "profile" names
// the profile that defines the rest. The profile reads Raw strictly.
type KeyEvidence struct {
	Profile string
	Raw     jsontext.Value
}

func (k KeyEvidence) MarshalJSON() ([]byte, error) { return k.Raw, nil }

func (k *KeyEvidence) UnmarshalJSON(raw []byte) error {
	var head struct {
		Profile string `json:"profile"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return fmt.Errorf("key: %w", err)
	}
	if head.Profile == "" {
		return errors.New("key: no profile")
	}
	k.Profile, k.Raw = head.Profile, append(jsontext.Value{}, raw...)
	return nil
}

// Timestamp is an RFC 3161 time-stamp over the root of a Merkle tree of signed-statement IDs; Tree proves this
// bundle's is one of them (spec section 2).
type Timestamp struct {
	Token Bytes `json:"token"`
	Tree  Tree  `json:"tree"`
}

type Tree struct {
	Size  uint64  `json:"size"`
	Index uint64  `json:"index"`
	Path  []Bytes `json:"path"`
}

// Bytes is base64 in JSON: RFC 4648 section 4, with padding.
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

func (b *Bytes) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	d, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return errors.New("invalid base64 (standard alphabet, with padding)")
	}
	*b = d
	return nil
}

// ParseBundle reads a bundle from JSON.
func ParseBundle(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := UnmarshalStrict(raw, &b); err != nil {
		return nil, err
	}
	if err := b.checkShape(0); err != nil {
		return nil, err
	}
	return &b, nil
}

func (b *Bundle) checkShape(depth int) error {
	if depth > maxNesting {
		return errors.New("bundles nested too deeply")
	}
	if b.MediaType != BundleMediaType {
		return fmt.Errorf("not a bundle of this version (mediaType %q)", b.MediaType)
	}
	if t := b.VerificationMaterial.Timestamp; t != nil && (t.Tree.Size > MaxJSONInteger || t.Tree.Index > MaxJSONInteger) {
		return errors.New("time-stamp tree: number out of range")
	}
	for _, in := range b.VerificationMaterial.InputBundles {
		if in == nil {
			return errors.New("null input bundle")
		}
		if err := in.checkShape(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

// Statement is an in-toto Statement v1.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     jsontext.Value       `json:"predicate,omitzero"`
}

// ResourceDescriptor is in-toto's; fields this verifier doesn't use are left out.
type ResourceDescriptor struct {
	Name        string            `json:"name,omitzero"`
	URI         string            `json:"uri,omitzero"`
	Digest      map[string]string `json:"digest,omitzero"`
	MediaType   *string           `json:"mediaType,omitzero"`
	Annotations struct {
		SignedStatementID string  `json:"signedStatementId,omitzero"`
		ContentEncoding   *string `json:"contentEncoding,omitzero"`
	} `json:"annotations,omitzero"`
}

// Member names this spec and in-toto define, by kind of object, and the kinds of their values (spec section 0).
var knownMembers = map[string]map[string]string{
	"statement": {"_type": "", "subject": "descriptor", "predicateType": "", "predicate": "predicate"},
	"descriptor": {"name": "", "uri": "", "digest": "digest", "content": "", "downloadLocation": "", "mediaType": "",
		"annotations": "annotations"},
	"digest":       {"sha256": ""},
	"annotations":  {"signedStatementId": "", "contentEncoding": ""},
	"predicate":    {"inputs": "descriptor", "startedAfter": "startedAfter"},
	"startedAfter": {"drand": "drand"},
	"drand":        {"chain": "", "round": "", "signature": ""},
}

// checkNames rejects, in a statement's defined objects, a member whose name equals a defined one under Unicode
// simple case folding but not exactly, and a defined member whose value is null.
func checkNames(raw jsontext.Value, kind string) error {
	switch raw.Kind() {
	case '[':
		var items []jsontext.Value
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for _, it := range items {
			if err := checkNames(it, kind); err != nil {
				return err
			}
		}
		return nil
	case '{':
	default:
		return nil
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(raw, &members); err != nil {
		return err
	}
	known := knownMembers[kind]
	for name, v := range members {
		child, ok := known[name]
		if !ok {
			for k := range known {
				if strings.EqualFold(name, k) {
					return fmt.Errorf("member %q differs from %q only in case", name, k)
				}
			}
			continue
		}
		if v.Kind() == 'n' {
			return fmt.Errorf("member %q is null", name)
		}
		if child != "" {
			if err := checkNames(v, child); err != nil {
				return err
			}
		}
	}
	return nil
}

// ParseStatement reads an in-toto Statement v1. Names are case-sensitive and duplicates are rejected; unknown
// members are ignored, as in-toto requires, except case variants of defined ones.
func ParseStatement(raw []byte) (*Statement, error) {
	if err := checkNames(raw, "statement"); err != nil {
		return nil, fmt.Errorf("statement: %w", err)
	}
	var s Statement
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Type != InTotoStatement1 {
		return nil, fmt.Errorf("not an in-toto Statement v1 (_type %q)", s.Type)
	}
	if len(s.Subject) == 0 {
		return nil, errors.New("statement has no subject")
	}
	for _, sub := range s.Subject {
		if !isSHA256(sub.Digest["sha256"]) {
			return nil, errors.New("every subject needs a sha256 digest (lowercase hex)")
		}
	}
	if s.PredicateType == "" {
		return nil, errors.New("statement has no predicateType")
	}
	return &s, nil
}

// Inputs returns the statements this one lists as inputs (predicate.inputs, spec section 1).
func (s *Statement) Inputs() ([]ResourceDescriptor, error) {
	if len(s.Predicate) == 0 {
		return nil, nil
	}
	var p struct {
		Inputs []ResourceDescriptor `json:"inputs"`
	}
	if err := json.Unmarshal(s.Predicate, &p); err != nil {
		return nil, fmt.Errorf("predicate: %w", err)
	}
	for _, in := range p.Inputs {
		if in.MediaType == nil || *in.MediaType != InTotoPayload || !isSHA256(in.Digest["sha256"]) ||
			!isSHA256(in.Annotations.SignedStatementID) {
			return nil, errors.New("every input needs mediaType " + InTotoPayload +
				", a sha256 digest and a signedStatementId annotation (lowercase hex)")
		}
	}
	return p.Inputs, nil
}

// StartedAfter is a value nobody could know before a known time, included in the statement to bound it from
// below (spec section 1).
type StartedAfter struct {
	Drand *DrandRound `json:"drand"`
}

type DrandRound struct {
	Chain     string `json:"chain"`
	Round     uint64 `json:"round"`
	Signature string `json:"signature"`
}

// StartedAfter returns predicate.startedAfter, if present.
func (s *Statement) StartedAfter() (*StartedAfter, error) {
	if len(s.Predicate) == 0 {
		return nil, nil
	}
	var p struct {
		StartedAfter *StartedAfter `json:"startedAfter"`
	}
	if err := json.Unmarshal(s.Predicate, &p); err != nil {
		return nil, fmt.Errorf("predicate: %w", err)
	}
	if p.StartedAfter == nil {
		return nil, nil
	}
	d := p.StartedAfter.Drand
	if d == nil {
		return nil, errors.New("startedAfter: no supported value (drand)")
	}
	if !isSHA256(d.Chain) || d.Round == 0 || d.Round > MaxJSONInteger || !isLowerHex(d.Signature, 48) {
		return nil, errors.New("startedAfter: malformed drand round")
	}
	return p.StartedAfter, nil
}

// SubjectDigest returns the sha256 digest (hex) of the subject with the given name.
func (s *Statement) SubjectDigest(name string) (string, bool) {
	for _, sub := range s.Subject {
		if sub.Name == name {
			return sub.Digest["sha256"], true
		}
	}
	return "", false
}

// StatementID is SHA-256 of the statement's bytes.
func StatementID(statement []byte) [32]byte { return sha256.Sum256(statement) }

// SignedStatementID binds a statement, the profile and key binding (the evidence naming the key and its signer)
// and the signature (spec section 2): the leaf of a time-stamp tree, and what input links name.
func SignedStatementID(profile string, statementID [32]byte, binding, signature []byte) [32]byte {
	bindingHash := sha256.Sum256(binding)
	return sha256.Sum256(bytes.Join([][]byte{[]byte(SignedIDPrefix), {byte(len(profile))}, []byte(profile),
		statementID[:], bindingHash[:], signature}, nil))
}

// PAE is DSSE's pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func isSHA256(h string) bool { return isLowerHex(h, 32) }

func isLowerHex(h string, n int) bool {
	b, err := hex.DecodeString(h)
	return err == nil && len(b) == n && strings.ToLower(h) == h
}

// HTTPResponse is a saved HTTP response (curl -i … > file).
type HTTPResponse struct {
	StatusLine string
	Status     int
	Headers    [][2]string // as received, in order
	Body       []byte
}

// Header returns the values of every field line named name (compared case-insensitively).
func (r *HTTPResponse) Header(name string) []string {
	var out []string
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			out = append(out, h[1])
		}
	}
	return out
}

var statusLine = regexp.MustCompile(`^(HTTP/1\.1|HTTP/2|HTTP/3) ([2-5][0-9][0-9])(?: [\t\x20-\x7e\x80-\xff]*)?$`)

const tokenChars = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// ParseHTTPResponse reads a saved HTTP response strictly (spec section 6), and the bundle carried in its
// Attested-* headers.
func ParseHTTPResponse(raw []byte) (*HTTPResponse, *Bundle, error) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, nil, errors.New("not a saved HTTP response (save it with curl -i … > file)")
	}
	head := string(raw[:end])
	for i := 0; i < len(head); i++ {
		if (head[i] == '\n' && (i == 0 || head[i-1] != '\r')) || (head[i] == '\r' && (i+1 >= len(head) || head[i+1] != '\n')) {
			return nil, nil, errors.New("a line doesn't end in CRLF")
		}
	}
	lines := strings.Split(head, "\r\n")
	m := statusLine.FindStringSubmatch(lines[0])
	if m == nil {
		return nil, nil, fmt.Errorf("bad status line %q", lines[0])
	}
	r := &HTTPResponse{StatusLine: lines[0], Body: raw[end+4:]}
	r.Status, _ = strconv.Atoi(m[2])
	attested := map[string]string{}
	for _, l := range lines[1:] {
		name, value, ok := strings.Cut(l, ":")
		if !ok || name == "" || strings.Trim(name, tokenChars) != "" {
			return nil, nil, fmt.Errorf("bad header line %q", l)
		}
		for _, c := range []byte(value) {
			if (c < 0x20 && c != '\t') || c == 0x7f {
				return nil, nil, fmt.Errorf("control character in header %s", name)
			}
		}
		value = strings.Trim(value, " \t")
		r.Headers = append(r.Headers, [2]string{name, value})
		if n := strings.ToLower(name); strings.HasPrefix(n, "attested-") {
			if _, dup := attested[n]; dup {
				return nil, nil, fmt.Errorf("%s appears twice: refusing an ambiguous response", name)
			}
			attested[n] = value
		}
	}
	if len(r.Header("Transfer-Encoding")) > 0 {
		return nil, nil, errors.New("a saved response must not have Transfer-Encoding")
	}
	switch cl := r.Header("Content-Length"); len(cl) {
	case 0:
	case 1:
		if n, err := strconv.ParseUint(cl[0], 10, 63); err != nil || strings.Trim(cl[0], "0123456789") != "" || n != uint64(len(r.Body)) {
			return nil, nil, errors.New("Content-Length doesn't equal the body's length")
		}
	default:
		return nil, nil, errors.New("Content-Length appears twice")
	}
	if len(attested) == 0 {
		return r, nil, errors.New("no Attested-* headers: this response carries no bundle")
	}
	if v := attested["attested-version"]; v != HTTPVersion {
		return nil, nil, fmt.Errorf("Attested-Version is %q, not %s", v, HTTPVersion)
	}
	one := func(name string) ([]byte, error) {
		v, ok := attested[name]
		if !ok {
			return nil, fmt.Errorf("no %s header", name)
		}
		b, err := sfBytes(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return b, nil
	}
	statement, err := one("attested-statement")
	if err != nil {
		return nil, nil, err
	}
	sig, err := one("attested-signature")
	if err != nil {
		return nil, nil, err
	}
	key, err := one("attested-key")
	if err != nil {
		return nil, nil, err
	}
	b := &Bundle{MediaType: BundleMediaType,
		DSSEEnvelope: DSSEEnvelope{PayloadType: InTotoPayload, Payload: statement, Signatures: []DSSESignature{{Sig: sig}}}}
	if err := json.Unmarshal(key, &b.VerificationMaterial.Key); err != nil {
		return nil, nil, fmt.Errorf("attested-key: %w", err)
	}
	_, hasToken := attested["attested-timestamp"]
	_, hasTree := attested["attested-timestamp-tree"]
	if hasToken != hasTree {
		return nil, nil, errors.New("Attested-Timestamp and Attested-Timestamp-Tree must appear together")
	}
	if hasToken {
		token, err := one("attested-timestamp")
		if err != nil {
			return nil, nil, err
		}
		tree, err := parseTreeHeader(attested["attested-timestamp-tree"])
		if err != nil {
			return nil, nil, fmt.Errorf("attested-timestamp-tree: %w", err)
		}
		b.VerificationMaterial.Timestamp = &Timestamp{Token: token, Tree: tree}
	}
	return r, b, nil
}

// CheckHTTPBody checks the HTTP binding (spec section 6): the response's body, Content-Type and
// Content-Encoding are the statement's one "body" subject.
func CheckHTTPBody(st *Statement, r *HTTPResponse) error {
	var body *ResourceDescriptor
	for i, sub := range st.Subject {
		if sub.Name == "body" {
			if body != nil {
				return errors.New(`the statement has two "body" subjects`)
			}
			body = &st.Subject[i]
		}
	}
	if body == nil {
		return errors.New(`the statement has no "body" subject`)
	}
	sum := sha256.Sum256(r.Body)
	if body.Digest["sha256"] != hex.EncodeToString(sum[:]) {
		return errors.New("the body doesn't match the signed digest")
	}
	for alg, d := range body.Digest {
		if h, ok := map[string]crypto.Hash{"sha384": crypto.SHA384, "sha512": crypto.SHA512}[alg]; ok {
			w := h.New()
			w.Write(r.Body)
			if hex.EncodeToString(w.Sum(nil)) != d {
				return fmt.Errorf("the body doesn't match the signed %s digest", alg)
			}
		}
	}
	same := func(field string, signed *string) error {
		got := r.Header(field)
		switch {
		case len(got) > 1:
			return fmt.Errorf("%s appears more than once", field)
		case len(got) == 0 && signed == nil:
			return nil
		case len(got) == 1 && signed != nil && got[0] == strings.Trim(*signed, " \t"):
			return nil
		}
		return fmt.Errorf("%s differs from the signed one", field)
	}
	if err := same("Content-Type", body.MediaType); err != nil {
		return err
	}
	return same("Content-Encoding", body.Annotations.ContentEncoding)
}

// sfBytes reads exactly one RFC 9651 byte sequence: ":base64:".
func sfBytes(v string) ([]byte, error) {
	if len(v) < 2 || v[0] != ':' || v[len(v)-1] != ':' || strings.ContainsAny(v[1:len(v)-1], ":,; ") {
		return nil, errors.New("not exactly one byte sequence")
	}
	return base64.StdEncoding.Strict().DecodeString(v[1 : len(v)-1])
}

// parseTreeHeader reads the RFC 9651 dictionary "size=N, index=I, path=(:h1: :h2: …)".
func parseTreeHeader(v string) (Tree, error) {
	var t Tree
	seen := map[string]bool{}
	for _, member := range strings.Split(v, ",") {
		k, val, ok := strings.Cut(strings.TrimSpace(member), "=")
		if !ok || seen[k] {
			return t, fmt.Errorf("bad member %q", member)
		}
		seen[k] = true
		var err error
		switch k {
		case "size":
			t.Size, err = strconv.ParseUint(val, 10, 53)
		case "index":
			t.Index, err = strconv.ParseUint(val, 10, 53)
		case "path":
			if len(val) < 2 || val[0] != '(' || val[len(val)-1] != ')' {
				return t, errors.New("path is not an inner list")
			}
			for _, item := range strings.Fields(val[1 : len(val)-1]) {
				h, err := sfBytes(item)
				if err != nil {
					return t, err
				}
				t.Path = append(t.Path, h)
			}
		default:
			return t, fmt.Errorf("unknown member %q", k)
		}
		if err != nil {
			return t, err
		}
	}
	if !seen["size"] || !seen["index"] || !seen["path"] {
		return t, errors.New("needs size, index and path")
	}
	return t, nil
}
