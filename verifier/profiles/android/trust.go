package android

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	RevocationURL        = "https://android.googleapis.com/attestation/status"
	GrapheneOSKeysURL    = "https://grapheneos.org/attestation.json"
	GrapheneOSKeysSigURL = "https://grapheneos.org/attestation.json.sig"
	// The signed timestamp of the GrapheneOS key list this verifier was built with: older lists are rejected.
	grapheneOSListBuiltWith = 1776709772
)

//go:embed data
var data embed.FS

// Trust is what the profile relies on besides its settings.
type Trust struct {
	Roots []*x509.Certificate
	// Revoked maps certificate serial numbers, as the list gives them (lowercase hex or decimal), to their status.
	Revoked map[string]string
	// RevocationProduced is when the revocation list was produced (spec section 3), or when its operator says.
	RevocationProduced time.Time
	// BootKeyLists are lists of alternative OS verified boot keys, by name.
	BootKeyLists map[string]*BootKeyList
}

// BootKeyList is a trusted list of verified boot keys (lowercase hex). Err says why it isn't available; it is
// needed only to check devices running such an OS.
type BootKeyList struct {
	Keys     map[string]bool
	Produced time.Time
	Err      error
}

// GoogleRoots returns Google's attestation roots, as pinned in the binary (spec: profiles/android.md, appendix).
func GoogleRoots() ([]*x509.Certificate, error) {
	raw, err := data.ReadFile("data/google-roots.json")
	if err != nil {
		return nil, err
	}
	var pems []string
	if err := json.Unmarshal(raw, &pems); err != nil {
		return nil, err
	}
	var roots []*x509.Certificate
	for _, p := range pems {
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			return nil, errors.New("google-roots.json: not PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		roots = append(roots, c)
	}
	return roots, nil
}

// LoadTrust builds the trust store from the pinned roots plus the current revocation list and GrapheneOS key list,
// fetched with client (nil: http.DefaultClient). The revocation list is required; if the GrapheneOS list can't be
// obtained, only devices running GrapheneOS are rejected.
func LoadTrust(ctx context.Context, client *http.Client) (*Trust, error) {
	if client == nil {
		client = http.DefaultClient
	}
	status, produced, err := fetch(ctx, client, RevocationURL)
	if err != nil {
		return nil, err
	}
	t, err := newTrust(status, produced)
	if err != nil {
		return nil, err
	}
	list, listProduced, err := fetch(ctx, client, GrapheneOSKeysURL)
	var sig []byte
	if err == nil {
		sig, _, err = fetch(ctx, client, GrapheneOSKeysSigURL)
	}
	if err == nil {
		t.BootKeyLists["grapheneos"], err = parseGrapheneOSList(list, sig, listProduced)
	}
	if err != nil {
		t.BootKeyLists["grapheneos"] = &BootKeyList{Err: fmt.Errorf("GrapheneOS key list: %w", err)}
	}
	return t, nil
}

// NewTrust builds the trust store from the pinned roots plus a revocation list and, optionally, a signed
// GrapheneOS key list (nil: not available), as published at RevocationURL, GrapheneOSKeysURL and
// GrapheneOSKeysSigURL, obtained at the time their operator states.
func NewTrust(revocationList, grapheneOSKeys, grapheneOSKeysSig []byte, obtained time.Time) (*Trust, error) {
	t, err := newTrust(revocationList, obtained)
	if err != nil {
		return nil, err
	}
	if grapheneOSKeys == nil {
		t.BootKeyLists["grapheneos"] = &BootKeyList{Err: errors.New("the GrapheneOS key list wasn't given")}
		return t, nil
	}
	l, err := parseGrapheneOSList(grapheneOSKeys, grapheneOSKeysSig, obtained)
	if err != nil {
		return nil, fmt.Errorf("GrapheneOS key list: %w", err)
	}
	t.BootKeyLists["grapheneos"] = l
	return t, nil
}

func newTrust(revocationList []byte, produced time.Time) (*Trust, error) {
	roots, err := GoogleRoots()
	if err != nil {
		return nil, err
	}
	revoked, err := parseRevocationList(revocationList)
	if err != nil {
		return nil, fmt.Errorf("revocation list: %w", err)
	}
	return &Trust{Roots: roots, Revoked: revoked, RevocationProduced: produced, BootKeyLists: map[string]*BootKeyList{}}, nil
}

func parseGrapheneOSList(list, sig []byte, produced time.Time) (*BootKeyList, error) {
	signers, err := data.ReadFile("data/grapheneos-allowed_signers")
	if err != nil {
		return nil, err
	}
	if err := verifySSHSignature(signers, "contact@grapheneos.org", "attestation keys", list, sig); err != nil {
		return nil, err
	}
	var l struct {
		VerifiedBootKeys []string `json:"verifiedBootKeys"`
		Timestamp        int64    `json:"timestamp"`
	}
	if err := json.Unmarshal(list, &l); err != nil {
		return nil, err
	}
	if l.Timestamp < grapheneOSListBuiltWith {
		return nil, fmt.Errorf("list of %v is older than the one this verifier was built with", time.Unix(l.Timestamp, 0).UTC())
	}
	keys := map[string]bool{}
	for _, k := range l.VerifiedBootKeys {
		if b, err := hex.DecodeString(k); err != nil || len(b) != 32 || strings.ToLower(k) != k {
			return nil, fmt.Errorf("boot key %q isn't 32 bytes of lowercase hex", k)
		}
		keys[k] = true
	}
	return &BootKeyList{Keys: keys, Produced: produced}, nil
}

func parseRevocationList(raw []byte) (map[string]string, error) {
	var list struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	if list.Entries == nil {
		return nil, errors.New("no entries")
	}
	revoked := map[string]string{}
	for serial, e := range list.Entries {
		if serial == "" || strings.Trim(serial, "0123456789abcdef") != "" {
			return nil, fmt.Errorf("entry %q is neither lowercase hex nor decimal", serial)
		}
		revoked[strings.TrimLeft(serial, "0")] = e.Status
	}
	return revoked, nil
}

// revoked tells whether a certificate's serial is on the list, written as hex or as decimal (Google documents hex,
// but most of its list is decimal).
func (t *Trust) revoked(serial *big.Int) (string, bool) {
	for _, s := range []string{serial.Text(16), serial.Text(10)} {
		if status, ok := t.Revoked[s]; ok {
			return status, true
		}
	}
	return "", false
}

// fetch gets url with caching disabled, and when the server produced it: the earlier of its Date and the time
// received minus its Age (spec section 3).
func fetch(ctx context.Context, client *http.Client, url string) ([]byte, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("User-Agent", "hardware-attested-statements-verifier")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	received := time.Now()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, time.Time{}, err
	}
	return body, produced(resp.Header, received), nil
}

func produced(h http.Header, received time.Time) time.Time {
	t := received
	if d, err := http.ParseTime(h.Get("Date")); err == nil && d.Before(t) {
		t = d
	}
	if age, err := strconv.ParseInt(h.Get("Age"), 10, 64); err == nil && age > 0 {
		if a := received.Add(-time.Duration(age) * time.Second); a.Before(t) {
			t = a
		}
	}
	return t
}

// verifySSHSignature checks an OpenSSH signature (ssh-keygen -Y sign) of message by principal's key from an
// allowed_signers file, in the given namespace: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
func verifySSHSignature(allowedSigners []byte, principal, namespace string, message, armored []byte) error {
	var key ssh.PublicKey
	for _, line := range strings.Split(string(allowedSigners), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == principal {
			k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(f[len(f)-2:], " ")))
			if err != nil {
				return err
			}
			key = k
		}
	}
	if key == nil {
		return fmt.Errorf("no key for %s", principal)
	}
	block, _ := pem.Decode(armored)
	if block == nil || block.Type != "SSH SIGNATURE" {
		return errors.New("not an SSH signature")
	}
	b := block.Bytes
	if !bytes.HasPrefix(b, []byte("SSHSIG")) || len(b) < 10 || binary.BigEndian.Uint32(b[6:10]) != 1 {
		return errors.New("not an SSHSIG version 1 signature")
	}
	b = b[10:]
	var fields [5][]byte // public key, namespace, reserved, hash algorithm, signature
	for i := range fields {
		if len(b) < 4 || uint64(len(b)-4) < uint64(binary.BigEndian.Uint32(b)) {
			return errors.New("truncated SSH signature")
		}
		n := binary.BigEndian.Uint32(b)
		fields[i], b = b[4:4+n], b[4+n:]
	}
	if !bytes.Equal(fields[0], key.Marshal()) {
		return errors.New("signed by a different key")
	}
	if string(fields[1]) != namespace {
		return fmt.Errorf("signature namespace is %q", fields[1])
	}
	var digest []byte
	switch string(fields[3]) {
	case "sha512":
		h := sha512.Sum512(message)
		digest = h[:]
	case "sha256":
		h := sha256.Sum256(message)
		digest = h[:]
	default:
		return fmt.Errorf("hash algorithm %q", fields[3])
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(fields[4], &sig); err != nil {
		return err
	}
	str := func(s []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...) }
	signed := append([]byte("SSHSIG"), str(fields[1])...)
	signed = append(signed, str(fields[2])...)
	signed = append(signed, str(fields[3])...)
	signed = append(signed, str(digest)...)
	return key.Verify(signed, &sig)
}
