package verifier

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// DrandChain is a drand randomness beacon: one publicly verifiable random value every Period.
// https://docs.drand.love/docs/specification/
type DrandChain struct {
	Hash      string
	PublicKey []byte // on G2, compressed
	Genesis   time.Time
	Period    time.Duration
}

// The domain separation tag of drand's bls-unchained-g1-rfc9380 scheme.
const drandDST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

// DrandQuicknet returns the League of Entropy's quicknet chain (3-second rounds), as pinned in the binary.
func DrandQuicknet() (DrandChain, error) {
	raw, err := data.ReadFile("data/drand-quicknet.json")
	if err != nil {
		return DrandChain{}, err
	}
	var info struct {
		PublicKey string `json:"public_key"`
		Period    int64  `json:"period"`
		Genesis   int64  `json:"genesis_time"`
		Hash      string `json:"hash"`
		Scheme    string `json:"schemeID"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return DrandChain{}, err
	}
	if info.Scheme != "bls-unchained-g1-rfc9380" {
		return DrandChain{}, fmt.Errorf("drand scheme %s is not supported", info.Scheme)
	}
	pk, err := hex.DecodeString(info.PublicKey)
	if err != nil {
		return DrandChain{}, err
	}
	return DrandChain{Hash: info.Hash, PublicKey: pk, Genesis: time.Unix(info.Genesis, 0).UTC(),
		Period: time.Duration(info.Period) * time.Second}, nil
}

// RoundTime is when round becomes known; nobody can know its value earlier.
func (c DrandChain) RoundTime(round uint64) time.Time {
	return c.Genesis.Add(time.Duration(round-1) * c.Period)
}

// Verify checks round's signature: BLS on G1 over SHA-256(round as 8 big-endian bytes).
func (c DrandChain) Verify(round uint64, signature []byte) error {
	if round == 0 {
		return errors.New("drand round 0 doesn't exist")
	}
	var sig bls12381.G1
	if err := sig.SetBytes(signature); err != nil || !sig.IsOnG1() {
		return errors.New("drand signature is not a valid point")
	}
	var pk bls12381.G2
	if err := pk.SetBytes(c.PublicKey); err != nil || !pk.IsOnG2() {
		return errors.New("drand public key is not a valid point")
	}
	msg := sha256.Sum256(binary.BigEndian.AppendUint64(nil, round))
	var h bls12381.G1
	h.Hash(msg[:], []byte(drandDST))
	// e(sig, g2) == e(H(m), pk)  ⇔  e(sig, g2) · e(H(m), pk)⁻¹ == 1
	if !bls12381.ProdPairFrac([]*bls12381.G1{&sig, &h}, []*bls12381.G2{bls12381.G2Generator(), &pk}, []int{1, -1}).IsIdentity() {
		return errors.New("drand signature is invalid")
	}
	return nil
}
