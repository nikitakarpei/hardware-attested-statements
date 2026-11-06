package awsnitro

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

//go:embed data
var data embed.FS

// rootFingerprint is the SHA-256 of AWS_NitroEnclaves_Root-G1 (spec: profiles/awsnitro.md, appendix).
const rootFingerprint = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

// Trust is what the profile relies on besides its settings: the roots attestation documents must start at.
type Trust struct {
	Roots []*x509.Certificate
}

// AWSRoot returns the AWS Nitro Enclaves root, as pinned in the binary.
func AWSRoot() (*x509.Certificate, error) {
	raw, err := data.ReadFile("data/aws-nitro-enclaves-root-g1.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("the AWS Nitro Enclaves root isn't PEM")
	}
	if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != rootFingerprint {
		return nil, fmt.Errorf("the AWS Nitro Enclaves root doesn't match its pinned fingerprint")
	}
	return x509.ParseCertificate(block.Bytes)
}

// DefaultTrust trusts AWS's root only.
func DefaultTrust() (*Trust, error) {
	root, err := AWSRoot()
	if err != nil {
		return nil, err
	}
	return &Trust{Roots: []*x509.Certificate{root}}, nil
}
