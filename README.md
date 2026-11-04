# Hardware-Attested Statements

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/nikitakarpei/hardware-attested-statements/badge)](https://scorecard.dev/viewer/?uri=github.com/nikitakarpei/hardware-attested-statements)

A format for statements signed with a key that the signer's hardware generated and vouches for, and a verifier
for it. Draft (v0.1). Start with the [spec](spec/README.md); to verify statements, see the
[verifier](verifier/README.md).

## Install the verifier

Download your platform's file and `SHA256SUMS` from the [releases](https://github.com/nikitakarpei/hardware-attested-statements/releases), then:

```
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify <file> --repo nikitakarpei/hardware-attested-statements    # built by this repository's CI from the release's tag
```

Or build it: `cd verifier && go build ./cmd/attested-verify`. Release builds are reproducible with
`CGO_ENABLED=0 go build -trimpath -buildvcs=false` at the tag.

## More

[Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Governance](GOVERNANCE.md) · [Changes](CHANGELOG.md) ·
License: [Apache-2.0](LICENSE)
