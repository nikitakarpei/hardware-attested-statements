# Verifier

Checks [Hardware-Attested Statements](../spec/README.md): a Go library, and the `attested-verify` command.

```
go build ./cmd/attested-verify
./attested-verify -policy policy.json http capture.http          # a response carrying a bundle in its headers
./attested-verify -policy policy.json bundle a.json [b.json …]    # a bundle, plus bundles of its inputs not nested in it
./attested-verify extract capture.http > capture.bundle.json      # the bundle from a response's headers
```

As a library:

```go
policy, err := verifier.ParsePolicy(policyJSON)   // which TSAs, drand chains, predicate types and signers to trust
trust, err := android.LoadTrust(ctx, nil)         // pinned roots + current revocation and GrapheneOS lists
v, err := verifier.New(policy, android.New(trust))

result, err := v.Verify(bundle)                   // and the input bundles nested in it
result, err := v.Verify(bundle, inputBundles...)  // plus input bundles presented separately
// err != nil: not verified; result, if not nil, still says what passed and why the rest didn't
```

A `Result` says between which times the statement was signed, and its `Key` what the profile established: for
Android, an `android.App` (package, versionCode, signing certificates) and an `android.Device` (key storage,
provisioning, OS, patch levels, key creation time). Its `Inputs` are the statement's listed inputs, each with its
own `Result` if its bundle was presented, whether it's verified, and if not, why: provenance holds only along
verified inputs (`UnverifiedInputs` lists them all). Profiles implement
`verifier.Profile`; `profiles/android` is the first. What a statement *means* is up to its predicate type:
`predicates/httpresponse` handles `urn:signed-capture:http-response:v1`
([spec](../spec/predicates/http-response.md)), including checking a saved response against it.

Tests run offline: `go test ./...`. `profiles/android/testdata/google` is Google's corpus of real attestations (Apache-2.0, see
its README); `testdata/capture` holds saved responses signed under a test attestation root.
