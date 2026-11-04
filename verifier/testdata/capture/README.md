Saved responses carrying their bundle in headers, signed under a test attestation root (`fake_root.pem`), with
real drand rounds and FreeTSA time-stamps. `capture_gen_test.go` makes them: `go test -run '^TestGenerateCaptures$'
-generate-captures .` (needs the network). `../trust` holds snapshots of Google's revocation list and GrapheneOS's
signed key list, so the tests run offline.
