# Contributing

Report bugs and propose changes in issues; security problems go to [SECURITY.md](SECURITY.md). Open an issue
before changing what verifies.

Every change goes through a pull request, which CI must pass and a maintainer reviews. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/); commits are signed and carry `Signed-off-by`
(`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org/).
Add a line to [CHANGELOG.md](CHANGELOG.md).

**Spec changes** come with the verifier change and its tests, use the key words as section 0 defines them, and
version any change to what existing bundles verify as (section 0, Versioning). Format with
`mdformat --compact-tables spec`.

**Verifier changes**, from `verifier/`: `gofmt -l .` prints nothing, and `go vet ./...` and `go test ./...` pass.
New behaviour needs tests; a new rejection needs a test that fails without it; parsers of untrusted input keep a
fuzz target. Avoid new dependencies.

**Releases**: a maintainer adds `## <version> (<date>)` to the changelog, pushes the tag `v<version>`, and
approves the release job.
