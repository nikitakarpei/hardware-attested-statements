# Changelog

Each release has a section `## <version> (<date>)`, used as its release notes. Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

- Verifier: when a statement comes in several bundles, each bundle's key evidence is checked at the statement's
  upper time bound. Before, only the first bundle's was, so a bundle whose certificate chain had expired passed if
  a valid one came first (spec section 5: one failing bundle fails the statement).

## 0.1.0 (2026-11-05)

First release: the format at version v0.1 (a draft, which can still change incompatibly), with the Android profile
and the predicate type `http-response`; and the verifier, as a Go library and the `attested-verify` command for
Linux, macOS and Windows.
