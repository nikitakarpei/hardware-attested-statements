# Changelog

Each release has a section `## <version> (<date>)`, used as its release notes. Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

The `awsnitro` profile, for programs in AWS Nitro Enclaves, in the spec and the verifier (`profiles/awsnitro`,
also used by `attested-verify`). Profiles' `VerifyKey` now takes a `verifier.KeyContext`, with the policy's trusted
drand chains.

## 0.1.0 (2026-11-05)

First release: the format at version v0.1 (a draft, which can still change incompatibly), with the Android profile
and the predicate type `http-response`; and the verifier, as a Go library and the `attested-verify` command for
Linux, macOS and Windows.
