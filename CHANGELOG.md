# Changelog

Each release has a section `## <version> (<date>)`, used as its release notes. Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

- Android profile: new settings `minOsVersion` (default 140000, Android 14) and `maxPatchAgeMonths` (default 6),
  which rejects keys whose OS patch level is more than that many months older than the statement's upper time
  bound. Both are on by default, so devices on older Android versions, or that stopped getting updates, are now
  rejected; set either to 0 to turn it off. Patch levels whose month isn't 1 to 12 are rejected. The verifier
  reports the Android version (`Key.StaleFrom` says until when the patch level is accepted).

## 0.1.0 (2026-11-05)

First release: the format at version v0.1 (a draft, which can still change incompatibly), with the Android profile
and the predicate type `http-response`; and the verifier, as a Go library and the `attested-verify` command for
Linux, macOS and Windows.
