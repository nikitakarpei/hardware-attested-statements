# Changelog

Each release has a section `## <version> (<date>)`, used as its release notes. Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

- Android profile: a `trustedSigners` entry can end the acceptance of some of its `versionCodes` with
  `versionEndTimes`, to retire a version on a date known in advance: a statement of that version is accepted only if
  its upper time bound is before the end time.
- Android profile: two `trustedSigners` entries of a predicate type with the same package and a signing
  certificate in common are a policy error, whatever their versions. Before, the first in the policy that accepted
  an app applied, so a version's end time could be ignored depending on the order of the entries.
- Verifier library (breaking): `Profile.CheckPolicy` returns the profile's parsed part of the policy
  (`ProfilePolicy`), which the verifier keeps and passes to `Profile.VerifyKey` in place of the raw `trustedSigners`
  entries and settings. Profiles parse their policy once, when the verifier is made, not for every key.

## 0.2.0 (2026-11-07)

- Android profile: new settings `minOsVersion` (default 140000, Android 14) and `maxPatchAgeMonths` (default 6),
  which rejects keys whose OS patch level is more than that many months older than the statement's upper time
  bound. Both are on by default, so devices on older Android versions, or that stopped getting updates, are now
  rejected; set either to 0 to turn it off. The policy identifier stays `…/policy/v0.1`: a policy that sets
  neither now accepts fewer devices than under 0.1.0.
- Policy: profile settings are given only per predicate type; the policy-wide `profiles` member is gone, and a
  policy that has it is rejected. Each type's requirements are stated where they apply, so a type can't silently
  inherit (or miss) settings meant for another. A `null` anywhere in a policy is rejected (spec section 0), as are
  Android settings that aren't an object.
- Android profile: patch levels whose month isn't 1 to 12, or that are more than a month after the statement's
  upper time bound, are rejected.
- Verifier: reports the Android version; `Key.AcceptedFrom` and `Key.AcceptedUntil` say between when the patch
  levels are accepted.
- Verifier: when a statement comes in several bundles, each bundle's key evidence is checked at the statement's
  upper time bound. Before, only the first bundle's was, so a bundle whose certificate chain had expired passed if
  a valid one came first (spec section 5: one failing bundle fails the statement).

## 0.1.0 (2026-11-05)

First release: the format at version v0.1 (a draft, which can still change incompatibly), with the Android profile
and the predicate type `http-response`; and the verifier, as a Go library and the `attested-verify` command for
Linux, macOS and Windows.
