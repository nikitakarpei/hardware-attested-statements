# Android profile, v0.1 (draft)

A profile of [Hardware-Attested Statements](../README.md) for apps on Android phones, using Android key attestation:
the signing key lives in StrongBox (a separate security chip) or the TEE (the main processor's secure area), only
the app that created it can use it, and its certificate chain, issued by the secure hardware and rooted at Google,
states which app created it on a device in what state.

The core spec's conventions (its section 0), including the BCP 14 key words and what an error or a rejection fails,
apply to this profile.

## Key

The app MUST generate its signing key in Android Keystore: EC P-256, purpose SIGN only, digest SHA-256, no validity
dates (`setKeyValidityStart`/`End`), and attestation challenge `hardware-attested-statement/v0.1/android/key`. The
challenge binds the key to this profile and version: verifiers of other profiles or versions reject it.

The attested state (app version, patch levels, boot state) is the state **when the key was created**. An app MUST
therefore create a new key whenever its version changes (and MAY do so more often), and MUST NOT use a key created
by an earlier version. It MUST refuse to create or use its key in a debuggable build.

A key is only usable while its whole chain is valid, and remotely provisioned chains are short-lived (about two
weeks). An app MUST create a new key before the earliest `notAfter` in its chain, with a margin at least as long as
getting a statement time-stamped can take (for example a day).

The bundle's `key` is:

```json
{ "profile": "android", "certificates": ["…", "…", "…"] }
```

`certificates`: the key's attestation chain. It MUST be leaf first, **without** the self-signed root, and each
certificate MUST be strict DER. An **intermediate** is any certificate of the chain other than the leaf.

The **key binding** (core spec section 2) is the leaf certificate's `tbsCertificate`, exactly as given: it contains
the signing key and the attestation, and can't be changed without the issuer's key (unlike the certificate's own
signature, which anyone can turn into another valid one).

## Verification

A verifier MUST reject the key unless:

1. **The chain** is signed link by link: each certificate by the next, the last by one of Google's attestation roots
   (appendix). No certificate is self-signed (its issuer equal to its subject, or its key equal to a root's).
   Certificates are signed with ECDSA, or RSA (PKCS #1 v1.5 or PSS), with SHA-256, SHA-384 or SHA-512.
2. **Exactly one certificate carries the attestation extension** (OID 1.3.6.1.4.1.11129.2.1.17): the leaf. A chain
   in which any other certificate carries it is rejected. (Otherwise anyone with an attested key could sign a
   certificate with a forged attestation and put it in front of their real chain.) Chains for keys attested by an
   app-provided attestation key (Android 12's ATTEST_KEY), which carry the extension above the leaf, are therefore
   not supported.
3. **No certificate is revoked**: no intermediate, nor the root, is on Google's revocation list
   (https://android.googleapis.com/attestation/status), with any status or reason.
   - A certificate is on it if its serial number, written as lowercase hex without leading zeros **or** as decimal,
     is a key of the list's `entries` (Google documents hex, but most of the published list is decimal). A list with
     an entry key that is neither is rejected.
   - The leaf isn't matched: the app's own key is issued by the device's attestation key, and the list revokes
     attestation keys.
   - The list isn't signed, so a verifier MUST fetch it from Google over HTTPS, unless the verifier is given a copy,
     which is trusted on its operator's word.
   - It MUST be at most `maxListAgeHours` old (core spec section 3); if it can't be obtained, the key is rejected.
     Google's list serves cached copies up to a day old, and documents that expired certificates can be removed from
     it (core spec section 3 states the risk).
4. **The extension** parses and says:
   - attestation challenge `hardware-attested-statement/v0.1/android/key`;
   - origin GENERATED; algorithm EC, curve P-256, purposes exactly {SIGN}, digests including SHA-256, and none of
     the validity tags (activeDateTime, originationExpireDateTime, usageExpireDateTime), all hardware-enforced;
   - attestation and KeyMint security levels equal, TEE or StrongBox, matching the chain (below);
   - a hardware-enforced root of trust with the bootloader locked and an accepted OS (below);
   - an OS version and patch levels meeting the policy (below);
   - an attestation application ID with exactly one package, and at least one signing-certificate digest, matching a
     policy entry.
5. **The signing key** is the leaf's public key: id-ecPublicKey on prime256v1, uncompressed point.

The evidence is valid while every certificate of the chain, and the root, is valid.

**Provisioning and security level.** The certificate just below the root decides how the device got its attestation
key:

| Certificate below the root | Provisioning | Security level is stated by |
| -- | -- | -- |
| subject of exactly two attributes, CN `Droid CA2` and O `Google LLC` (in either order) | remote (RKP), short-lived certificates | the leaf's issuer's subject `O`: exactly `TEE` or `StrongBox` |
| anything else | factory | a subject `title` of `StrongBox` on any intermediate means StrongBox; otherwise TEE |

The attestation's security level MUST equal the one the chain states. Leaked attestation keys come from
factory-provisioned devices, so factory chains are rejected, at any security level, unless the policy allows them.

**OS version and patch levels** are read from the hardware-enforced list.

`osVersion` is MMmmpp (140000 is Android 14) and MUST be at least `minOsVersion`; a missing or 0 version fails any
nonzero minimum.

The `min…PatchLevel` settings are YYYYMM, compared with the attested level's year and month (`osPatchLevel` is
YYYYMM; `vendorPatchLevel` and `bootPatchLevel` are YYYYMMDD, or YYYYMM on some devices). A level of neither six nor
eight digits, or with a month outside 1 to 12, is rejected; a missing level fails any nonzero minimum. A level's
month MUST NOT be more than one month after the month of the statement's upper bound (core spec section 4), in UTC:
vendors ship patches early, but not by more.

With `maxPatchAgeMonths` above 0, the statement's upper bound (core spec section 4) MUST fall, in UTC, at most that
many calendar months after the month of `osPatchLevel` (6 and 202605: until the end of November 2026), and a missing
`osPatchLevel` is rejected. This rejects devices that stopped getting updates; 6 accepts devices updated quarterly.
The patch level is the one when the key was created (section Key), and is the vendor's claim, not proof of the
fixes.

**Operating system.** The boot state MUST be one of:

- **Verified**: the device's stock OS, checked by its own boot chain, with a verified boot key that isn't one of
  AOSP's published test keys (appendix). Some vendors ship devices whose OS is signed with those keys, so anyone can
  sign an OS that such a device boots as Verified.
- **SelfSigned**, with a verified boot key on a list of alternative OS keys the verifier trusts. Such a list is
  published and signed by the OS project; the verifier MUST pin the signing key, and MUST reject a list older (by
  its signed `timestamp`) than the one it was built with. v0.1 knows one list, `grapheneos` (appendix).

A boot-key list is needed only to check SelfSigned devices. Its signed `timestamp` changes only when the list does,
so it can't show freshness: a replayed older list that is still newer than the verifier's own is accepted, which is
why lists are obtained afresh (`maxListAgeHours`).

`verifiedBootKey` MUST be exactly 32 bytes, and is compared as lowercase hex. Some devices report all zeros even
when locked and Verified (Google's own Pixel 9 Pro sample does); the test-key check can't catch those, and it
catches only bootloaders that hash the key in libavb's format, so it is a backstop, not a guarantee.

## Policy

A `trustedSigners` entry names an app by package and signing certificates (SHA-256), optionally only some versions:

```json
{ "profile": "android", "package": "org.example.app", "signingCertificates": ["<SHA-256>"], "versionCodes": [16] }
```

Every signing-certificate digest in the attestation MUST be one of the entry's. Without `versionCodes`, any version
is accepted; with it, only those listed. An empty list is a policy error. Version codes above 2⁵³ − 1 can't be
named.

The version is the one that created the key, so `versionCodes` keeps other versions out only as long as every
version signed with these certificates makes its own key (section Key), which a verifier can't check;
`maxKeyAgeHours` limits how long an older key stays usable.

An entry with `versionCodes` MAY end the acceptance of some of them, to retire a version on a date known in
advance:

```json
{ "profile": "android", "package": "org.example.app", "signingCertificates": ["<SHA-256>"], "versionCodes": [15, 16],
  "versionEndTimes": [{ "versionCode": 15, "endTime": 1798761600 }] }
```

`endTime` is Unix seconds. A statement signed by a listed version with an end time is accepted only if its upper
bound (core spec section 4) is before that time. Nobody can get a time-stamp in the past, so an old app can't make
such a statement after its end time, while the statements it made before stay accepted. Each `versionCode` in
`versionEndTimes` MUST be in `versionCodes` and appear once, and `endTime` MUST be at least 1; anything else is a
policy error. To stop accepting a version's statements made at any time, leave it out of `versionCodes`.

Settings go under `profiles.android` of each predicate type (core spec section 5):

```json
{ "requireStrongBox": false, "allowFactoryProvisioned": false,
  "minOsPatchLevel": 0, "minVendorPatchLevel": 0, "minBootPatchLevel": 0,
  "minOsVersion": 140000, "maxPatchAgeMonths": 6,
  "os": { "stock": true, "bootKeyLists": ["grapheneos"] }, "maxListAgeHours": 48 }
```

Without settings, or for members not given, these are the defaults.

- `maxListAgeHours` applies to every list: the revocation list and boot-key lists.
- `minOsVersion` (0, or 10000 to 999999) and `maxPatchAgeMonths` (0 to 1200): 0 turns the check off.
- `maxKeyAgeHours` (no default), if set, rejects keys created longer ago than that before the statement's upper
  bound, as their attestation shows (creationDateTime, set by the device's OS and clock). With it set, a missing
  creationDateTime, or one later than the upper bound, is rejected.
- `os` MUST have both members, and MUST accept at least one OS: `{"stock": false, "bootKeyLists": ["grapheneos"]}`
  accepts only GrapheneOS, whose devices (Pixels) have boot chains GrapheneOS vets.

## What a verifier reports

A verifier MUST report the following, all as the attestation states them, as of the key's creation:

- when the key was created, if the attestation states it (creationDateTime, set by the OS);
- the app's package, versionCode and signing certificates;
- where the key is (StrongBox or TEE), and how the device was provisioned;
- the boot state, the verified boot key, and the OS (stock, or which list);
- the Android version, and the OS, vendor and boot patch levels.

It MUST also report when the lists used were obtained.

## Appendix: trust anchors

**Google's attestation roots** (https://android.googleapis.com/attestation/root), SHA-256 of the DER certificates:

- `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc` (RSA, subject `serialNumber=f92009e853b6b045`,
  2022 to 2042)
- `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` (EC,
  `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US`, until 2035)

A verifier MUST take new roots only from its own updates, never from the network.

**AOSP test keys** (`external/avb/test/data`), as `verifiedBootKey` (SHA-256 of the key in libavb's format):

- `testkey_rsa2048`: `22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c`
- `testkey_rsa4096`: `7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6`
- `testkey_rsa8192`: `e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614`

**`grapheneos`** boot key list:

- list: https://grapheneos.org/attestation.json,
  `{ "verifiedBootKeys": ["<lowercase hex>", …], "timestamp": <Unix seconds> }`; rejected if `timestamp` is below
  1776709772
- signature: https://grapheneos.org/attestation.json.sig, an SSH signature (`ssh-keygen -Y sign`, namespace
  `attestation keys`) by `contact@grapheneos.org`'s key:
  `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIUg/m5CoP83b0rfSCzYSVA4cw4ir49io5GPoxbgxdJE` (as published at
  https://grapheneos.org/allowed_signers)
