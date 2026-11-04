# Hardware-Attested Statements, v0.1 (draft)

A program running on hardware that can attest to it (an Android phone's secure hardware, a cloud enclave, …) makes a
statement about data it produced and signs it with a key the hardware generated and vouches for. The bundle carries
what a verifier needs to check it:

- **who** signed: which program (for example an app's package, signing certificate and version, or a code
  measurement), on hardware in what state, as the key's attestation states it;
- **when**: an optional RFC 3161 time-stamp (signed no later than) and an optional drand value inside the statement
  (signed no earlier than);
- **from what**: a statement can name other statements as its inputs, and carry their bundles, so one bundle can
  prove a chain of steps after the intermediate data has been deleted.

This document is the core, the same for every kind of hardware. How a kind of hardware's evidence is checked is a
**profile**, specified separately:

| Profile | Document |
| -- | -- |
| `android` | [profiles/android.md](profiles/android.md): Android key attestation (StrongBox or TEE) |

It reuses existing standards where they fit, unchanged:

| Part | Standard |
| -- | -- |
| Statement | [in-toto Attestation Framework v1 Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) |
| Signature envelope | [DSSE v1](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md) |
| Time-stamp | RFC 3161, over an RFC 9162 Merkle tree |
| Lower time bound | a [drand](https://docs.drand.love/docs/specification/) randomness beacon round |
| Input references | in-toto [ResourceDescriptor](https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md) |

What a statement *means* is defined by its predicate type, outside this spec.

## 0. Conventions

- **Requirements**: the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
  "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP
  14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown here.
- **Errors**: where this document or a profile says that something is an *error* or is *rejected*, what fails
  depends on where it is:
  - in a policy: the verifier MUST NOT use the policy;
  - in a list: the list counts as not obtained (section 3);
  - in a statement, or a key, time-stamp or `startedAfter` that is rejected: the statement's node fails (section 5),
    and bounds still pass through it (section 4);
  - in key evidence, so that the bundle's signed-statement ID can't be computed: the bundle has no node; if it is a
    listed input, that input has failed (section 2), and otherwise the verification fails;
  - anywhere else in a bundle, a bundle that section 2 or 5 calls an error, or a rejected HTTP response (section 6):
    the whole verification fails, and gives no result.
- **Formats**: a requirement on the form of a bundle, statement, key evidence, policy, list or header binds whoever
  produces it, and a verifier MUST treat a violation as an error. A SHOULD on a producer isn't checked.
- **JSON**: bundles, key evidence, statements and policies MUST be I-JSON (RFC 7493). A verifier:
  - MUST match member names exactly and case-sensitively;
  - MUST reject an object with a duplicate member name, at any depth;
  - MUST treat an unknown member as an error in bundles, key evidence and policies, and MUST ignore one in
    statements, as in-toto requires;
  - MUST treat as an error a member of a statement whose name equals one this spec or in-toto defines under Unicode
    simple case folding (as in Go's `strings.EqualFold`), but not exactly (`PredicateType`, `Inputs`, `ſubject`, …),
    since some parsers would read it as that member;
  - MUST treat a member this spec defines whose value is `null` as an error, not as an absent member.
- **Integers** in members this spec and its profiles define MUST be between 0 and 2⁵³ − 1, written as plain decimal
  digits: no sign, fraction, exponent or leading zeros. Other numbers in a statement need only be I-JSON.
- **Binary** values in JSON MUST be base64 (RFC 4648 section 4) with padding; **hashes** in JSON, and drand
  signatures (as drand publishes them), MUST be lowercase hex.
- **Lists** a verifier obtains (revocation and boot-key lists): a verifier MUST reject a list with a duplicate
  member name or a member of the wrong type, and MUST ignore unknown members.
- SHA-256 throughout; `‖` is concatenation; integers inside hashed or signed byte strings are big-endian.
- **Versioning**: every string that domain-separates a hash or signature names the version (`…/v0.1/…`), and each
  profile binds its keys to the version (section 3), so a v0.1 signature can't be read under other rules.
- **Trust anchors** (the keys and certificates in appendix A and in each profile's) are built into or configured in
  the verifier. A verifier MUST NOT fetch them from the network or take them from whoever presents a bundle.

## 1. Statement

An in-toto Statement v1, as is:

```json
{ "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "…", "digest": { "sha256": "…" } }],
  "predicateType": "<URI>",
  "predicate": { "inputs": [{ "mediaType": "application/vnd.in-toto+json", "digest": { "sha256": "<statement ID>" },
                              "annotations": { "signedStatementId": "…" } }],
                 "startedAfter": { "drand": { "chain": "<chain hash>", "round": 33638467, "signature": "…" } } } }
```

- `_type` MUST be exactly `https://in-toto.io/Statement/v1`.
- `subject`: what the program produced. The predicate type says what each subject is, and exactly which bytes are
  hashed (for example, whether before or after a content encoding).
- `predicateType`, `predicate`: defined by the predicate type. The URI SHOULD resolve to its description, but
  verifiers MUST treat it only as a name and MUST NOT fetch it.
- The **statement ID** is SHA-256 of the statement's bytes, which are signed and linked exactly as they are:
  implementations MUST NOT re-serialize them.
- `predicate.inputs` and `predicate.startedAfter` are reserved in every predicate type, with these meanings, which a
  predicate type MUST NOT change:
  - **inputs**: the statements this one was derived from. Each entry MUST have:

    - `mediaType` `application/vnd.in-toto+json`;
    - the input's statement ID in `digest.sha256` (other digest algorithms are ignored);
    - the input's signed-statement ID (section 2) in `annotations.signedStatementId`. This also binds the input's
      key evidence and signature, so a statement can only name inputs that were already signed, by that key.

    An entry without these is an error. A predicate type with too many inputs to list MAY commit to them another
    way, not in `inputs`. Its documentation MUST then say how to prove that a statement is one of them; generic
    verifiers don't treat such statements as inputs.

  - **startedAfter**: a drand round obtained when the program started its work: the chain hash, the round number
    (which MUST be at least 1) and the round's signature (lowercase hex). Nobody can know a round's value before its
    time, but anyone can include an older round: the signer chooses it, so it only shows the statement wasn't signed
    earlier.

A program that consumes another statement's subject MUST check that the data matches the subject's digest. It need
not verify the input's bundle; verifiers do (section 5).

## 2. Bundle

```json
{ "mediaType": "application/vnd.hardware-attested-statement.bundle.v0.1+json",
  "dsseEnvelope": { "payloadType": "application/vnd.in-toto+json", "payload": "…", "signatures": [{ "sig": "…" }] },
  "verificationMaterial": {
    "key": { "profile": "android", … },
    "timestamp": { "token": "…", "tree": { "size": 8, "index": 5, "path": ["…", "…", "…"] } },
    "inputBundles": [ { … } ] } }
```

- `dsseEnvelope`: a DSSE envelope with the statement as payload. Its `payloadType` MUST be exactly
  `application/vnd.in-toto+json`, and it MUST have exactly one signature, which MUST NOT have a `keyid` member and
  MUST be:

  - ECDSA P-256 with SHA-256 over DSSE's PAE (`"DSSEv1" SP len(type) SP type SP len(payload) SP payload`);
  - strictly DER-encoded: minimal integers, nothing after the sequence;
  - low-S: `s` at most half the group order (a signer MUST convert `s` to `n − s` if needed).

  So each signing produces exactly one valid signature, and one signed-statement ID. Signing the same statement
  again gives another signature (ECDSA signatures are randomized), so another signed-statement ID.

- `key`: the evidence for the signing key; `profile` names the profile that defines the rest, including the **key
  binding**: bytes of the evidence that contain the signing key and what the evidence says about the signer (section
  3).

- `timestamp` (OPTIONAL): a time-stamp over a tree of signed statements.

  - `token` MUST be an RFC 3161 TimeStampResp whose SHA-256 message imprint is the root of an RFC 9162 Merkle tree
    (section 2.1 of RFC 9162). Whoever requests it SHOULD do so without certificates; verifiers ignore them (section
    2.1).

  - The tree's leaves are the **signed-statement IDs** of every statement time-stamped together:

    `SHA-256("hardware-attested-statement/v0.1/signed" ‖ len(profile) ‖ profile ‖ statement ID ‖ SHA-256(key binding) ‖ signature)`

    where profile is the `key` object's `profile` (UTF-8, which MUST be 1 to 255 bytes, preceded by its length as
    one byte), the key binding is exactly as the evidence carries it (implementations MUST NOT re-encode it), and
    signature is the DSSE signature's decoded bytes. Each ID is a leaf's *data*: its RFC 9162 leaf hash is
    SHA-256(0x00 ‖ ID).

  - `tree` proves this bundle's ID is leaf `index` of the `size`-leaf tree; `path` is the RFC 9162 inclusion proof.
    A statement time-stamped alone has `size` 1 and an empty `path`, and the root is its leaf hash.

  So a time-stamp covers this statement, signed with this signature by this key, as this key binding states it, and
  can't be moved to another statement, signature, key or key binding. The rest of the evidence (on Android, the
  certificates above the leaf) isn't covered: it is checked as presented, when verifying.

- `inputBundles` (OPTIONAL): bundles of statements this one lists in `predicate.inputs`, nested as they are, so that
  the bundle of a program with few inputs proves the whole chain on its own. Each MUST be one of this statement's
  listed inputs (same statement ID and signed-statement ID); a bundle nested anywhere else is an error. The
  exception is a bundle whose statement ID matches a listed input but whose signed-statement ID can't be computed
  (for example its profile is unknown to the verifier, or its evidence can't be read): it isn't an error, but that
  input has failed.

### 2.1 Time-stamp checks

A verifier MUST reject a time-stamp unless all of these hold (RFC 3161, RFC 5816):

- the TimeStampResp status is `granted` (0); any other status, including `grantedWithMods`, is rejected;
- the token is a CMS SignedData with exactly one SignerInfo, whose encapsulated content type is id-ct-TSTInfo
  (1.2.840.113549.1.9.16.1.4);
- its signed attributes are present and include content-type (equal to id-ct-TSTInfo), message-digest (matching the
  content) and an ESS signing-certificate or signing-certificate-v2 attribute identifying the signing certificate;
- its digest and signature algorithms use SHA-256 or stronger (the ESS attribute's certificate hash MAY be SHA-1: it
  only identifies a pinned certificate);
- the signing certificate is one the policy trusts for a TSA (section 5), and chains to that TSA's root through the
  TSA's own intermediates, if any;
- the signing certificate, its intermediates and the root are valid **both at the token's time and at verification
  time** (the token states its own time, so a retired key could otherwise back-date tokens forever);
- the signing certificate's extended key usage is critical and exactly id-kp-timeStamping;
- the TSTInfo has version 1, a SHA-256 message imprint equal to the tree root, and, if present, an accuracy whose
  `millis` and `micros` are 1–999 and whose total is at most one day.

The verifier MUST ignore certificates in the token, if any.

The token's upper bound is `genTime` plus its accuracy, but at least one second (TSAs can truncate times to whole
seconds). A bundle stops verifying when its TSA's signing certificate expires.

## 3. Profiles

A profile MUST define, for one kind of hardware:

- the `key` object's members, and how to verify that its evidence attests the signing key: a P-256 key generated by
  the hardware, which can't leave it and is used only for these statements;
- the **key binding** (section 2): which bytes of the evidence, exactly as carried, contain the signing key and what
  the evidence says about the signer and device;
- how the key is bound to this format and version (for example an attestation challenge naming it), so keys made for
  other purposes or versions are rejected;
- how the evidence names the **signer** (the program), and the policy entries that say which signers to trust;
- what the evidence says about the **device or platform**, as of when, and the settings that constrain it;
- which signature algorithms its evidence can use (which MUST be SHA-256 or stronger);
- the interval during which the evidence is valid, and how revocation is checked;
- which of its lists are authenticated, and how;
- its trust anchors, in full.

**Lists** (revocation and other lists):

- A list is needed only for evidence it applies to. If a list that's needed can't be obtained, the verifier MUST
  reject the evidence it applies to.
- A list MUST be at most as old as the policy allows; an older one counts as not obtained. Its age is the
  verification time minus the time it counts as produced:
  - for a fetched list, the earlier of its response's `Date` and the time it was received minus its `Age` (caches
    keep the original `Date`, and some serve copies a day old whatever the request asks);
  - for a copy given to the verifier, the time the operator states, which the verifier MUST report.
- Revocation MUST be checked at verification time, so a revocation also invalidates bundles signed before it. The
  converse is a risk: if a list's publisher removes an entry later (for example once the certificate has expired),
  bundles relying on that evidence verify again. Archived bundles whose evidence has expired therefore rely on
  revocations staying listed.

## 4. Time bounds

For each statement:

- **Upper bound** from its own time-stamps that pass section 2.1, in any of its bundles: the smallest of their upper
  bounds (section 2.1).
- **Lower bound** from its own `startedAfter`, if it passes its checks: the round's time,
  `genesis + (round − 1) × period`.
- A verifier MUST take each of these bounds even if the statement fails another check, including another of its
  time-stamps: a bound rests only on the time source and hash commitments, so it doesn't depend on which checks
  fail, or in which order bundles are checked.
- If a time-stamp or `startedAfter` is present but fails its checks, or names a TSA or drand chain the policy
  doesn't know, the verifier MUST fail the statement (section 5), and MUST NOT ignore it. If it is from a TSA or
  drand chain the policy **distrusts** (it would pass its checks if the policy trusted that TSA or chain), the
  verifier MUST NOT take a bound from it and MUST report it as distrusted, but MUST NOT fail the statement for that
  alone.
- A verifier MUST then propagate bounds along every link whose IDs match (section 5, step 1). A statement can only
  name inputs that were already signed, so an input's upper bound is at most that of each statement naming it, and a
  statement's lower bound is at least that of each of its inputs.
- Bounds pass through statements that fail any other check, since they rest only on hash commitments. An input whose
  signed-statement ID can't be computed (section 2) has no node, so no bound passes through it.
- A lower bound later than an upper bound anywhere means a trusted time source is wrong: the verifier MUST then fail
  the whole verification.
- A verifier MUST require the key evidence to be valid **at the upper bound** after propagation: the latest time the
  statement can have been signed. A statement with no upper bound is bounded by the verification time, so its
  evidence MUST be valid then. The lower bound never shows the evidence was valid when signing, since the signer
  chooses its drand round.

This is what the bounds are for: given honest time-stamp authorities, a signing key that falls into an attacker's
hands only after its evidence expired can't sign a statement that is accepted, since anything it signs is
time-stamped, or verified, later.

So one time-stamp at the end of a chain bounds every step before it, and one drand round at its start bounds every
step after it. But each step's evidence then has to be valid at its upper bound: that time-stamp, unless an earlier
one also bounds the step. Evidence can be short-lived (on Android, about two weeks): a bundle with no time-stamp
stops verifying when its evidence expires, and a step whose evidence expires before a later step is time-stamped
fails. Programs whose output is kept SHOULD therefore time-stamp their own statements; batching (section 2) makes
this cheap.

## 5. Verification and policy

A verifier MUST check the bundle it is given and every input bundle (nested in it, or presented separately), in
three steps:

1. **Links.** Check each bundle's own evidence: its envelope and signature, its key evidence as the profile defines,
   its time-stamp (section 2.1) and its `startedAfter`.
   - Bundles of the same signing (same signed-statement ID: the same statement, key binding and signature) are one
     node. Each bundle is checked, and one that fails fails the node.
   - A link from a statement to an input is valid if the input's node is one of the statement's listed inputs.
   - A presented bundle, other than the one being verified, that is no valid listed input of any node is an error.
     The exception is a bundle whose signed-statement ID can't be computed but whose statement ID matches a listed
     input (section 2): that input has failed.
2. **Bounds.** Propagate time bounds over the valid links (section 4).
3. **Policy.** Apply the policy to each node: its predicate type and signer, its settings, its evidence's validity
   at its upper bound, and the required bounds.

A node **passes** if it passes all three steps. It is **accepted** if it passes and either every input it lists is
accepted, or its own predicate type's policy says `allowUnverifiedInputs`. The bundle verifies if its own
statement's node is accepted and nothing fails the whole verification (sections 0 and 4).

`inputBundles` aren't signed, and one failing bundle fails its node. So whoever passes a bundle on can make it fail
(by nesting a copy of an input with a broken time-stamp, say), or make the verification fail (by adding a member to
a nested bundle): a failure shows that something presented was wrong, not that a signed statement was.

When there is a result (section 0), it MUST describe:

- each statement, and whether it passed and was accepted;
- for each listed input, whether it was verified (accepted) or not, and why: not presented, or which check failed;
- every unverified input anywhere in the chain.

A statement vouches only for itself: provenance ("derived from a capture of …") holds only along verified inputs,
and the verifier MUST NOT drop an unverified one silently. Verification time is the verifier's own clock when it
verifies; a verifier MUST NOT verify "as of" another time.

The policy says what to trust:

```json
{ "policy": "hardware-attested-statement/policy/v0.1",
  "timestampAuthorities": ["freetsa"],
  "drandChains": ["quicknet"],
  "predicateTypes": {
    "<URI>": { "trustedSigners": [{ "profile": "android", … }],
               "requireTimestamp": true, "requireStartedAfter": true, "allowUnverifiedInputs": false,
               "profiles": { "android": { … } } } },
  "profiles": { "android": { … } } }
```

- `timestampAuthorities`, `drandChains` (REQUIRED, and can be empty): which TSAs and drand chains to trust: built-in
  ones by name (appendix A), or a TSA given in full, as
  `{ "name": "…", "root": "<PEM>", "intermediates": ["<PEM>"], "signingCertificates": ["<PEM>"] }` (`intermediates`
  OPTIONAL), under a name that MUST NOT be a built-in one.
- `distrustedTimestampAuthorities`, `distrustedDrandChains` (OPTIONAL): names of compromised TSAs and drand chains.
  Bounds from them aren't accepted, and statements using them are reported (section 4); a name MUST NOT be both
  trusted and distrusted.
- `predicateTypes`: a verifier MUST accept only these.
  - `trustedSigners`: entries defined by each entry's profile. A verifier MUST accept a statement only if an entry
    of its key's profile accepts the key's signer.
  - `requireTimestamp`, `requireStartedAfter`: the statement MUST have that bound after propagation (section 4).
  - `allowUnverifiedInputs` (default false): a statement of this type is accepted although some of the inputs it
    lists aren't; they MUST still be reported.
  - `profiles`: settings for this predicate type, merged over the global ones member by member: a member given here
    replaces the global one, and members not given keep the global value (or, without one, the default). A member
    whose value is an object is replaced as a whole, and MUST then be complete.
- `profiles`: each profile's settings.

## 6. HTTP binding

A program that returns its subject as an HTTP response MAY carry its bundle in headers instead (`inputBundles` can't
be carried this way). The statement MUST then have exactly one subject named `body` (it MAY have others), with:

- a `sha256` digest of the response body exactly as received (after any transfer decoding, before any content
  decoding);
- a `mediaType` equal to the response's `Content-Type` (absent if it has none);
- `annotations.contentEncoding` equal to its `Content-Encoding` (absent if it has none).

A verifier MUST check all of these, on live and saved responses; every other digest algorithm it knows MUST match
too. It MUST compare field names case-insensitively, MUST reject a response with more than one `Content-Type` or
more than one `Content-Encoding` field line, and MUST compare values byte for byte after removing leading and
trailing spaces and tabs.

The status code and other headers aren't covered (a saved 206 response could be relabelled 200): a predicate type
that needs them MUST define further checks, as `urn:signed-capture:http-response:v1` does
([predicates/http-response.md](predicates/http-response.md)).

| Header | Value |
| -- | -- |
| `Attested-Version` | token: `v0.1` (REQUIRED) |
| `Attested-Statement` | byte sequence: the statement |
| `Attested-Signature` | byte sequence: the DSSE signature |
| `Attested-Key` | byte sequence: the `key` object, as JSON |
| `Attested-Timestamp` | byte sequence: the token |
| `Attested-Timestamp-Tree` | dictionary of exactly `size` and `index` (integers) and `path` (inner list of byte sequences): `size=8, index=5, path=(:…: :…: :…:)` |

Values MUST be RFC 9651 structured fields, each in one field line, without parameters. `Attested-Timestamp` and
`Attested-Timestamp-Tree` MUST appear together or not at all. A response carrying any `Attested-*` header more than
once (including as comma-joined values) is rejected; a verifier MUST ignore trailers. The headers total about 9 KB,
more than some proxies and servers allow by default (nginx's `proxy_buffer_size`, 4 or 8 KB, for example). Responses
aren't bound to a request: their time bounds show when they were made.

A **saved response** is the status line, the header fields, an empty line, and the body, to the end of the file. A
verifier MUST parse it strictly, and MUST reject anything else rather than interpreting it, since parsers disagree
on where headers end and the body begins and ends:

- the status line is `version SP status [ SP reason ] CRLF`: version `HTTP/1.1`, `HTTP/2` or `HTTP/3`, status three
  digits from 200 to 599, and reason any visible characters, spaces and tabs (so curl's `HTTP/2 200 ` is accepted);
  nothing comes before it (no interim 1xx response, no proxy's `Connection Established`);
- field names are tokens, with no whitespace before the colon; field values have no control characters other than
  horizontal tab; every line ends in CRLF; no obs-fold;
- there is no `Transfer-Encoding`, at most one `Content-Length`, and, if present, it equals the body's length.

So programs SHOULD send `Content-Length`, and a response can be saved with `curl -i … > file` (HTTP/1.1 or HTTP/2;
through a proxy for an `http://` URL there is no `CONNECT` preamble).

## 7. Trust model

A verified bundle is as good as what the verifier trusts:

- **the hardware and its vendor's attestation roots and revocation** (for Android: Google's roots and revocation
  list), to attest only keys that live in the hardware, with true statements about the device, and to revoke devices
  found compromised. Some statements come from software the hardware trusts rather than checks: on Android, the
  app's identity is what the OS told the hardware when the key was created, and the boot state is what the device's
  bootloader told it;
- **the weakest device model a policy accepts**, to have a boot chain that holds: a device whose boot chain is weak
  (for example its vendor's boot keys are public, or its chip can be made to skip checking the bootloader) can, in
  an attacker's hands, attest anything. Revocation lists revoke leaked or faulty attestation keys, not device models
  with weak boot chains, so such a model stays a way to forge for as long as a policy accepts it: evidence is as
  good as the weakest device a policy accepts;
- **the program**, identified by the profile (for Android: an app's package and signing certificate), to sign only
  true statements. Whoever holds its signing key can publish a program that signs anything; a trusted signing
  certificate MUST therefore never sign debuggable or other test builds;
- **the device or platform state** as attested: a device that is exploited after its key was attested can sign
  anything until its evidence expires or is revoked;
- **the time-stamp authorities**, for upper bounds, to state the true time (within its accuracy) in every token they
  sign, and not to use their signing keys for anything else that could pass section 2.1's checks;
- **the drand network's threshold of operators**, not to compute rounds early, for lower bounds;
- **the verifier's own clock**: verification time decides whether evidence without a time-stamp is still valid,
  whether a TSA's certificates are (section 2.1), and how old lists are (section 3), so a verifier whose clock is
  behind accepts expired evidence;
- **inputs**, only as far as they were verified themselves (section 5);
- **revocation and other lists**, as fresh as obtained: a list fetched by the verifier is as authentic as its source
  and transport (the profile says which), and a copy given to the verifier is as fresh as its operator says.

## Relation to other formats

- **in-toto and DSSE** are used unchanged, so existing tools can read the statement and check the signature with the
  key from the evidence. They can't check the evidence, the time-stamp tree or the drand round.
- **Sigstore bundles** inspired the layout (`dsseEnvelope` + `verificationMaterial`), but a Sigstore bundle
  identifies signers by an OIDC-based certificate and a transparency log, time-stamps one signature per token, and
  carries no hardware attestation. So this isn't one.
- **IETF RATS** (RFC 9334) describes the same roles: the hardware's evidence, an attester, a verifier, and a relying
  party. A profile could carry evidence as an Entity Attestation Token (RFC 9711).
- **C2PA** embeds signed manifests in media files with X.509 signer identities. It's the better fit when the output
  is a photo or video that should carry its own provenance.

## Appendix A. Built-in trust anchors

**`freetsa`** (time-stamp authority, https://freetsa.org/tsr). SHA-256 of the DER certificates:

- root: `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc`
- signing certificate (valid 2026-02-15 to 2040): `32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc`

FreeTSA's earlier signing certificate (2016–2026-03-11,
`4694be23c3a53004444b1705bfe5a7f50a6d2a1638194f23c0f389b68bd78a75`) is not trusted: it has expired, so its tokens
fail section 2.1 anyway.

**`quicknet`** (drand chain of the League of Entropy):

- chain hash: `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`
- scheme: `bls-unchained-g1-rfc9380` (signatures on G1, domain separation tag
  `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`, message SHA-256 of the round number as 8 bytes)
- public key (G2, compressed):
  `83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a`
- genesis: 1692803367 (Unix time), period: 3 seconds
