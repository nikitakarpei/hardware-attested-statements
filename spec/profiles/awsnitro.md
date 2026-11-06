# AWS Nitro profile, v0.1 (draft)

A profile of [Hardware-Attested Statements](../README.md) for programs running in AWS Nitro Enclaves: the program
generates its signing key inside an enclave, an isolated virtual machine whose memory its parent EC2 instance can't
read, and the enclave's Nitro Secure Module (NSM) attests it. The attestation document, signed through AWS's Nitro
attestation PKI and rooted at AWS, states which enclave image is running (its PCRs) and carries the key. It states
nothing else about the platform: the platform is AWS's, as of the document.

The core spec's conventions (its section 0), including the BCP 14 key words and what an error or a rejection fails,
apply to this profile.

## Key

The program MUST generate its signing key inside the enclave, as an ECDSA P-256 key, and MUST NOT export it or use
it for anything but these statements. Any process in the enclave can ask the NSM for a document attesting any key,
so the enclave image MUST NOT run code that lets anyone else choose what the NSM attests. The image MUST NOT be run
in debug mode.

When it creates the key, the program MUST obtain a drand round, the key's **startedAfter**: the latest round, since
an older one only shortens the key's life. For its key, it then requests attestation documents from the NSM with:

- `public_key`: the signing key, as a DER SubjectPublicKeyInfo (id-ecPublicKey, the named curve prime256v1, an
  uncompressed point);
- `user_data`: `SHA-256("hardware-attested-statement/v0.1/awsnitro/key" ‖ chain hash ‖ round ‖ round signature)`,
  where the chain hash is 32 bytes, the round 8 bytes, and the round signature its decoded bytes;
- no `nonce`.

The `user_data` binds the key to this profile and version, so verifiers of other profiles or versions reject it, and
states that the key was created no earlier than the round.

A key is usable for `maxKeyAgeHours` after its round's time (section Policy). A program MUST create a new key, with
a new round, before that time has passed for every policy it targets, with a margin at least as long as getting a
statement time-stamped can take (for example an hour), and MUST NOT request documents for an older key. Within that
time, the evidence can be renewed, since the NSM attests a key as often as it is asked: without the limit, a key
read once by an attacker would stay usable for as long as the enclave runs.

A document's certificate is short-lived (hours), the NSM puts the same certificate in every document until it
expires, and the evidence MUST be valid at the statement's upper bound (core spec section 4). So a program MUST NOT
put a document in a bundle unless its certificate is valid for at least the same margin, SHOULD then request a new
one, and SHOULD have statements that are kept time-stamped within that margin.

The bundle's `key` is:

```json
{ "profile": "awsnitro", "attestationDocument": "…",
  "keyStartedAfter": { "drand": { "chain": "<chain hash>", "round": 33638467, "signature": "…" } } }
```

- `attestationDocument`: the COSE_Sign1 structure the NSM returned, exactly as returned.
- `keyStartedAfter`: the key's drand round, with the members and rules of the core spec's `startedAfter` (section
  1).

The **key binding** (core spec section 2) is the content of the COSE_Sign1 payload byte string: the attestation
document, which contains the signing key, the commitment to the round, the PCRs and the certificate chain, and can't
be changed without the signing certificate's key (unlike the COSE signature, which anyone can turn into another
valid one). A verifier can compute it once the `key` object has exactly the members above and step 1 holds;
otherwise the evidence can't be read (core spec section 0).

## Verification

A verifier MUST reject the key unless:

1. **The COSE_Sign1 structure** is an untagged CBOR array of four items, with nothing after it: a protected header
   of exactly the bytes `a1 01 38 22` (`{1: -35}`, ES384), an empty map as unprotected header, the payload as a byte
   string, and a byte string of 96 bytes, the signature.
2. **The CBOR** of the structure and of the payload is well-formed and uses only arrays, maps, byte strings, text
   strings (valid UTF-8), integers and `null`, and no tags. Every item has a definite length, except that the
   payload's top-level map MAY have an indefinite length (AWS changed it to one, without notice, between 2024-09 and
   2025-09). Integers and lengths are in shortest form, map keys are unique, and nothing follows the payload's map.
   Anything else is rejected, not interpreted.
3. **The document** (the payload) is a map with exactly these keys, of these types:
   - `module_id`: text, `i-` followed by 8 to 17 lowercase hex digits, `-enc`, and 16 lowercase hex digits;
   - `timestamp`: an unsigned integer above 0, milliseconds since the Unix epoch;
   - `digest`: the text `SHA384`;
   - `pcrs`: a map of 1 to 32 entries, each from an integer 0–31 to a byte string of 48 bytes;
   - `certificate`: a byte string, the signing certificate;
   - `cabundle`: an array of at least one byte string, certificates from the root down;
   - `public_key`, `user_data` and `nonce`: each a byte string or `null`.
4. **The chain**: `cabundle[0]` is the AWS Nitro Enclaves root (appendix); each later element of `cabundle` is
   issued and signed by the one before it, and `certificate` by the last. Every certificate is strict DER, has an
   ECDSA key on the named curve P-384, and is signed with ECDSA and SHA-384. Every element of `cabundle` is a CA,
   and the chain meets their path length constraints; `certificate` isn't a CA. The subject of `certificate` has
   exactly one common name, which is `module_id`, a dot, a region name (lowercase letters, digits and hyphens), and
   `.aws`.
5. **The signature** over the COSE `Sig_structure` (`["Signature1", protected header, empty byte string, payload]`)
   verifies with `certificate`'s key, as ECDSA P-384 with SHA-384, the signature being `r ‖ s` as 48-byte big-endian
   integers. A high `s` is accepted: the NSM produces them.
6. **The key**: `public_key` is a strict DER SubjectPublicKeyInfo of an uncompressed point on the named curve P-256;
   `keyStartedAfter` passes the core spec's drand checks, from a chain in the policy's `drandChains` (a round from a
   chain the policy distrusts or doesn't know is rejected, since it can't bound the key's age); `user_data` is the
   commitment to it (section Key); `nonce` is `null`.
7. **Not debug**: `pcrs` has entries 0, 1 and 2, and none of them is all zero bytes. An enclave run in debug mode
   reports PCR0, PCR1 and PCR2 (and PCR8) as zero; its other PCRs, such as PCR4, can be set.
8. **The signer**: the PCRs match a policy entry (section Policy).

NitroTPM documents, which the root user of any EC2 instance can request with any `public_key` and `user_data`,
including a P-256 key, chain to the same root through the same kind of certificates. Steps 3 and 4 reject them:
their `module_id` has `-tpm` instead of `-enc`, it is also in their certificate's name, and they carry
`nitrotpm_pcrs` instead of `pcrs`.

The evidence is valid while every certificate of the chain is valid, and until `maxKeyAgeHours` after the round's
time. `timestamp`, the NSM's time of the document, MUST be within the validity of `certificate`. It is reported, but
is not a time bound: the key can sign before the document is made.

AWS publishes no revocation lists for this PKI; its certificates are short-lived instead. This profile uses no
lists.

## Policy

A `trustedSigners` entry names an enclave image by its PCRs, as lowercase hex (48 bytes each):

```json
{ "profile": "awsnitro", "pcrs": { "0": "…", "1": "…", "2": "…" } }
```

`pcrs` MUST name PCRs 0, 1 and 2 (the image, its kernel and boot ramdisk, and its application), none of them all
zero, and MAY name others from 0 to 15 (for example 3, the parent instance's IAM role, or 8, the image's signing
certificate). A name that isn't a decimal integer 0–15 without leading zeros, or a value that isn't 48 bytes, is a
policy error: PCRs 16 to 31 can be extended by any process in the enclave while it runs, so they name a state, not
an image. Every PCR the entry names MUST be present in the document and equal; a missing one doesn't match.

PCR0 alone doesn't name an image: it hashes the kernel, command line and ramdisks as one sequence, so the same bytes
cut differently give the same PCR0. PCR8 alone doesn't either: it names the key that signed the image (any image it
ever signed, however old), and AWS doesn't document that the enclave's launch checks the image's signature.

A program has an entry for each release. Its producer SHOULD build the image reproducibly and publish the expected
PCRs with its source, so that others can check what the entry trusts.

Settings go under `profiles.awsnitro`, globally and per predicate type, merged over the global ones member by member
(core spec section 5):

```json
{ "maxKeyAgeHours": 24 }
```

Without settings, this is the default. `maxKeyAgeHours` MUST be at least 1: a verifier rejects a key whose round's
time is more than that before the statement's upper bound.

## What a verifier reports

A verifier MUST report, as the document states them:

- the enclave's `module_id`, and the region in its certificate's name;
- the document's `timestamp`;
- all of its PCRs;
- the time of the key's round, before which the key didn't exist;
- the period during which the whole chain is valid.

## Appendix: trust anchor

**AWS Nitro Enclaves root** (https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip), SHA-256 of the
DER certificate:

- `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b` (ECDSA P-384,
  `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`, 2019 to 2049)

A verifier MUST take new roots only from its own updates, never from the network. Only documents under this root are
supported.
