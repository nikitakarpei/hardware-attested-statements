# Nitro profile, v0.1 (draft)

A profile of [Hardware-Attested Statements](../README.md) for programs running in AWS Nitro Enclaves: the program
generates its signing key inside an enclave, an isolated virtual machine whose memory its parent EC2 instance can't
read, and the enclave's Nitro Secure Module (NSM) attests it. The attestation document, signed through AWS's Nitro
attestation PKI and rooted at AWS, states which enclave image is running (its PCRs) and carries the key.

The core spec's conventions (its section 0), including the BCP 14 key words and what an error or a rejection fails,
apply to this profile.

## Key

The program MUST generate its signing key inside the enclave, as an ECDSA P-256 key, and MUST NOT export it or use
it for anything but these statements. Any process in the enclave can ask the NSM for a document attesting any key,
so the enclave image MUST NOT run code that lets anyone else choose what the NSM attests. The image MUST NOT be run
in debug mode.

For its key, the program requests attestation documents from the NSM with:

- `public_key`: the signing key, as a DER SubjectPublicKeyInfo (id-ecPublicKey, prime256v1, uncompressed point);
- `user_data`: the ASCII bytes `hardware-attested-statement/v0.1/nitro/key`;
- no `nonce`.

The `user_data` binds the key to this profile and version: verifiers of other profiles or versions reject it.

A document's certificate is short-lived (hours), and the evidence MUST be valid at the statement's upper bound (core
spec section 4). A program SHOULD therefore request a new document for its key at least every hour, put the newest
in each bundle, and have statements that are kept time-stamped while it is valid.

The bundle's `key` is:

```json
{ "profile": "nitro", "attestationDocument": "…" }
```

`attestationDocument`: the COSE_Sign1 structure the NSM returned, exactly as returned.

The **key binding** (core spec section 2) is the COSE_Sign1 payload, exactly as given: the attestation document,
which contains the signing key, the PCRs and the certificate chain, and can't be changed without the signing
certificate's key (unlike the COSE signature, which anyone can turn into another valid one).

## Verification

A verifier MUST reject the key unless:

1. **The COSE_Sign1 structure** is an untagged CBOR array of four items: a protected header of exactly the bytes
   `a1 01 38 22` (`{1: -35}`, ES384), an empty map as unprotected header, the payload as a byte string, and a
   96-byte signature.
2. **The CBOR** of the structure and of the payload is well-formed and uses only definite- or indefinite-length
   arrays, maps, byte strings and text strings, integers, `null`, and no tags; integers and lengths are in shortest
   form, map keys are unique, and nothing follows the structure. Anything else is rejected, not interpreted.
3. **The document** (the payload) is a map with exactly these keys, of these types:
   - `module_id`: text, `i-` followed by 8 to 17 lowercase hex digits, `-enc`, and 16 lowercase hex digits;
   - `timestamp`: an unsigned integer above 0, milliseconds since the Unix epoch;
   - `digest`: the text `SHA384`;
   - `pcrs`: a map of 1 to 32 entries, each from an integer 0–31 to a byte string of 48 bytes;
   - `certificate`: a byte string, the signing certificate;
   - `cabundle`: an array of at least one byte string, certificates from the root down;
   - `public_key`, `user_data` and `nonce`: each a byte string or `null`.
4. **The chain**: `cabundle[0]` is the AWS Nitro Enclaves root (appendix); each later element of `cabundle` is
   signed by the one before it, and `certificate` by the last. Every certificate is strict DER, has an ECDSA P-384
   key, and is signed with ECDSA and SHA-384; every one but `certificate` is a CA. The subject of `certificate` has
   exactly one common name, which is `module_id`, a dot, a region name (lowercase letters, digits and hyphens), and
   `.aws`.
5. **The signature** over the COSE `Sig_structure` (`["Signature1", protected header, empty byte string, payload]`)
   verifies with `certificate`'s key, as ECDSA P-384 with SHA-384, the signature being `r ‖ s` as 48-byte big-endian
   integers.
6. **The key**: `user_data` is exactly `hardware-attested-statement/v0.1/nitro/key`; `public_key` is a strict DER
   SubjectPublicKeyInfo of an uncompressed P-256 point; `nonce` is `null` or absent.
7. **Not debug**: `pcrs` has entries 0, 1 and 2, and none of them is all zero bytes (an enclave run in debug mode
   reports all-zero PCRs).
8. **The signer**: the PCRs match a policy entry (section Policy).

NitroTPM documents, which the root user of any EC2 instance can request with any `public_key` and `user_data`, chain
to the same root through the same kind of certificates. Steps 3 and 4 reject them: their `module_id` has `-tpm`
instead of `-enc`, it is also in their certificate's name, and they carry `nitrotpm_pcrs` instead of `pcrs`.

The evidence is valid while every certificate of the chain is valid. `timestamp`, the NSM's time of the document,
MUST be within the validity of `certificate`. It is reported, but is not a time bound: the key can sign before the
document is made.

AWS publishes no revocation lists for this PKI; its certificates are short-lived instead. This profile uses no
lists.

## Policy

A `trustedSigners` entry names an enclave image by its PCRs, as lowercase hex (48 bytes each):

```json
{ "profile": "nitro", "pcrs": { "0": "…", "1": "…", "2": "…" } }
```

`pcrs` MUST name PCRs 0, 1 and 2 (the image, its kernel and boot ramdisk, and its application), and MAY name others
from 0 to 31 (for example 3, the parent instance's IAM role, or 8, the image's signing certificate). A name that
isn't a decimal integer 0–31 without leading zeros, or a value that isn't 48 bytes, is a policy error. Every PCR the
entry names MUST be present in the document and equal; a missing one doesn't match.

PCR0 alone doesn't name an image: it hashes the kernel, command line and ramdisks as one sequence, so the same bytes
cut differently give the same PCR0. PCR8 alone doesn't either: it names the key that signed the image (any image it
ever signed, however old), and AWS doesn't document that the enclave's launch checks the image's signature.

A program has an entry for each release. Its producer SHOULD build the image reproducibly and publish the expected
PCRs with its source, so that others can check what the entry trusts.

The profile has no settings: `profiles.nitro`, globally and per predicate type, MUST be absent or `{}`.

## What a verifier reports

A verifier MUST report, as the document states them:

- the enclave's `module_id`, and the region in its certificate's name;
- the document's `timestamp`;
- all of its PCRs;
- the period during which the whole chain is valid.

## Appendix: trust anchor

**AWS Nitro Enclaves root** (https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip), SHA-256 of the
DER certificate:

- `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b` (ECDSA P-384,
  `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`, 2019 to 2049)

A verifier MUST take new roots only from its own updates, never from the network. Other AWS partitions (GovCloud,
China) aren't supported.
