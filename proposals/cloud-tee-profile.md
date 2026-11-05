# Proposal: cloud TEE profiles, starting with `nitro`

Status: proposal, for discussion before any change to what verifies (CONTRIBUTING.md). Nothing here is part of v0.1.
Sources were read on 2026-11-05; claims marked *unconfirmed* could not be checked against a primary source, and
*observed* ones come from real documents, not from their vendor's documentation.

## Summary

Add a profile, `nitro`, for programs running in an AWS Nitro Enclave. The program generates its P-256 signing key
inside the enclave and asks the enclave's Nitro Secure Module (NSM) for an attestation document carrying that key.
The document, signed through AWS's Nitro attestation PKI, names the program by the measurements of its enclave image
(`PCR0`–`PCR2`). A verifier checks it against one pinned AWS root, with no lists to fetch.

The root of trust is AWS, as hardware vendor and as operator. That is a real cost, but a smaller one than it looks:
for every cloud TEE, the cloud's physical security is already trusted (section [Why Nitro first](#why-nitro-first)),
and Nitro is the only option today that also names the program and the host.

Intel TDX on Google Cloud (`tdx`) and AMD SEV-SNP (`sev-snp`) follow, once the blockers in
[Later profiles](#later-profiles) are resolved. This proposal was reviewed adversarially and fact-checked; the
findings changed its first draft (TDX first) to this one.

## Why Nitro first

A statement from a cloud TEE is only worth something if the evidence names both **which program** signed (so the key
can't come from other code) and **which host** ran it (so the key can't come from a machine someone has physical
access to). TEE.fail (October 2025) extracted the attestation key of an Intel TDX platform with a DDR5 bus
interposer costing under $1,000; forged quotes then verified as UpToDate in Intel's own library, and Intel considers
physical attacks out of scope. DDRop (September 2026) forced a TD into debug mode with a similar device. So evidence
from TDX or SEV-SNP proves no more than "some platform signed this", unless a policy can also tell the platform is
in a data centre it trusts.

|  | Names the program | Names the host | Root of trust |
| -- | -- | -- | -- |
| AWS Nitro Enclaves | yes: `PCR0`–`PCR2` measure the enclave image | yes: only AWS's Nitro hardware holds keys under its root | AWS |
| Intel TDX on GCP | yes: firmware in `MRTD`; boot loader, kernel, initrd and command line in `RTMR1`–`RTMR2` via measured boot | no: Google's host registry is an unsigned lookup; Proof of Cloud publishes no format | Intel, plus Google's firmware and physical security |
| AMD SEV-SNP on AWS | no: the launch measurement covers only AWS's firmware, which then boots any AMI unmeasured | yes: the VLEK is issued by AMD for AWS's fleet | AMD, plus AWS's firmware and physical security |
| Attestation-service tokens (Confidential Space, Azure Attestation, Intel Trust Authority) | as the service reports it | as the service reports it | the service; tokens expire in minutes to hours |

So:

- **TDX on GCP** names the program but not the host: anyone with a used Xeon server can forge.
- **SEV-SNP on AWS** names the host but not the program: every SNP guest on AWS has the same measurement, whatever
  it boots, so anyone who rents one can bind any key. AWS documents no custom firmware, measured direct boot or
  NitroTPM binding for SNP instances.
- **Nitro** names both, at the price of trusting AWS's software (the Nitro hypervisor and the NSM) as well as its
  data centres. What TDX would add is protection from the cloud's software and from insiders without hardware
  access; it can't be had yet without a host signal.

Nitro also fits this format simply: the attestation document has a `public_key` field for the signing key itself,
the whole certificate chain is inside the signed payload, and there are no lists. Its costs: no revocation, leaf
certificates that are short-lived (about 3 hours, *observed*), so bundles need a time-stamp within that time, and a
strict CBOR and COSE parser.

## Prior art

How existing systems bind a key made in a cloud TEE to its attestation, and name the workload:

| System | TEE | Key binding | Workload identity | Later, third-party verification |
| -- | -- | -- | -- | -- |
| Evervault Enclaves | Nitro | TLS key in `public_key`; nonce from the hostname | PCR0–2 from a reproducible build | per connection |
| Marlin Oyster | Nitro | key in `user_data` | PCR0–2 (docs warn that checking PCRs without `user_data` is the common mistake) | signed receipts |
| Signal SVR3 | SGX, SNP, Nitro | per protocol | MRENCLAVE; reproducible EIF PCRs for Nitro | no |
| AWS KMS | Nitro | RSA key in `public_key`, to encrypt responses | key-policy conditions on PCRs | no |
| RA-TLS (Gramine) | SGX | REPORTDATA = hash of CBOR claims including the key's hash | MRENCLAVE / MRSIGNER | per connection |
| IETF SEAT, draft-fossati-seat-expat-05 | any (RATS CMW) | challenge = Hash(key ‖ TLS exporter) | via RATS reference values | no: bound to one connection |
| dstack (Phala, Flashbots) | TDX | 64 caller-chosen bytes | MRTD, RTMR0–2 for the OS; RTMR3 event log with compose hash and app ID | via its KMS |
| Phala Confidential AI, NEAR private-ml-sdk | TDX | signer address and nonce in REPORTDATA | dstack measurements | signs request and response hashes: closest to `http-response` |
| Tinfoil | SNP, TDX | SHA-256 of the TLS key (v2: plus a raw HPKE key) | measurements published as in-toto statements in Sigstore | per session |
| Constellation, Contrast | SNP, TDX | hash of key and nonce; policy hash in HOSTDATA / MRCONFIGID | measured UKI and read-only root | via a coordinator |
| Confidential Containers Trustee | SNP, TDX, … | hash of nonce and key as JWK | reference values in the KBS | an RS256 token |
| Project Oak | SNP, TDX | DICE layers; the report signs the first layer's key | in-toto endorsements, Rekor, SLSA provenance | yes, with endorsements |
| Apple Private Cloud Compute | Apple silicon; Google Cloud | SEP-attested request key | release measurements in a transparency log; an "append-only ledger of all Google Cloud hardware" | clients only |
| Oasis ROFL | SGX, TDX | registered key that expires each epoch | on-chain policy | on-chain |
| Google Confidential Space | SEV, TDX | key hash as a nonce in `eat_nonce` | container image digest | Google-signed token, about 1 hour |
| Azure Attestation | SNP, TDX, SGX | SHA-256 of runtime data in report data | launch measurement, or vTPM PCRs | Microsoft-signed token, 8 hours |
| Intel Trust Authority | TDX, SGX | hash of nonce and held data | quote measurements | PS384 token, minutes |
| Town Crier (2016) | SGX | enclave key | MRENCLAVE | signs HTTPS-sourced data: the original design |

What this proposal takes from them:

- **The key itself, or a domain-separated hash of it, in the attestation**: universal. Nitro has a field for the
  key, so this profile puts the key there and a challenge naming the format and version next to it.
- **Every PCR a policy names must be present and equal.** CVE-2025-64186 (Evervault) came from PCRs missing from a
  document being treated as matching.
- **The attestation itself as the long-lived evidence**, not a service's token, so verification needs no online
  service.
- **Measurements, not a vendor key, name the program** (see open question 2 on `PCR8`). Tinfoil and Oak publish
  measurements as in-toto statements; a later version could accept measurements endorsed that way.
- **The image is the boundary.** In every TEE, any code inside it can ask for an attestation with values it chooses;
  dstack's `GetQuote`, for example, takes caller-chosen report data. So the image, not the verifier, must make sure
  only the program's own key is ever attested.
- **Host identity is a requirement**, after TEE.fail: the Proof of Cloud alliance, Google's confidential host
  registry and Apple's ledger of Google Cloud hardware all try to supply it for TDX and SNP.

## Draft profile text

What follows is written as `spec/profiles/nitro.md` would be, if accepted.

### Key

The program MUST generate its signing key inside the enclave, as an ECDSA P-256 key, and MUST NOT export it or use
it for anything but these statements. The enclave image MUST NOT run code that lets anyone else choose what the NSM
attests: any process in the enclave can ask the NSM for a document with any `public_key` and `user_data`. The image
MUST NOT be built or run in debug mode.

For each key, the program requests attestation documents from the NSM with:

- `public_key`: the signing key, as a DER SubjectPublicKeyInfo (id-ecPublicKey, prime256v1, uncompressed point);
- `user_data`: the ASCII bytes `hardware-attested-statement/v0.1/nitro/key`, which bind the key to this profile and
  version;
- no `nonce`.

A document's certificate is short-lived (about 3 hours, *observed*), and a bundle's evidence MUST be valid at its
upper bound (core spec section 4). So the program SHOULD request a new document for its key at least every hour, put
the newest one in each bundle, and have its statements time-stamped promptly; a bundle without a time-stamp stops
verifying when its document's certificate expires.

The bundle's `key` is:

```json
{ "profile": "nitro", "attestationDocument": "…" }
```

`attestationDocument`: the COSE_Sign1 structure the NSM returned, exactly as returned.

The **key binding** is the COSE_Sign1 payload, exactly as carried: the attestation document, which contains the
signing key, the challenge, the PCRs and the certificate chain. The COSE signature isn't part of it, since anyone
can turn an ECDSA signature into another valid one.

### Verification

A verifier MUST reject the key unless:

1. **The COSE_Sign1 structure** is a CBOR array of four items: a protected header of exactly the bytes `a1 01 38 22`
   (`{1: -35}`, ES384), an empty unprotected header map, the payload as a byte string, and a 96-byte signature.
   Whether the NSM's output carries CBOR tag 18 is to be fixed against real documents before acceptance.
2. **The CBOR** is well-formed and in the subset this profile allows (definite lengths, shortest-form integers, no
   duplicate map keys, no tags inside the payload); anything else is rejected, not interpreted.
3. **The document** is a map with exactly these keys, of these types: `module_id` (non-empty text), `timestamp`
   (unsigned integer, milliseconds since the Unix epoch, above 0), `digest` (the text `SHA384`), `pcrs` (a map of 1
   to 32 entries, from integers 0–31 to 48-byte strings), `certificate` (byte string), `cabundle` (array of at least
   one byte string), and `public_key`, `user_data` and `nonce`, each a byte string or null. A document with
   `nitrotpm_pcrs`, or any other key, is rejected: NitroTPM documents, which the parent EC2 instance can request
   with any fields, chain to the same root.
4. **The chain**: `cabundle[0]` is AWS's Nitro Enclaves root (appendix); `certificate` is signed by the last element
   of `cabundle`, each element by the one before it. Each certificate is strict DER, with an ECDSA P-384 key, signed
   with ECDSA and SHA-384.
5. **The signature**: the COSE signature verifies, with `certificate`'s key, over the COSE `Sig_structure`
   (`["Signature1", protected, h'', payload]`), as ECDSA P-384 with SHA-384, `r ‖ s` as 48-byte big-endian integers.
6. **The key**: `user_data` is exactly the challenge; `public_key` is a DER SubjectPublicKeyInfo of an uncompressed
   P-256 point; `nonce` is null or absent.
7. **Not debug**: `PCR0`, `PCR1` and `PCR2` are present and not all zero bytes.
8. **The signer**: the PCRs match a policy entry (section Policy).

The evidence is valid while every certificate of the chain is valid. `timestamp` MUST be within the validity of
`certificate`; it is AWS's time of the document, and is reported, but bounds nothing, since the key may have signed
before the document was made.

There is no revocation: AWS publishes no revocation lists and documents that CRL checking must be disabled.
Short-lived certificates take their place, and this profile uses no lists.

### Policy

A `trustedSigners` entry names an enclave image by its PCRs, as lowercase hex (48 bytes each):

```json
{ "profile": "nitro", "pcrs": { "0": "…", "1": "…", "2": "…" } }
```

`pcrs` MUST name `0`, `1` and `2`, and MAY name others (for example `3`, the parent instance's IAM role, or `8`, the
image's signing certificate). Every PCR named MUST be present in the document and equal; a missing one is a
mismatch. A program has an entry for each release; producers SHOULD build reproducibly and publish the expected PCRs
with their source.

The profile has no settings: `profiles.nitro`, if given, MUST be `{}`.

### What a verifier reports

A verifier MUST report the document's `module_id` and `timestamp`, all of its PCRs, and the chain's validity period.

### Appendix: trust anchor

**AWS Nitro Enclaves root** (`CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`, from
https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip, ECDSA P-384, valid 2019-10-28 to
2049-10-28), SHA-256 of the DER certificate: `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.

## Core spec changes

1. **Section 3, the key.** It says "a P-256 key generated by the hardware, which can't leave it". In a TEE, a
   program the hardware measured generates the key in memory the hardware isolates, and keeps it there. Proposed:
   "generated by the hardware, or by a program the evidence names, in memory the hardware isolates; which can't
   leave it …".
2. **Section 7, trust model.** Add: a TEE program's key is as safe as its whole image, including every input the
   image reads that isn't measured; and for Nitro, AWS's hypervisor and NSM are trusted, as Google's hardware and
   software are for Android.

The first draft's other two changes (a key binding that commits to the key by hash; signed lists from any source)
are not needed for `nitro`. The second would also have weakened the Android profile: its GrapheneOS boot-key list is
signed, but its signed `timestamp` can't show freshness, which is why it must be fetched afresh.

## Later profiles

**`tdx`** (Intel TDX, on Google Cloud and self-hosted). The review found these blockers:

- **Hosts.** Without a signed list of trusted platforms (by the PCK certificate's PPID), every policy would have to
  accept any host, so anyone with physical access to any TDX server could forge. Google's registry
  (`storage.googleapis.com/confidential-host-registry/<PPID>`) documents no signature; Proof of Cloud publishes no
  format or key. A second binding of the same key through Google's vTPM is another option. Hosts on the list must be
  removable, since clouds resell retired hardware.
- **The TCB.** `TEE_TCB_SVN` is fixed when the TD launches (TDX 1.5 adds `TEE_TCB_SVN_2` for the module running
  after an update), so after a TCB update the TD must relaunch, not only make a new key. The matching rules (module
  identities `TDX_01`, `TDX_03`, statuses including `TDRelaunchAdvised` and `*ConfigurationNeeded`) must be written
  out in full.
- **TCB status over time.** Intel recovers the TCB two or three times a year (evaluation numbers 13 to 22 from
  2022-08 to 2026-08); "early" collateral changes on the event's date, "standard" about a year later. Judged at
  verification time, every bundle from a platform stops verifying at the next recovery it doesn't meet. Judged at
  the statement's upper bound (Intel serves past evaluation numbers), archived bundles keep verifying, but trust
  that the flaw wasn't exploited before its disclosure. This must be decided before acceptance.
- **The key binding** must cover the PCK certificate (PPID, FMSPC, TCB components), not only the quote's header and
  body, since the core spec requires it to state what the evidence says about the device.
- **Collateral freshness**: take a list's age from its signed `issueDate` or `thisUpdate` (Intel reissues TCB Info,
  QE Identity and the PCK CRL daily), require its `fmspc`, `pceId` and identity fields to match the quote, and ship
  a minimum `tcbEvaluationDataNumber` with each verifier release.
- **Identity**: pin `TDATTRIBUTES`, `XFAM`, `MRCONFIGID`, `MROWNER`, `MROWNERCONFIG` (all-zero unless named; on GCP
  `MROWNER` is per instance) and, in quote v5, `MRSERVICETD`; forbid migratable TDs. Real quotes end their PEM chain
  with a NUL byte, which the parser must allow.

**`sev-snp`** (AMD SEV-SNP). It needs a cloud that both issues a VLEK and lets the customer's kernel and image be
measured at launch; none documents both today. On self-hosted hardware, with measured direct boot (QEMU
`kernel-hashes=on`), it has the same host problem as TDX. The reporting VM can lower `REPORTED_TCB`, so minimums
apply to it and to the certificate's TCB.

Not planned: Azure confidential VMs (the hardware report measures Microsoft's paravisor, and the guest only through
its vTPM); attestation-service tokens (the service becomes the root of trust); Arm CCA (no cloud offers it); GPUs
(evidence for an input to a CPU profile, later).

## Implementation plan

A package `verifier/profiles/nitro`, with no new dependency:

- a strict CBOR reader for the subset above, hand-written as the Android profile's DER reader is, with a fuzz
  target;
- COSE_Sign1 verification with `crypto/ecdsa` (P-384, `r ‖ s`), and the chain with `crypto/x509`;
- no `LoadTrust`: the root is built in, and there are no lists.

`verifier.New` checks every registered profile's settings even for policies that don't use it; with no settings
(`{}` or absent) this profile passes, so Android-only policies keep loading.

Tests: real attestation documents (to be found under a license that allows them, for example in AWS's or others'
open-source test data), checked with a fake clock at their time; and documents made under a test root for each
rejection: wrong protected header, extra or missing keys, NitroTPM documents, a missing named PCR, zero PCRs, a
wrong challenge, a key that isn't P-256, a broken chain.

## Open questions

1. **Where this lives.** CONTRIBUTING asks for an issue before changing what verifies; this file could become that
   issue.
2. **`PCR8`.** It measures the image's signing certificate, and would name a program across releases as Android's
   signing certificate does. But AWS doesn't document whether the Nitro hypervisor verifies the image's signature at
   launch, or only `nitro-cli` on the untrusted parent instance does. If only the latter, anyone could attach a
   public signing certificate to another image, and `PCR8` alone would name nothing. Until AWS confirms the former,
   entries must name `PCR0`–`PCR2`.
3. **NitroTPM documents.** Is the field name (`pcrs` against `nitrotpm_pcrs`) the only difference, or do the leaf
   certificates differ too? The profile should reject NitroTPM documents by more than one property if it can.
4. **Unknown document keys.** Rejecting them is strict, but if AWS adds a field, all new documents stop verifying.
   Ignoring them risks accepting a document whose meaning changed.
5. **Short-lived certificates.** Should the profile require a time-stamp (as if `requireTimestamp` were set), since
   without one a bundle verifies for about 3 hours?

## Sources

- AWS Nitro Enclaves: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html,
  https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html,
  https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md,
  https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves, `PCR8`
  computation: https://github.com/aws/aws-nitro-enclaves-cli/issues/446
- NitroTPM: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html,
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-content.html
- AWS SEV-SNP: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snp-attestation.html,
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html, https://github.com/aws/uefi/issues/23
- AMD: SEV-SNP ABI 56860 (rev 1.55 read); VLEK certificate definition 58369:
  https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/user-guides/58369-010-versioned-loaded-endorsement-key-certificate-definition.pdf;
  go-sev-guest: https://github.com/google/go-sev-guest
- Intel TDX: Quoting Library API, rev 0.9:
  https://download.01.org/intel-sgx/sgx-dcap/1.23/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf; PCS:
  https://api.portal.trustedservices.intel.com/content/documentation.html; TCB evaluation numbers:
  https://api.trustedservices.intel.com/tdx/certification/v4/tcbevaluationdatanumbers; Linux TDX documentation:
  https://www.kernel.org/doc/html/latest/arch/x86/tdx.html; go-tdx-guest: https://github.com/google/go-tdx-guest
- Google Cloud: https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware,
  https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/tdx-provenance; Confidential Space:
  https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims
- Azure:
  https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design,
  https://learn.microsoft.com/en-us/azure/attestation/faq; Intel Trust Authority:
  https://docs.trustauthority.intel.com/main/articles/concept-attestation-tokens.html
- Attacks: TEE.fail: https://tee.fail/; Intel's statement:
  https://intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2025-10-28-001.html;
  DDRop: https://ddropattack.eu/; Battering RAM: https://batteringram.eu/; BadRAM: https://badram.eu/
- Host identity: Proof of Cloud: https://proofofcloud.org/; Data Center Execution Assurance:
  https://arxiv.org/abs/2510.12469; Apple: https://security.apple.com/blog/expanding-pcc
- Prior art: Evervault: https://docs.evervault.com/security/cages-attestation-in-tls; Marlin:
  https://docs.marlin.org/oyster/core-concepts/remote-attestations; Signal:
  https://github.com/signalapp/SecureValueRecovery2; RA-TLS:
  https://gramine.readthedocs.io/en/stable/attestation.html; SEAT:
  https://datatracker.ietf.org/group/seat/documents/; dstack:
  https://docs.phala.com/phala-cloud/attestation/attestation-fields; Phala signed responses:
  https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-signature; Tinfoil:
  https://docs.tinfoil.sh/verification/predicate; Contrast:
  https://docs.edgeless.systems/contrast/architecture/attestation/overview; Trustee:
  https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs_attestation_protocol.md; Oak:
  https://github.com/project-oak/oak/blob/main/proto/attestation/endorsement.proto; Apple PCC:
  https://security.apple.com/documentation/private-cloud-compute; Oasis ROFL: https://docs.oasis.io/build/rofl/app;
  Town Crier: https://eprint.iacr.org/2016/168.pdf; IETF RATS: RFC 9334, RFC 9711
