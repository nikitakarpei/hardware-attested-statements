# Proposal: a `tdx` profile for cloud TEEs

Status: proposal, for discussion before any change to what verifies (CONTRIBUTING.md). Nothing here is part of v0.1.
Sources were read on 2026-11-05; claims marked *unconfirmed* could not be checked against a primary source.

## Summary

Add a profile, `tdx`, for programs running in an Intel TDX confidential VM (a *trust domain*, TD): on Google Cloud,
Alibaba Cloud, or self-hosted hardware. The program generates its P-256 signing key inside the TD and binds it into
the TDX quote's `REPORTDATA`; the quote, signed through Intel's DCAP chain, names the program by its measurements
(`MRTD`, `RTMR0`–`RTMR3`). Everything a verifier needs is signed by Intel, so it can be checked against one pinned
root, without trusting the cloud provider's attestation service.

The profile needs three small changes to the core spec (section [Core spec changes](#core-spec-changes)), and one
new policy decision that has no Android counterpart: **which hosts to trust**, since anyone who owns a TDX server
can forge quotes with physical access to it (TEE.fail, 2025).

SEV-SNP and AWS Nitro Enclaves were evaluated and are recommended as later profiles, in that order; see
[Alternatives](#alternatives).

## Why TDX first

|  | Intel TDX (DCAP) | AMD SEV-SNP | AWS Nitro Enclaves | Attestation-service tokens |
| -- | -- | -- | -- | -- |
| Root of trust | Intel | AMD | AWS | the service (Google, Microsoft, Intel ITA) |
| Pins the whole guest image on a public cloud | yes, on GCP: firmware in `MRTD`, kernel, initrd and command line in `RTMR1`–`RTMR2` | no: on AWS and GCP the launch measurement covers only the provider's firmware | yes: `PCR0`–`PCR2` | as the service reports it |
| Collateral authenticated | all signed by Intel (certificates, CRLs, signed JSON) | certificates and CRL signed by AMD; no signed TCB-status list | nothing to fetch; no revocation | service's JWKS or certificate chain |
| Evidence lifetime | PCK certificate years; TCB status changes with Intel's advisories | VCEK about 7 years | leaf certificate about 3 hours | 1–8 hours |
| Algorithms | ECDSA P-256, SHA-256 | ECDSA P-384, RSA-PSS SHA-384 | ECDSA P-384 (COSE, CBOR) | RS256, PS384 |
| New parsing | fixed binary quote, X.509, JSON | fixed binary report, X.509 | CBOR and COSE_Sign1 | JWT |
| Cloud use | GCP, Alibaba, Azure (behind a paravisor, see below) | AWS, Azure, GCP | AWS | per cloud |

TDX is the only option that pins the program on a public cloud against a hardware vendor's root: GCP runs TDX guests
with Google's firmware, which extends the kernel, initrd and command line into the RTMRs, and Google publishes
signed endorsements of its firmware's `MRTD`. With a dm-verity root hash on the kernel command line, the RTMRs cover
the whole disk image. This is what dstack, Tinfoil and Apple's Private Cloud Compute nodes on Google Cloud do (prior
art, below). It also fits the core spec closely: P-256 and SHA-256 throughout, signed lists, and a revocation model
(Intel's TCB status) checked at verification time, as section 3 already requires.

## Prior art

How existing systems bind a key made in a cloud TEE to its attestation, and name the workload:

| System | TEE | Key binding | Workload identity | Later, third-party verification |
| -- | -- | -- | -- | -- |
| RA-TLS (Gramine) | SGX | REPORTDATA = hash of CBOR claims including the key's hash, in an X.509 extension | MRENCLAVE / MRSIGNER | per connection |
| IETF SEAT, draft-fossati-seat-expat-05 | any (RATS CMW) | challenge = Hash(key ‖ TLS exporter) | via RATS reference values | no: bound to one connection |
| dstack (Phala, Flashbots) | TDX | 64 caller bytes, e.g. SHA-512(`ratls-cert:` ‖ key) | MRTD, RTMR0–2 for the OS; RTMR3 event log with compose hash and app ID | via its KMS |
| Phala Confidential AI, NEAR private-ml-sdk | TDX | signer address and nonce in REPORTDATA | dstack measurements | signs request and response hashes: closest to `http-response` |
| Tinfoil | SNP, TDX | SHA-256 of the TLS key (v2: plus an HPKE key) | measurements published as in-toto statements in Sigstore | per session |
| Constellation, Contrast | SNP, TDX | hash of key and nonce; policy hash in HOSTDATA / MRCONFIGID | measured UKI and read-only root | via a coordinator |
| Confidential Containers Trustee | SNP, TDX, … | hash of nonce and key as JWK | reference values in the KBS | an RS256 token |
| Project Oak | SNP, TDX | DICE layers; the report signs the first layer's key | in-toto endorsements, Rekor, SLSA provenance | yes, with endorsements |
| Apple Private Cloud Compute | Apple silicon; TDX on GCP | SEP-attested request key; on GCP TDX + Titan TPM + GPU | release measurements in a transparency log | clients only |
| Oasis ROFL | SGX, TDX | registered key that expires each epoch | on-chain policy | on-chain |
| Evervault, Marlin Oyster | Nitro | `public_key` / `user_data` field | PCR0–2 (a CVE came from checking PCR8 only) | per connection, or receipts |
| Google Confidential Space | SEV, TDX | key hash as a nonce in `eat_nonce` | container image digest | Google-signed token, about 1 hour |
| Azure Attestation | SNP, TDX, SGX | SHA-256 of runtime data in report data | launch measurement, or vTPM PCRs | Microsoft-signed token, 8 hours |
| Town Crier (2016) | SGX | enclave key | MRENCLAVE | signs HTTPS-sourced data: the original design |

What this proposal takes from them:

- **A domain-separated hash of the key in report data** is universal (RA-TLS, Tinfoil, Trustee, Azure). Intel and
  AMD define no layout for it; this profile does, with the version in it, as the Android profile's challenge does.
- **The quote itself as the long-lived evidence**, not a service's token, so verification needs no online service
  and survives it: the tokens of Confidential Space, Azure Attestation and Intel Trust Authority replace Intel's
  root with the service's signing key, and expire within hours.
- **Measurements, not a signing key, name the program.** TDX has no field a vendor key signs, like Android's signing
  certificate. Tinfoil and Oak publish measurements as in-toto statements; a later version could do the same with
  this format (open question 3).
- **Keys expire.** Every system rotates keys (per boot, per session, per epoch); none relies on the quote alone,
  which has no time in it. This profile binds a drand round into the quote, so a key's age is bounded from below by
  something the TD can't forge.
- **Physical attacks are in scope.** TEE.fail (October 2025) extracted the PCK private key of a TDX platform with a
  DDR5 bus interposer costing under $1,000; forged quotes then verified as UpToDate in Intel's own library. Intel
  considers physical attacks out of scope. The Proof of Cloud alliance and Google's confidential host registry
  respond by listing platforms known to be in a cloud's data centre.

## Draft profile text

What follows is written as `spec/profiles/tdx.md` would be, if accepted.

### Key

The program MUST generate its signing key inside the TD, as an ECDSA P-256 key, and MUST NOT export it or let any
other program read it. It MUST NOT run, or create a key, in a TD whose `TDATTRIBUTES` has a debug bit set.

When it creates a key, the program MUST obtain a recent drand round (the key's **startedAfter**) and request a TDX
quote with:

`REPORTDATA = SHA-256("hardware-attested-statement/v0.1/tdx/key" ‖ public key ‖ chain hash ‖ round ‖ round signature) ‖ 32 zero bytes`

where public key is the uncompressed point (65 bytes), chain hash is 32 bytes, round is 8 bytes, and round signature
is the decoded drand signature. This binds the key to this profile and version, and states that it was created no
earlier than the round.

A program MUST create a new key at least every `maxKeyAgeHours` of the strictest policy it targets, and after any
update to the platform's TCB (a new TDX module or microcode), since the quote states the TCB of when it was made.

The bundle's `key` is:

```json
{ "profile": "tdx", "quote": "…", "publicKey": "…",
  "startedAfter": { "drand": { "chain": "<chain hash>", "round": 33638467, "signature": "…" } } }
```

- `quote`: a TDX quote, version 4 or 5, with certification data of type 6 (QE report) holding certification data of
  type 5 (the PCK certificate chain, leaf, intermediate and root, as PEM).
- `publicKey`: the signing key, as the uncompressed point.
- `startedAfter`: a drand round, as in the core spec's `predicate.startedAfter`.

The **key binding** is the bytes the quote's attestation key signs, exactly as carried: the header and the TD quote
body (version 4: bytes 0 to 0x277; version 5: header, body descriptor and body). It contains `REPORTDATA`, which
commits to the signing key, and the measurements and attributes that name the program.

### Verification

A verifier MUST reject the key unless:

01. **The quote's form**: version 4 or 5; attestation key type 2 (ECDSA P-256); TEE type 0x81 (TDX); QE vendor ID
    `939a7233f79c4ca9940a0db3957f0607`; for version 5, a body of type 2 (TDX 1.0) or 3 (TDX 1.5); certification data
    as above, and nothing after it.
02. **The chain**: the PCK certificate is signed by the Intel SGX PCK Platform CA or Processor CA, which is signed
    by the Intel SGX Root CA (appendix); the root in the quote equals the pinned root. Each certificate is strict
    DER, signed with ECDSA P-256 and SHA-256.
03. **The signatures**: the QE report is signed by the PCK certificate's key; the QE report's `REPORTDATA` is
    SHA-256(attestation key ‖ QE authentication data) followed by 32 zero bytes; the key binding is signed by the
    attestation key (ECDSA P-256, SHA-256).
04. **The key**: `REPORTDATA` is as section Key defines, for `publicKey` and `startedAfter`; the round passes the
    core spec's drand checks, from a chain the policy trusts.
05. **The TD**: no debug bit (`TDATTRIBUTES` bits 0–7) set, and not migratable (bit 29) unless the policy allows it.
06. **The TCB**, against Intel's current TCB Info for the PCK certificate's FMSPC (type `TDX`, version 3): the
    highest TCB level that the PCK certificate's SGX TCB components and PCE SVN and the quote's `TEE_TCB_SVN` all
    meet has a status the policy allows; `MRSIGNERSEAM` and the masked `SEAMATTRIBUTES` match the TDX module
    identity it names. The matching rules are those of Intel's quote verification library, to be written out here in
    full before this profile is accepted.
07. **The quoting enclave**, against Intel's current QE Identity (`TD_QE`): its `MRSIGNER` and `ISVPRODID` equal,
    its masked `MISCSELECT` and attributes match, and the level its `ISVSVN` meets is UpToDate.
08. **Revocation**: neither the PCK certificate nor its CA is on the PCK CRL of that CA or on the root CA's CRL.
09. **The host**: the platform is one the policy trusts (section Hosts).
10. **The signer**: the measurements match a policy entry (section Policy).

The evidence is valid from the `startedAfter` round's time until `maxKeyAgeHours` later, and while every certificate
of the chain is valid.

**Lists.** TCB Info, QE Identity and the CRLs are lists in the core spec's sense (section 3), and are all
authenticated: each is signed by a key that chains to the pinned root (TCB Info and QE Identity by the Intel SGX TCB
Signing certificate, over their `tcbInfo` or `enclaveIdentity` member's bytes exactly as received). So a verifier
MAY take them from any source (Intel's PCS, a caching service, a copy). It MUST reject one past its signed
`nextUpdate`, and one older than `maxListAgeHours` (core spec section 3). A TCB Info with a lower
`tcbEvaluationDataNumber` than the policy's minimum counts as not obtained.

**Hosts.** Anyone with physical access to a TDX platform can extract its PCK key and forge quotes for any
measurements, so evidence says nothing more than *some* TDX platform signed it. A policy MUST therefore either name
host lists, whose platforms (by the PCK certificate's PPID) it trusts, or explicitly accept any host. *v0.1 would
define no host list:* neither Google's confidential host registry nor Proof of Cloud documents a signed format (open
question 1).

### Policy

A `trustedSigners` entry names a program by its measurements, as lowercase hex:

```json
{ "profile": "tdx", "mrtd": "…", "rtmrs": ["…", "…", "…", "…"],
  "mrConfigId": "…", "mrOwner": "…", "mrOwnerConfig": "…" }
```

`mrtd` and `rtmrs` (exactly four) MUST match exactly. The others, if given, MUST match; if not, they aren't checked.
A program has as many entries as it has releases and VM shapes (`RTMR0` depends on the VM's size). Producers SHOULD
build reproducibly and publish the expected values with their source, as dstack and Tinfoil do.

Settings go under `profiles.tdx`, merged as the core spec says:

```json
{ "tcbStatuses": ["UpToDate"], "minTcbEvaluationDataNumber": 0, "allowMigratable": false,
  "hosts": { "any": false, "lists": [] }, "maxKeyAgeHours": 24, "maxListAgeHours": 48 }
```

- `tcbStatuses`: the statuses accepted. `SWHardeningNeeded` MAY be added; `Revoked` MUST NOT.
- `hosts` is replaced as a whole, MUST have both members, and MUST accept some host: with the defaults, a policy
  that doesn't set it is an error.
- `maxKeyAgeHours` MUST be at least 1. A TD has no clock the verifier can trust, so this, not the quote, ends the
  evidence's validity.

### What a verifier reports

The measurements and attributes, the TCB status and its advisory IDs, the TCB evaluation data number, the FMSPC and
PPID and which host list (if any) named it, when the key was created at the earliest (its round's time), and when
the lists used were obtained.

### Appendix: trust anchor

**Intel SGX Root CA**
(https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer, valid 2018-05-21 to
2049-12-31), SHA-256 of the DER certificate: `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`
(computed from Intel's file; Intel publishes no fingerprint as text).

## Core spec changes

1. **Section 3, the key.** It says "a P-256 key generated by the hardware, which can't leave it". In a TEE, a
   program the hardware measured generates the key in memory the hardware isolates, and keeps it there; the
   guarantee rests on that program as well. Proposed: "generated by the hardware, or by a program the evidence
   names, in memory the hardware isolates; which can't leave it …". Section 7 then adds that a TEE program's key is
   as safe as the program and its image.
2. **Section 3, the key binding.** "contain the signing key" becomes "contain, or commit to by hash, the signing
   key" (TDX's `REPORTDATA` has 64 bytes).
3. **Section 3, lists.** Add: a list signed by a key the profile pins is authenticated, MAY come from any source,
   and is also rejected after a validity end it states.
4. **Section 7, trust model.** Add the hosts: evidence of TDX (and SNP) is as good as the physical security of the
   least trusted host a policy accepts.

Profile-specific drand rounds in key evidence reuse the core's drand checks and the policy's `drandChains`; the
verifier would need to give profiles access to them (`verifier.Profile.VerifyKey` gets the policy's chains).

## Alternatives

- **AMD SEV-SNP** (`sev-snp`): second. The same key binding works (`REPORT_DATA`, 64 bytes), and AMD's chain (ARK,
  ASK or ASVK, VCEK or VLEK, RSA-PSS SHA-384, CRL) is easy to pin. But on AWS and GCP the launch measurement covers
  only the provider's firmware, not the kernel, and Azure puts a Microsoft paravisor there; so on those clouds it
  can't name the program without a vTPM, which on Azure is Microsoft's software. It fits self-hosted guests with
  measured direct boot (QEMU `kernel-hashes=on`), and AWS's VLEK states that a report came from AWS's fleet. The
  reporting VM can lower `REPORTED_TCB`, so minimums apply to it and to the certificate's TCB.
- **AWS Nitro Enclaves** (`nitro`): third. A good fit: `public_key` and `user_data` fields, PCR0–2 for the image and
  PCR8 for its signing certificate (like Android's), a pinned root (`AWS_NitroEnclaves_Root-G1`, valid to 2049). But
  the root of trust is AWS as both hardware vendor and operator, there is no revocation, leaf certificates live
  about 3 hours (so every bundle needs a time-stamp within hours), and it needs a CBOR and COSE parser.
- **Attestation-service tokens** (Confidential Space, Azure Attestation, Intel Trust Authority): not recommended.
  They make the service the root of trust and expire within hours. Confidential Space's PKI tokens could be a
  separate profile if a use case needs it.
- **Azure TDX and SNP confidential VMs**: not supported. The quote measures Microsoft's paravisor, and the guest
  only through vTPM PCRs and Azure-signed keys.
- **Arm CCA, NVIDIA GPUs**: no cloud offers CCA realms; GPU evidence would be an input to a CPU profile, as Apple's
  PCC nodes on Google Cloud do. Later.

## Implementation plan

A package `verifier/profiles/tdx`, with no new dependency: the quote is a fixed binary layout; X.509, CRLs and ECDSA
are in Go's standard library, and the SGX extensions parse with `golang.org/x/crypto/cryptobyte`, already a
dependency. `LoadTrust` fetches TCB Info, QE Identity and the CRLs from Intel's PCS, or takes copies. Tests: real
quotes (go-tdx-guest's test data, Apache-2.0) with collateral captured at a fixed time, and quotes made under a test
root for each rejection; fuzz targets for the quote and collateral parsers.

## Open questions

1. **Host lists.** Is Google's confidential host registry (`storage.googleapis.com/confidential-host-registry`)
   signed, and in what format? Will Proof of Cloud publish its signed log? Until one is usable, every policy has to
   accept any host, which this proposal makes an explicit choice.
2. **TCB changes invalidate old bundles.** Checking TCB status at verification time means that once Intel marks a
   platform's TCB out of date, every bundle it ever signed stops verifying, as revocation does today. Is that the
   intended meaning, or should a time-stamp before the advisory's date keep them valid?
3. **Endorsed measurements.** Pinning measurements means a policy update per release. Should a later version accept
   measurements endorsed by a statement in this format (a predicate type for reference measurements, signed by a
   builder), as Tinfoil and Oak do with in-toto?
4. **Event log.** Should the evidence carry the TD's event log, so a verifier can report what each RTMR holds (for
   example dstack's compose hash), and policies can name parts of `RTMR3`?

## Sources

- Intel TDX DCAP Quoting Library API, rev 0.9 (May 2025):
  https://download.01.org/intel-sgx/sgx-dcap/1.23/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
- Intel PCS: https://api.portal.trustedservices.intel.com/content/documentation.html
- go-tdx-guest: https://github.com/google/go-tdx-guest; go-sev-guest: https://github.com/google/go-sev-guest
- GCP firmware endorsements:
  https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware; TDX provenance:
  https://codelabs.developers.google.com/codelabs/tdx-cvm-attestation-and-provenance
- Azure guest attestation:
  https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
- AWS SEV-SNP: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snp-attestation.html; Nitro Enclaves:
  https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html,
  https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
- AMD SEV-SNP ABI 56860 (rev 1.55 read; 1.58 *unconfirmed*, via go-sev-guest)
- TEE.fail: https://tee.fail/; Intel's statement:
  https://intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2025-10-28-001.html;
  Battering RAM: https://batteringram.eu/; BadRAM: https://badram.eu/; WireTap: https://wiretap.fail/; DDRop
  (*unconfirmed*, secondary sources): https://ddropattack.eu/
- Proof of Cloud: https://proofofcloud.org/; Data Center Execution Assurance: https://arxiv.org/abs/2510.12469
- IETF RATS: RFC 9334, RFC 9711; SEAT: https://datatracker.ietf.org/group/seat/documents/
- RA-TLS: https://gramine.readthedocs.io/en/stable/attestation.html; dstack:
  https://docs.phala.com/phala-cloud/attestation/attestation-fields; Phala signed responses:
  https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-signature; Tinfoil:
  https://docs.tinfoil.sh/verification/predicate; Contrast:
  https://docs.edgeless.systems/contrast/architecture/attestation/overview; Trustee:
  https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs_attestation_protocol.md; Oak:
  https://github.com/project-oak/oak/blob/main/proto/attestation/endorsement.proto; Apple PCC:
  https://security.apple.com/documentation/private-cloud-compute; Oasis ROFL: https://docs.oasis.io/build/rofl/app;
  Evervault: https://docs.evervault.com/security/cages-attestation-in-tls; Town Crier:
  https://eprint.iacr.org/2016/168.pdf
- Confidential Space token claims:
  https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims; Azure
  Attestation: https://learn.microsoft.com/en-us/azure/attestation/faq; Intel Trust Authority:
  https://docs.trustauthority.intel.com/main/articles/concept-attestation-tokens.html
