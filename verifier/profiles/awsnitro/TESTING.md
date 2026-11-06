# Testing plan: `awsnitro` profile

How the verifier's `awsnitro` package ([profile](../../../spec/profiles/awsnitro.md)) is to be tested, to meet
CONTRIBUTING: new behaviour needs tests, a new rejection needs a test that fails without it, and parsers of
untrusted input keep a fuzz target. This file is replaced by the tests and a `testdata/aws/README.md` when the
package lands.

## Principles

- **Every rejection names its rule.** Each verification step returns its own error (a sentinel, or a typed error
  with the step), and every negative test asserts that error, not only that the key was rejected. Otherwise a test
  still passes when the rule it is for is deleted, since a document usually fails more than one step.
- **One fault per negative test.** Each negative case starts from a document that passes every step, and changes one
  thing.
- **A trust seam**, as `android.Trust` is: the root is passed in, so tests can use a test root, and production code
  uses the pinned one.
- **No real clock.** Tests set verification time explicitly, and some set it long after every certificate expired.

## Real documents

Copied in with their licences (Apache-2.0 needs a copy of the licence and the upstream NOTICE, if any; MIT needs its
notice; MIT-0 needs nothing), each with its source URL, commit and SHA-256 in `testdata/aws/README.md`:

| Source                                                          | Licence                 | SHA-256 (prefix) | Kind     | Properties                                                                        |
| --------------------------------------------------------------- | ----------------------- | ---------------- | -------- | --------------------------------------------------------------------------------- |
| aws-samples/aws-iot-validate-enclave-attestation                | MIT-0                   | `ad3e38b5f961`   | enclave  | 2023-06, production, definite-length map, low `s`, no `public_key`                |
| thehappieco/wappie                                              | Apache-2.0              | `fcc16a1cc376`   | enclave  | 2026-09, production, indefinite-length map, RSA `public_key`                      |
| ppmag/aws-nitro-enclaves-attestation                            | Apache-2.0              | `883eaa6cbccb`   | enclave  | 2021-03, debug, definite, high `s`                                                |
| private-compute-infra-toolkit/transparent-certificate-authority | Apache-2.0              | `37af332430bb`   | enclave  | 2025-11, debug, indefinite, RSA `public_key`                                      |
| evervault/evervault-go                                          | MIT                     | `dec4093d7132`   | enclave  | 2025-09, debug, indefinite, high `s`, made 1 h 24 min into its certificate's life |
| aws-samples/sample-mpc-biomodel-ec2-instance-attestation        | MIT-0                   | `dd6d8af26c8d`   | NitroTPM | 2026-08, **P-256 `public_key`**, high `s`                                         |
| EternisAI/attestation-server                                    | Apache-2.0, with NOTICE | `8d02c24a9752`   | NitroTPM | 2026-03                                                                           |

None of them carries this profile's `user_data`, so none can pass. Each is run through the steps one by one, at its
own time, and the test asserts the outcome of each step:

- every enclave document passes steps 1–5 (both encodings, the AWS chain, the COSE signature, high and low `s`);
- the debug documents fail step 7, and the production ones pass it;
- every enclave document fails step 6, with the error for its own fault (`public_key` absent, or not P-256);
- both NitroTPM documents fail step 3 (`nitrotpm_pcrs`, `module_id`), and also step 4 (the certificate's name) when
  step 3 is skipped. The biomodel document is the one that matters: an AWS-signed document with a P-256 key, which
  any instance's root user can make.

Later, one real document from an enclave running a minimal program that follows the profile, made once on AWS, is
the only real positive case: it needs an AWS account and a Nitro-capable instance.

## Test root

A test root, intermediates and leaf generated to look like AWS's chain, as the real documents show it: four CAs
(root, regional, zonal, instance) with path length constraints 2, 1 and 0 below the root, critical key usage on the
CAs, only basic constraints critical on the leaf, P-384 keys and ECDSA SHA-384 signatures, lifetimes like AWS's
(regional 20 days, zonal 5, instance 1, leaf 3 hours), the zonal CA's attribute order, and the leaf's common name
`<module_id>.<region>.aws`. Documents are made with this chain, with the indefinite-length top-level map (and one
with a definite one), a real drand `quicknet` round, and the profile's `user_data`. The test root is never trusted
outside tests, and one test checks that a test-root document is rejected under the pinned root.

## Negative tests, one per rule

- **Step 1**: tagged COSE (tag 18); an array of 3 or 5 items; a protected header other than `a1 01 38 22`; a
  non-empty unprotected header; a signature of 95 or 97 bytes; bytes after the structure; the `key` object with a
  missing or extra member.
- **Step 2**: an indefinite-length item other than the payload's top-level map (a chunked payload byte string, an
  indefinite array); a non-shortest integer or length; a duplicate map key; a tag in the payload; a float, a boolean
  or another simple value; invalid UTF-8; bytes after the payload's map.
- **Step 3**: each key missing; an extra key; `nitrotpm_pcrs` in place of `pcrs`; `module_id` with `-tpm`, with
  uppercase hex, or too short; `timestamp` 0; `digest` other than `SHA384`; a PCR index above 31; a PCR value of 32
  or 64 bytes; an empty `cabundle`; wrong types for each key.
- **Step 4**: `cabundle[0]` not the pinned root; the bundle in reverse order; an intermediate that isn't a CA; a
  path length constraint broken; a leaf that is a CA; a P-256 or RSA key, or a SHA-256 signature, anywhere in the
  chain; a certificate signed by the wrong parent; issuer and subject names that don't chain; a leaf with two common
  names, or a name that doesn't match `module_id`, or a malformed region.
- **Step 5**: a signature over other bytes; a signature by another key.
- **Step 6**: `public_key` null, RSA, P-384, compressed point, explicit curve parameters, or non-strict DER;
  `user_data` null, wrong, or committing to another round; a drand round whose signature is wrong; a round from a
  chain the policy doesn't know, and from one it distrusts; a non-null `nonce`.
- **Step 7**: PCR 0, 1 or 2 missing; each of them zero.
- **Step 8**: a PCR value that differs; a named PCR missing from the document.
- **Validity**: a chain that has expired at the statement's upper bound; a key older than `maxKeyAgeHours` at the
  upper bound, at the boundary and one second past it; `timestamp` outside the leaf's validity.
- **Policy errors**: a PCR name `01`, `16` or `32`; a value of the wrong length or in uppercase hex; an entry
  without PCR 0, 1 or 2, or with one of them zero; `maxKeyAgeHours` 0; unknown settings members.

## Positive tests

- A test-root document with the indefinite-length map, and one with a definite one.
- High and low `s`.
- A bundle time-stamped while its chain was valid, verified long after every certificate expired: catches an
  implementation that checks the chain or `timestamp` against the verification time (for example `x509.Verify` with
  its default time).
- A key exactly `maxKeyAgeHours` old at the statement's upper bound.
- Policy loading: a policy without `awsnitro` settings, or with none for any predicate type, loads (the verifier
  checks every registered profile's settings).
- Reporting: `module_id`, region, `timestamp`, PCRs, the round's time and the chain's validity are reported.

## Fuzzing

Targets for the CBOR reader, the document parser, the strict SubjectPublicKeyInfo parser, and `Binding`, which reads
untrusted input before anything is verified. Seeded with all seven real documents and the test-root ones. A
property: an accepted input with definite lengths encodes back to the same bytes.
