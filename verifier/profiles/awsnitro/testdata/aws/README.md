Real AWS attestation documents (COSE_Sign1), each base64-decoded from a file of another project, as it was at the
commit named. Each is licensed as its project is; the licences, and NOTICE files where there are any, are in
licenses/.

| File | Kind | From | Licence |
| -- | -- | -- | -- |
| aws-iot.cose | enclave, production | https://github.com/aws-samples/aws-iot-validate-enclave-attestation, commit c31d8ebe714b511afc76502331f06c864ab86207, python/example-attestation-doc.json (member "attestation") | MIT-0 |
| wappie.cose | enclave, production | https://github.com/thehappieco/wappie, commit 4c0d641ed1b8622723ccb4a55174c41e50c35e35, packages/client/testdata/attestation/att.b64 | Apache-2.0 |
| ppmag.cose | enclave, debug | https://github.com/ppmag/aws-nitro-enclaves-attestation, commit 83ca87233298c302973a5bdbbb394c36cd7eb6e6, tests/data/ad_debug_mode.b64 | Apache-2.0 |
| tca.cose | enclave, debug | https://github.com/private-compute-infra-toolkit/transparent-certificate-authority, commit c2ad101c729c8315cf25ccb7f769edd5f6a91447, javatests/com/google/tca/attestation/aws/resources/sample_attestation.b64 | Apache-2.0 |
| evervault-go.cose | enclave, debug | https://github.com/evervault/evervault-go, commit a47d6c0ceebb9b8c715f83617220fe240e683003, internal/attestation/testdata/20250910133616_attestation_doc.txt | MIT |
| biomodel.cose | NitroTPM | https://github.com/aws-samples/sample-mpc-biomodel-ec2-instance-attestation, commit f4f3953a1caa00f7769bb72e8a6f634fe028ce0a, app/frontend/src/services/\_\_tests\_\_/fixtures/liveAttestationDocument.ts (LIVE_ATTESTATION_DOCUMENT_BASE64) | MIT-0 |
| eternis.cose | NitroTPM | https://github.com/EternisAI/attestation-server, commit 242ac80286c7172e4aa3fb7a39f182af8d472ca8, pkg/nitro/testdata/nitrotpm_attestation.json (evidence of kind "nitrotpm") | Apache-2.0 |
