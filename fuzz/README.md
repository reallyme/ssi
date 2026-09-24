# ReallyMe Identity Fuzz Targets

This crate is intentionally outside the root workspace so fuzz dependencies and
libFuzzer build settings do not leak into release builds.

## Claims Targets

`fuzz_claim_path` exercises claim path parsing, escaping, and canonical ID
round-trips with bounded UTF-8 inputs.

`fuzz_claim_set` exercises untrusted JSON claim payload normalization and
registry-backed semantic validation with bounded byte inputs.

## Credential And Envelope Targets

`fuzz_mdoc_device_response` exercises identity-owned ISO mdoc DeviceResponse
CBOR decoding and re-encoding. COSE primitive fuzzing belongs in
`reallyme/cose`.

`fuzz_parse_tsl_xml` exercises the bounded portable ETSI TSL XML parser with
arbitrary UTF-8 input and compact structure-generation triggers. Its corpus
includes malformed XML, wrong and correct namespaces, entity-bearing XML,
recursive depth, the exact oversized-input boundary, and a valid v6 document.

`fuzz_status_list` exercises bounded status-list structure validation,
deterministic signing-payload construction, and bit lookup.

`fuzz_x509_trust_der` exercises X.509 certificate DER parsing and eIDAS
QCStatements DER parsing. General crypto primitive fuzzing belongs in the
crypto/Jose/Cose repositories.

Run focused checks before launching a long fuzz campaign:

```sh
cargo check --manifest-path fuzz/Cargo.toml
cargo fuzz run fuzz_claim_path
cargo fuzz run fuzz_claim_set
cargo fuzz run fuzz_mdoc_device_response
cargo fuzz run fuzz_parse_tsl_xml
cargo fuzz run fuzz_status_list
cargo fuzz run fuzz_x509_trust_der
```
