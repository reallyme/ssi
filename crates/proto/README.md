# reallyme-ssi-proto

Message-only Buffa bindings for SSI-owned, standards-level protobuf packages.

This crate owns all versioned SSI schemas under `proto` and their generated
Rust modules. Generated Rust is committed so downstream consumers can use a
reviewable, reproducible contract without running code generation during
ordinary builds.

The crate deliberately contains no product operation envelopes, domain
validation, provider selection, dispatch, runtime adapter, Connect dependency,
or generated Connect code. `reallyme-ssi-proto-codec` owns bounded validation
and generated-to-domain mappings for SSI messages. `reallyme/identity` owns the
product operation contract, operation codec, dispatch, and provider policy.

SSI does not declare a service contract. Protocol, wallet, service, and SDK
repositories may import these messages into separately generated service
schemas. Product bindings, FFI/JNI/Wasm adapters, Swift, Kotlin/Android, and
TypeScript packaging remain owned by `reallyme/identity`.

`identity.did.v1.DidDocument.context` carries string context IRIs. Inline
JSON-LD object contexts cannot be represented losslessly by that field and
must be preserved outside the generated message or rejected through the
bounded codec with a typed validation error.

## Generated-code hardening

Sensitive generated fields use schema-owned `debug_redact` annotations and the
generator disables owned views so regeneration cannot silently reintroduce
diagnostic or retained-buffer copies. Buffa messages remain
generator-compatible, and authored codecs validate SSI domain invariants before
generated messages cross public boundaries.

Regenerate and verify the canonical artifacts from the repository root with:

```sh
sh scripts/generate-protos.sh
cargo fmt -p reallyme-ssi-proto
node scripts/check-proto-first-boundaries.mjs
```

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
