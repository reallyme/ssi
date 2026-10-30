# ReallyMe Identity Core

`reallyme-ssi` is the stable Rust facade for the protocol-neutral
identity primitives owned by the `reallyme/ssi` repository. It composes the
credential, DID, presentation, envelope, trust, status, revocation, delivery,
and shared OAuth substrate crates without absorbing their implementation
boundaries.

Consumer-facing Swift, Kotlin, Android, TypeScript, FFI, JNI, and composed Wasm
packages belong in `reallyme/identity`. OpenID endpoint flows and state machines
belong in their protocol repositories.

## Zero-knowledge presentations

The protobuf presentation contract carries three typed ZK statements:
`ZkPresentation::Credential` for a direct credential claim,
`ZkPresentation::Persona` for a persona-authorized claim, and
`ZkPresentation::CommonRoot` for claims from two credentials linked by one
assured private root. Persona presentations declare `Private` or `Public`
ownership mode. Their nested evidence variant determines
`ZkPresentationProofMode`: a `RequestBoundProof` authenticates the active
request inside the proof, while a `PreparedProof` joins prepared evidence,
current signed status, and the verified request with a live signature by the
key exposed in the proof. The prepared private profile uses a one-time key;
the prepared public profile exposes the reusable persona key. Persona and
common-root packages keep credential subjects and status pointers private.

SSI owns the presentation envelope, protobuf encoding, and protocol-neutral
policy inputs. The ZK verifier authenticates the proof package, its circuit
profile, issuer credentials, and status before those facts are used in a
verification decision.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
