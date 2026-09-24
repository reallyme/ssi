# ReallyMe Identity Core

`reallyme-ssi` is the stable Rust facade for the protocol-neutral
identity primitives owned by the `reallyme/ssi` repository. It composes the
credential, DID, presentation, envelope, trust, status, revocation, delivery,
and shared OAuth substrate crates without absorbing their implementation
boundaries.

Consumer-facing Swift, Kotlin, Android, TypeScript, FFI, JNI, and composed Wasm
packages belong in `reallyme/identity`. OpenID endpoint flows and state machines
belong in their protocol repositories.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
