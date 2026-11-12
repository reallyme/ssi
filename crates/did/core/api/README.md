# reallyme-did-api

Ergonomic Rust API for ReallyMe DID generation, update, validation, and proto transport.

Composes DID generation, updates, validation, key handling, and protobuf transport over the DID engine and supported method crates. Network transport and application storage remain with the caller.

Select the `native` or `wasm` feature for the intended Rust provider lane.
The default feature selects `native`; disable default features when selecting `wasm`.

Part of [ReallyMe SSI](https://github.com/reallyme/ssi). Licensed under
MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.
