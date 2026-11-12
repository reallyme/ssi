# reallyme-did-core

DID document generation, validation, canonical state, and update logic.

Owns canonical DID state, document structure validation, and update rules. Method-specific behavior is exposed through the separate DID method crates.

Select the `native` or `wasm` feature for the intended Rust provider lane.
The default feature selects `native`; disable default features when selecting `wasm`.

Part of [ReallyMe SSI](https://github.com/reallyme/ssi). Licensed under
MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.
