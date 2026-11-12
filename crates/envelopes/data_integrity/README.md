# reallyme-data-integrity

W3C Data Integrity envelope helpers and the ReallyMe did:me proof suite.

Validates the ReallyMe `es256-jws-cid-2025` suite binding DID documents to their current core CID. This crate implements that specific cryptosuite.

Select the `native` or `wasm` feature for the intended Rust provider lane.
The default feature selects `native`; disable default features when selecting `wasm`.

Part of [ReallyMe SSI](https://github.com/reallyme/ssi). Licensed under
MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.
