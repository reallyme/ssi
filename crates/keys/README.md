# reallyme-keys

Keyset helpers for ReallyMe identity workflows.

Provides keyset handling for identity workflows using the shared cryptographic and serialization facades. Applications retain responsibility for key storage and lifecycle policy.

Select the `native` or `wasm` feature for the intended Rust provider lane.
The default feature selects `native`; disable default features when selecting `wasm`.

Part of [ReallyMe SSI](https://github.com/reallyme/ssi). Licensed under
MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.
