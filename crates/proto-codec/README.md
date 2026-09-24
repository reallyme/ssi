# reallyme-ssi-proto-codec

`reallyme-ssi-proto-codec` provides bounded validation, zeroizing ownership,
and domain conversions for SSI protobuf messages used by ReallyMe Identity.

The package sits between generated wire messages and strongly typed domain
models. It rejects malformed, oversized, and semantically invalid inputs at the
serialization boundary. Application developers should normally depend on
[`reallyme-identity`](https://crates.io/crates/reallyme-identity) instead of
using this support crate directly.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
