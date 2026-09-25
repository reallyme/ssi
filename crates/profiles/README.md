# ReallyMe OpenID4VC Profiles

Shared HAIP and EUDI profile identity for OpenID4VCI and OpenID4VP.

`reallyme-openid4vc-profiles` gives issuance and presentation implementations
one canonical vocabulary for cross-protocol interoperability profiles. It owns
stable profile names and identifiers; protocol-specific requirements remain in
their respective OpenID4VCI and OpenID4VP implementations.

Looking for the application-facing SDK layer? Start with
[ReallyMe Identity](https://github.com/reallyme/identity).

## Scope

| This crate owns | This crate does not own |
| --- | --- |
| Shared HAIP and EUDI PID profile identities | OpenID4VCI issuance policy |
| Canonical profile names and versions | OpenID4VP presentation policy |
| Stable display and short names | Credential formats or cryptography |
| Serde-compatible profile types | Conformance execution or trust decisions |

Keeping this boundary small prevents the issuance and presentation stacks from
defining incompatible identities for the same interoperability profile.

## Installation

```toml
[dependencies]
reallyme-openid4vc-profiles = "0.1.0"
```

## Usage

```rust
use reallyme_openid4vc_profiles::{Profile, HAIP_PROFILE_NAME, HAIP_VERSION};

assert_eq!(Profile::Haip.display_name(), HAIP_PROFILE_NAME);
assert_eq!(Profile::Haip.short_name(), "HAIP");
assert_eq!(HAIP_VERSION, "1.0");
```

The `native` and `wasm` features allow higher-level ReallyMe crates to keep
their platform feature graphs aligned. They do not change profile semantics.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
