# reallyme-trust-x509

**Portable X.509 parsing and policy for identity trust decisions**

`reallyme-trust-x509` parses certificates, verifies bounded chain signatures,
and evaluates data-driven certificate policy. It includes eIDAS and EUDI
profiles, qualified-certificate statement parsing, and typed trusted-list
service projections.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when implementing the X.509 parsing and policy boundary.

## Scope

| This crate provides | The host application provides |
| --- | --- |
| Bounded DER and PEM parsing | Certificate and trusted-list retrieval |
| Certificate metadata and QCStatements | Path discovery and trust-store management |
| eIDAS/EUDI policy presets | Application trust policy |
| Portable chain-signature verification | Final trust decisions |

## Install

```toml
[dependencies]
reallyme-trust-x509 = "0.7.0"
```

The default feature set supports parsing without a cryptographic provider.
Enable `native` for native signature verification, or `wasm` for WebAssembly.

## Lossless certificate projections

```rust
use reallyme_trust_x509::projections::{project_certificate, ProjectionError};

fn inspect(der: &[u8]) -> Result<(), ProjectionError> {
    let certificate = project_certificate(der)?;
    for rdn in certificate.subject().rdns() {
        for attribute in rdn.attributes() {
            let encoding = attribute.value().encoding();
            let text = attribute.decoded().text();
            // Apply the application's attribute policy to encoding and text.
            let _ = (encoding, text);
        }
    }
    let issuer_names = certificate.issuer_alternative_names();
    let distribution_points = certificate.crl_distribution_points();
    let _ = (issuer_names, distribution_points);
    Ok(())
}
```

The immutable views borrow the original DER. An existing `X509Certificate`
owner also exposes `projections()`; changing its legacy profile fields cannot
change the source of those views. Attribute OIDs, value identifiers, RDN grouping,
order, multiplicity, GeneralName alternatives, and CRL field presence remain
available without flattening. Absent extensions return `None`; a present CRL
`reasons` value with no set bits remains `Some`.

UTF8String, NumericString, PrintableString, IA5String, VisibleString, BMPString,
and UniversalString are validated against their declared encodings. BMP and
Universal text uses zeroizing owners with a single bounded allocation. Other
attribute syntaxes, including TeletexString, are explicitly uninterpreted and
retain their exact identifier and content; they are never guessed from text.
X.400 and EDI GeneralNames are explicitly unsupported structured alternatives
whose original DER is retained. All identifying diagnostics are redacted.

The boundary rejects duplicate extensions, non-canonical framing, malformed
supported strings, malformed selected extensions (including noncritical ones),
and bounded-work violations. Limits cover certificate bytes, DER nesting and
elements, total attributes, total GeneralNames, extensions, and distribution
points. The view does not authenticate the certificate, resolve a relative CRL
name, or impose ISO/AAMVA, IACA, or OCSP-service policy. Existing path, signature,
revocation, timestamp, SKI, and SSI mdoc APIs retain their roles.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
