# reallyme-trust

`reallyme-trust` is the public entry point for ReallyMe trust capabilities.
Its first domain, `certificate`, provides typed certificate trust decisions
using the released `reallyme-trust-core` and `reallyme-trust-x509` packages.
The same X.509 certificate type is used for parsing, path evaluation, signature
verification, and status checking.

The caller supplies trusted roots, evaluation time, and an optional status
checker. A configured policy can require status evidence; missing or unknown
required evidence produces an indeterminate decision. The portable signature
backend verifies the selected candidate path and rejects algorithms and path
constraints it cannot process. It does not fetch certificates, status responses,
or trusted lists.

The optional `openssl` feature exposes an explicit native verifier for
applications that require OpenSSL's strict path validation and broader
certificate-signature algorithm support. Its dependency closure is
registry-sourced. The portable backend remains available without OpenSSL and
fails closed for unsupported algorithms and weak RSA keys.

Typed decisions retain the selected path's leaf-to-anchor SHA-256 fingerprints,
selected trust anchor, policy, time, per-certificate status, and fixed failure
reasons. The `dto` module provides conversion to and from the trust protobuf
contract, with validation of inbound decision receipts.
Rust decision evidence clears linkable identifiers on drop and redacts them
from debug output. Protobuf conversion creates a caller-owned copy of that
evidence.

EU trusted-list ingestion, QTSP operations, and proprietary trust services are
separate capabilities. They are not enabled by this package's default feature.
Each future public capability must have a separately auditable, publishable
dependency closure before it is exposed here.

```toml
[dependencies]
reallyme-trust = "0.4.2"
```
