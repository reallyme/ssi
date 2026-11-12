# Publishing SSI components

The 0.6.2 release includes 33 component packages, all using the `reallyme-`
namespace. Data Integrity is `reallyme-data-integrity` and presentation policy
is `reallyme-vp-policy`. The composed `reallyme-ssi` facade,
`identity-trust-jades`, and `reallyme-eudi-rp-registration` remain source-only.
The workspace defaults to `publish = false`; public components opt in
explicitly and are checked against the approved package set.

## Release workflow

Run **Crates Package Preflight** on the current main commit with version
`0.6.2`. Preflight verifies the approved package set and dependency order,
builds and tests extracted package archives, and attests those archives after
the full Rust CI run succeeds. Its archive upload selects the certified release
version so cached archives from earlier releases are excluded.

Run **Crates.io Release** for the same commit after preflight succeeds. It
verifies provenance for all 33 archives, checks the approved package set and
order again, and publishes each dependency before its consumers. The publisher
includes optional, build, and versioned development dependencies when ordering
packages. A failed upload stops publication before dependent packages proceed.
The release summary lists every package from the publication ledger.

Inspect the complete order locally with:

```sh
node scripts/inspect_publishable_crates.mjs
RELEASE_VERSION=0.6.2 node scripts/publish_crates_in_order.mjs order
```

## Manual publication of 0.6.2

Publish all 33 public packages at 0.6.2, including packages that already have an
earlier release on crates.io. Published versions are immutable; existing
releases and their tags remain as recorded. Use a clean checkout of the reviewed
release commit and an account authorized to publish each package.

The following sequence stops at the first failure. Cargo verifies each package
and polls for its registry index entry. If that polling times out, confirm
whether the upload completed before resuming; the timeout does not undo the
upload. See the
[Cargo publication reference](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).

```sh
(
  set -eu
  for package in \
    reallyme-ssi-proto \
    reallyme-trust-x509 \
    reallyme-ssi-core \
    reallyme-credential-status \
    reallyme-revocation \
    reallyme-trust-core \
    reallyme-credential-claims \
    reallyme-credential-audit \
    reallyme-credential \
    reallyme-vp-core \
    reallyme-vp-policy \
    reallyme-compression-brotli \
    reallyme-did-types \
    reallyme-data-integrity \
    reallyme-did-core \
    reallyme-did-method-cheqd \
    reallyme-did-method-jwk \
    reallyme-did-method-ebsi \
    reallyme-did-method-ion \
    reallyme-did-method-key \
    reallyme-did-method-me \
    reallyme-did-method-web \
    reallyme-keys \
    reallyme-ssi-proto-codec \
    reallyme-did-api \
    reallyme-disclosure-policy \
    reallyme-etsi-eaa-conformance \
    reallyme-mdoc \
    reallyme-openid-oauth \
    reallyme-openid4vc-profiles \
    reallyme-sd-jwt \
    reallyme-vp-api \
    reallyme-trust
  do
    cargo publish --locked --registry crates-io -p "$package"
  done
)
```

If a command fails, resolve the failure and resume at that package. Do not
upload an already published version again. After publication, downstream
consumers must use the 0.6.2 component versions and the two corrected package
names together.
