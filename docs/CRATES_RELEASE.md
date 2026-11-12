# Publishing SSI components

The SSI release includes 33 component packages. The composed `reallyme-ssi`
facade, `identity-trust-jades`, and `reallyme-eudi-rp-registration` remain
source-only. The workspace defaults to `publish = false`; public components
opt in explicitly and are checked against the approved package set.

## Release workflow

Run **Crates Package Preflight** on the current main commit with its release
version. Preflight verifies the approved package set and dependency order,
builds and tests extracted package archives, and attests those archives after
the full Rust CI run succeeds.

Run **Crates.io Release** for the same commit after preflight succeeds. It
verifies provenance for all 33 archives, checks the approved package set and
order again, and publishes each dependency before its consumers. The publisher
includes optional, build, and versioned development dependencies when ordering
packages. A failed upload stops publication before dependent packages proceed.
The release summary lists every package from the publication ledger.

Inspect the current complete order locally with:

```sh
node scripts/inspect_publishable_crates.mjs
node scripts/publish_crates_in_order.mjs order
```

## Initial publication of the additional 0.6.1 packages

The additional packages retain version `0.6.1`. Publish only the following 13
packages manually, after committing the reviewed changes and completing
validation. Their existing SSI dependencies must already be available at
`0.6.1` on crates.io. Keep the existing release tag and published packages.

From a clean repository checkout, inspect the release before uploading:

```sh
RELEASE_VERSION=0.6.1 node scripts/publish_crates_in_order.mjs inspect
```

Then run this sequence from the repository root using an account authorized
to publish the packages. Cargo verifies each package and polls for its registry
index entry. If that polling times out, confirm whether the upload completed
before resuming; the timeout does not undo the upload. See the
[Cargo publication reference](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).

```sh
(
  set -eu
  for package in \
    envelopes-data-integrity \
    identity-presentation-vp-policy \
    reallyme-did-core \
    reallyme-did-method-cheqd \
    reallyme-did-method-jwk \
    reallyme-did-method-ebsi \
    reallyme-did-method-ion \
    reallyme-did-method-key \
    reallyme-did-method-me \
    reallyme-did-method-web \
    reallyme-keys \
    reallyme-did-api \
    reallyme-vp-api
  do
    cargo publish --locked --registry crates-io -p "$package"
  done
)
```

If a command fails, resolve the failure and resume at that package. Do not
upload an already published version again. The automated release publisher
compares existing registry archives against its reviewed archives, so use the
normal release workflow for subsequent workspace versions rather than
replaying the full release for this manual backfill.
