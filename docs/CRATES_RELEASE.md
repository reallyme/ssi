# Publishing SSI components

The approved release set contains 35 component packages, all using the
`reallyme-` namespace. It includes `reallyme-trust-jades` and
`reallyme-eudi-rp-registration`. The composed `reallyme-ssi` facade remains
source-only. The workspace defaults to `publish = false`; public components
opt in explicitly and are checked against the approved package set.

## X.509 projections at 0.7.0

All workspace packages and internal requirements advance together to 0.7.0.
Consumers needing the lossless certificate projections can depend directly on
`reallyme-trust-x509 = "0.7.0"` from crates.io. They do not need a Git dependency
or the composed SSI facade.

For the initial X.509 publication, publish its protobuf prerequisite first:

```sh
(
  set -eu
  cargo publish --locked --registry crates-io -p reallyme-ssi-proto
  cargo publish --locked --registry crates-io -p reallyme-trust-x509
)
```

Cargo verifies each package and polls for its registry index entry. If polling
times out, confirm whether the upload completed before resuming; the timeout
does not undo the upload. See the
[Cargo publication reference](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).

Use the same clean source commit for these two archives and any later complete
0.7.0 release. Published versions are immutable. The release publisher verifies
archive checksums, including source-commit provenance; it cannot replace an
already published archive with different bytes.

## Subsequent release workflows

The next normal workspace release includes all 35 packages. Run **Crates
Package Preflight** on the current main release commit with that release's
version. Preflight verifies the approved package set and dependency order,
builds and tests extracted package archives, and attests those archives after
the full Rust CI run succeeds. Its archive upload selects the certified release
version so cached archives from earlier releases are excluded.

Run **Crates.io Release** for the same commit after preflight succeeds. It
verifies provenance for all 35 archives, checks the approved package set and
order again, and publishes each dependency before its consumers. The publisher
includes optional, build, and versioned development dependencies when ordering
packages. A failed upload stops publication before dependent packages proceed.
The release summary lists every package from the publication ledger.

Inspect the complete current order locally with:

```sh
node scripts/inspect_publishable_crates.mjs
RELEASE_VERSION=0.7.0 node scripts/publish_crates_in_order.mjs order
```
