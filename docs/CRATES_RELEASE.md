# Publishing SSI components

The approved release set contains 35 component packages, all using the
`reallyme-` namespace. It includes `reallyme-trust-jades` and
`reallyme-eudi-rp-registration`. The composed `reallyme-ssi` facade remains
source-only. The workspace defaults to `publish = false`; public components
opt in explicitly and are checked against the approved package set.

## Complete 0.7.0 release

All 65 workspace packages and the standalone fuzz package use version 0.7.0.
The approved public set remains 35 packages. Run the complete Rust, fuzz, secret,
and repository-security workflows for the release commit, then run **Crates
Package Preflight** with version `0.7.0`. Publish only after those gates pass.

Two 0.7.0 packages already exist in crates.io: `reallyme-ssi-proto` and
`reallyme-trust-x509`. Their immutable archive checksums and original source
commit are pinned in `scripts/prepublished_crates.json`. Preflight downloads
those exact bytes, verifies their source provenance, and compares every member
against a fresh source package. The only approved source difference is moving
an X.509 test helper into the test module; both original and replacement file
hashes are pinned. Manifests, lockfiles, production behavior, binary fixtures,
and every other member must remain identical. Source-commit metadata is checked
against the respective original and current commits.

Preflight tests the original immutable archives alongside the newly packaged
components. Already-published packages are excluded from workspace packaging,
so new archives retain the registry's real dependency checksums. All 35 reviewed
archives are attested together. **Crates.io Release** verifies and reuses the two
pinned archives, publishes the remaining 33 in dependency order, and creates the
`reallyme-ssi-v0.7.0` GitHub release with its publication ledger and evidence.

The reuse policy is scoped to 0.7.0. Subsequent versions package the entire
approved public set normally. It never permits replacing an existing upload or
silently accepting an unreviewed source change.

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
