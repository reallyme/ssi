# Publishing SSI components

The approved release set contains 35 component packages, all using the
`reallyme-` namespace. It includes `reallyme-trust-jades` and
`reallyme-eudi-rp-registration`. The composed `reallyme-ssi` facade remains
source-only. The workspace defaults to `publish = false`; public components
opt in explicitly and are checked against the approved package set.

## Adding JAdES and RP-registration at 0.6.2

These two package names have no earlier 0.6.2 publication. They can be published
at 0.6.2 without replacing the existing component releases or advancing the
workspace version. Existing public component manifests do not acquire a new
JAdES or RP-registration dependency through this addition.

From a clean checkout of the reviewed commit, publish JAdES first and then
RP-registration using an authorized crates.io account:

```sh
(
  set -eu
  cargo publish --locked --registry crates-io -p reallyme-trust-jades
  cargo publish --locked --registry crates-io -p reallyme-eudi-rp-registration
)
```

Cargo verifies each package and polls for its registry index entry. If polling
times out, confirm whether the upload completed before resuming; the timeout
does not undo the upload. See the
[Cargo publication reference](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).

Do not rerun the complete 0.6.2 release workflow from this new commit. Already
published packages retain their original source commit and archive checksums.
The automated publisher requires those checksums to match its reviewed source,
so publishing these two additions manually avoids attempting to replace or
reproduce the other component archives from a different commit.

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
RELEASE_VERSION=0.6.2 node scripts/publish_crates_in_order.mjs order
```
