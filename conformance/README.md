# Identity Conformance

This directory records identity-layer conformance evidence. It is intentionally
separate from OpenID protocol conformance suites, wallet lifecycle tests, and
concrete ZK backend tests.

## Layout

`conformance/` is the canonical home for identity-layer conformance metadata:

- `requirements/` contains requirement records by identity-owned concept.
- `upstream/` contains pinned normative source metadata and upstream reference
  test registries.
- `dependencies.lock.json` pins the published dependency versions recorded in
  release evidence.
- `concepts.json` ties local crates, public APIs, requirement files, and
  publishing posture into one machine-checked inventory.

The root `vectors/` directory contains reusable cross-crate and cross-language
vectors. Crate-specific fixtures live beside the tests that consume them.

Generated reports are release evidence rather than source metadata. The package
preflight workflow generates them from a clean release commit, uploads the
hashed bundle as a workflow artifact, and the release workflow attaches the
same bundle to the GitHub release. They are deliberately not committed here
because a commit cannot truthfully contain evidence stamped with its own commit
identifier.

The package-preflight artifact is retained for 90 days. The copy attached to a
GitHub release follows the release's retention lifecycle. This repository does
not import evidence into another repository. A separate conformance system may
consume the release attachment and pin its source commit, but that transfer is
outside these workflows. Pull-request and branch CI also generates the bundle
to exercise the generator, but does not retain that non-release output after
the workflow run.

Protocol, wallet, SDK, and concrete ZK conformance suites belong in their owning
repositories and should be referenced here only as explicit upstream or external
evidence.

Every applicable requirement record must name:

- the exact normative source and section;
- the identity crate or module that implements it;
- positive and negative tests or vector sets.

Records that are not owned by this repository must be marked inapplicable with
an explicit exclusion reason. The release readiness script runs
`scripts/check_conformance_coverage.mjs` so missing implementation or test
coverage fails fast.

## Upstream Sources

`conformance/upstream/sources.lock` pins normative source documents, while
`conformance/upstream/tests.json` records upstream reference tests and portable
external vector sources. Dependency-owned test names are accepted only with an
exact Git commit, crates.io checksum, test-binary mapping, and executable Cargo
command. Rust CI checks out those immutable sources, verifies every mapped test
symbol and polarity, executes the named binaries, and records a result bound to
the exact SSI commit. Release evidence generation rejects a missing, stale, or
failed upstream result.

## Concept Inventory

`conformance/concepts.json` is the repository-level inventory that ties each
identity concept to:

- its owning repository;
- local crate manifests or external crates;
- public API surface;
- requirement files;
- current mapping status;
- publishing posture.

The checker requires every local Cargo manifest to be assigned to a concept
with an explicit conformance status and publication policy.

`mapping_status` values are intentionally conservative:

- `section_by_section` means every applicable section-level MUST/MUST NOT for
  the selected normative source has mapped tests.
- `representative` means tested coverage is not an exhaustive section-by-section
  mapping and does not substantiate a complete conformance claim.
- `in_progress` means required coverage is missing. The record identifies the
  current gaps and whether they block release.
- `external_upstream` means detailed conformance lives in another ReallyMe
  repository and SSI records only consumption or facade behavior.
- `not_applicable` means the concept is explicitly out of identity scope.

The `reallyme.identity.conformance.concepts.v1` inventory uses `coverage_notes`
to describe current evidence boundaries or missing coverage. A non-section-level
mapping or a package that is not publication-ready requires a nonempty
explanation. `release_blocker` records whether the concept prevents release;
these fields do not replace the executable requirement and test checks.

## Taxonomy Evidence

`taxonomy/conformance-ledger-evidence.json` records accepted evidence against
pinned taxonomy requirements. Its shared schema uses `planned` with
`implementation_planned` for requirements without accepted evidence bindings.
These values identify an evidence gap, not a delivery commitment or a finding
that implementation is absent. Only accepted, source-bound code and test
locators substantiate an implemented requirement. Unmapped requirements remain
visible and must not be counted as verified coverage.
