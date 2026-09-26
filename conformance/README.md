# Identity Conformance

This directory records identity-layer conformance evidence. It is intentionally
separate from OpenID protocol conformance suites, wallet lifecycle tests, and
concrete ZK backend tests.

## Layout

`conformance/` is the canonical home for identity-layer conformance metadata:

- `requirements/` contains requirement records by identity-owned concept.
- `upstream/` contains pinned normative source metadata and upstream reference
  test registries.
- `fixtures/` contains inputs owned specifically by conformance executions.
- `dependencies.lock.json` pins the published dependency versions recorded in
  release evidence.
- `concepts.json` ties local crates, public APIs, requirement files, and
  publishing posture into one machine-checked inventory.

The root `vectors/` directory contains reusable cross-crate and cross-language
vectors. Files move into `conformance/fixtures/` only when they exist solely as
inputs to a conformance run.

Generated reports are release evidence rather than source metadata. The package
preflight workflow generates them from a clean release commit, uploads the
hashed bundle as a workflow artifact, and the release workflow attaches the
same bundle to the GitHub release. Reviewed bundles are retained by
`reallyme/identity-conformance`; they are deliberately not committed here
because a commit cannot truthfully contain evidence stamped with its own commit
identifier.

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
external vector sources.

## Concept Inventory

`conformance/concepts.json` is the repository-level inventory that ties each
identity concept to:

- its owning repository;
- local crate manifests or external crates;
- public API surface;
- requirement files;
- current mapping status;
- publishing posture.

The checker requires every local Cargo manifest to be assigned to a concept.
This is deliberately stricter than requirement-record validation: it prevents
new crates, placeholder method packages, or extracted support crates from
landing without a conformance and publishing decision.

`mapping_status` values are intentionally conservative:

- `section_by_section` means every applicable section-level MUST/MUST NOT for
  the selected normative source has mapped tests.
- `representative` means there is useful tested coverage, but the concept still
  needs exhaustive section-by-section mapping before a final release claim.
- `in_progress` means the concept is actively moving and should block a public
  identity core release until the named next actions close.
- `external_upstream` means detailed conformance lives in another ReallyMe
  repository and SSI records only consumption or facade behavior.
- `not_applicable` means the concept is explicitly out of identity scope.
