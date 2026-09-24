# reallyme-disclosure-policy

`reallyme-disclosure-policy` owns protocol-neutral verifier policy for
credential presentations. It decides whether a verifier accepts a presentation
format, issuer and holder algorithms, status freshness, QEAA evidence, and
required claim disclosure modes.

This crate does not parse SD-JWT, mdoc, JWT-VC, W3C VC, OpenID4VP messages, or
ZK proof formats. Envelope and protocol layers must verify those inputs first
and pass only verified facts into policy evaluation.

## Claims Registry Preflight

Run `validate_policy_claims_against_registry` before planning or evaluating a
policy that contains required claims. The preflight validates the concrete
claims registry, confirms the registry claimset is allowed by policy, and checks
that every required claim path and disclosure mode is permitted by the
identity-owned claim definition.

This keeps verifier policy from carrying malformed claim paths, stale profile
claim names, or unsupported predicate modes into OpenID4VP or ZK proof assembly.

## Built-In Profiles

`policy_for_claimset` maps supported predefined claimset identifiers to
eIDAS-oriented verifier policies. Registry-backed profiles such as `eu.pid.v1`,
`eu.age.v1`, `eu.passport.v1`, `eu.driving_license.v1`, and `eu.eidas-vid.v1`
must validate against their corresponding `reallyme-credential-claims`
registries. `eu.kyc.v1` is policy-only because KYC is a relying-party workflow,
not a single authoritative claim registry.
