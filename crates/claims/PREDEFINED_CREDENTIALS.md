# Predefined Credential Claim Catalogs

This matrix records the claim catalogs owned by `reallyme-credential-claims`.
It separates registry-backed credentials from policy-only claimsets so release
review can distinguish supported validation from relying-party policy intent.

## Registry-Backed Profiles

| Claimset ID | Credential Shape | Source Authority | Catalog Status | Supported Normalization Formats | Disclosure Posture | Conformance |
| --- | --- | --- | --- | --- | --- | --- |
| `eu.pid.v1` | EU natural-person PID | `EU-2024-2977`, `EU-2024-1183` | Official-annex field set. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | PID identifiers and document numbers are predicate-only; address/name metadata can be revealed. | `CLAIMS-MUST-010`, `CLAIMS-MUST-011` |
| `eu.eidas-vid.v1` | eIDAS verified identity view | `EU-2024-2977` | Alias of `eu.pid.v1`. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Reuses the EU PID catalog so VID does not introduce alternate natural-person claim names. | `CLAIMS-MUST-012` |
| `eu.eaa.v1` | Generic electronic attestation of attributes | `EU-2024-2977`, `EU-2024-1183`, `EU-2025-1569`, `EUDI-ARF` | Reference interoperability baseline. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Attestation identifiers and authentic-source IDs are predicate-only; issuer, type, validity, and status metadata are shared by sector profiles. | `CLAIMS-MUST-012` |
| `eu.age.v1` | Age and age-over credential | `EU-2024-2977`, `EU-2024-1183` | Derived PID presentation profile. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Exact age and birth date are not revealable by default; age-over booleans support equality predicates. | `CLAIMS-MUST-011` |
| `eu.address.v1` | Residence address credential | `EU-2024-2977`, `EU-2024-1183` | Official-annex residence/contact subset. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Residence fields are revealable; contact identifiers and document/status locators are predicate-only. | `CLAIMS-MUST-011` |
| `eu.diploma.v1` | Diploma and learning credential | `ELM-3`, `EU-2024-1183`, `EU-2025-1569` | Reference interoperability baseline. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Learner birth date is predicate-only; award, qualification, and issuing metadata are revealable where appropriate. | `CLAIMS-MUST-012` |
| `eu.driving_license.v1` | Mobile driving licence | `ISO18013-5`, `EU-2024-1183`, `EU-2025-1569` | Reference interoperability baseline. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Document number, portrait, and structured driving privileges are not revealable by default; country/sign predicates are allowed. | `CLAIMS-MUST-012` |
| `eu.professional_license.v1` | Professional licence or certification | `ELM-3`, `EU-2024-1183`, `EU-2025-1569`, `EUDI-ARF` | Reference interoperability baseline. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Licence and registration numbers are predicate-only; profession, status, jurisdiction, and scope can be disclosed under policy. | `CLAIMS-MUST-012` |
| `eu.health.v1` | European Health Insurance Card entitlement | `EU-2003-751`, `EU-2025-1569` | Reference interoperability baseline. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Personal/card/institution identifiers are predicate-only; this profile intentionally excludes clinical data. | `CLAIMS-MUST-012` |
| `eu.company.v1` | EU legal-person PID/company credential | `EU-2024-2977`, `EU-2024-1183` | Official-annex field set. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Public company identifiers can be disclosed under policy; tax and excise identifiers are predicate-only. | `CLAIMS-MUST-011` |
| `eu.tax.v1` | Tax-residency and tax identifier baseline | `EU-2024-2977`, `EU-2024-1183` | Reference interoperability baseline. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Tax identifiers and document/status locators are predicate-only. | `CLAIMS-MUST-011` |
| `eu.passport.v1` | EU-facing passport selection | `ICAO9303` | Preserve-only alias. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Reuses the ICAO passport catalog; document numbers, MRZ, biometric, and chip-security fields are not revealable by default. | `CLAIMS-MUST-010`, `CLAIMS-MUST-011` |
| `icao.passport.v1` | ICAO passport and LDS-oriented attributes | `ICAO9303` | Preserve-only catalog. | SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, credential proto | Document numbers, MRZ, biometric, and chip-security fields are not revealable by default. | `CLAIMS-MUST-010` |

## Policy-Only Profiles

| Claimset ID | Status | Reason |
| --- | --- | --- |
| `eu.kyc.v1` | Policy-only | KYC is a relying-party verification use case, not one authoritative EU credential catalog. It should be backed by explicit PID, company, tax, status, trust, and sector attestations rather than a synthetic claims registry. |

## Vector Coverage

`vectors/claims/predefined-credentials.json` carries portable
predefined-credential vectors. The vector test normalizes each profile through
SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, and credential proto and then
validates the normalized `ClaimValue` against the built-in registry.

`vectors/claims/catalog-sources.json` records source and status
coverage for every registry-backed predefined profile. Source references are
limited to pinned official sources; non-normative extensions are identified as
reference interoperability baselines, normalization aliases, presentation
projections, or preserve-only catalogs rather than treated as external
standards. The profile test verifies that every predefined claimset has a
source-map entry and that each mapped field is present in the live registry.

The vector suite covers every registry-backed predefined profile in this matrix:
`eu.pid.v1`, `eu.age.v1`, `eu.address.v1`, `eu.eaa.v1`, `eu.company.v1`,
`eu.tax.v1`, `eu.passport.v1`, `icao.passport.v1`, `eu.driving_license.v1`,
`eu.diploma.v1`, `eu.health.v1`, `eu.professional_license.v1`, and
`eu.eidas-vid.v1`.
