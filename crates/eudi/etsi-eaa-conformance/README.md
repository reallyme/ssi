# ETSI EAA and EU PID Conformance

`reallyme-etsi-eaa-conformance` is the protocol-neutral conformance policy for
Electronic Attestations of Attributes (EAA) and person identification data
(PID). It validates actual borrowed PID values, structural profile data, and
transaction decisions without retaining or cloning credential PII. It also
provides stateful gates for portrait disclosure and wallet authentication,
actual relying-party registration/overasking comparison, status-reference
non-correlation checks, and detailed WIA/KA lifecycle policy. Private keys and
complete credential payloads never enter this crate.

## Normative Baseline

The implementation targets the standards and law in force on 21 September
2026:

- ETSI TS 119 472-1 V1.2.1 (2026-02), including common requirements and the
  SD-JWT VC, ISO/IEC mdoc, JSON-LD VC, and X.509 Attribute Certificate
  realizations, together with the
  adaptations made by Commission Implementing Regulation (EU) 2026/1731;
- ETSI TS 119 472-2 V1.2.1 (2026-03) as incorporated into EU law, and the
  distinct current ETSI TS 119 472-2 V1.3.1 (2026-07) profile;
- ETSI TS 119 472-3 V1.1.1 (2026-03);
- Commission Implementing Regulation (EU) 2024/2977, consolidated on
  11 August 2026;
- Commission Implementing Regulation (EU) 2024/2979, consolidated on
  11 August 2026;
- Commission Implementing Regulation (EU) 2024/2982, consolidated on
  11 August 2026, which is the legal source incorporating Parts 2 and 3;
- Commission Implementing Regulation (EU) 2026/1731, which introduced the
  current adaptations in all three consolidated regulations.

The official ETSI documents are referenced, not vendored. ETSI retains the
copyright in those documents.

The machine-readable identifier index contains 740 unique normative identifiers
(548 from Part 1, 88 from Part 2, and 104 from Part 3). See
[`requirements/README.md`](requirements/README.md) for source hashes and the
identifier-only inventory. The index includes optional and conditional
requirements so an applicability decision must be recorded rather than silently
dropping them.

The index is also an executable, fail-closed production registry. Call
`resolve_normative_requirement` to resolve an exact identifier to its typed
Part 1, Part 2, or Part 3 enforcement route, applicability predicate,
current-EU-profile status, and composed-evidence boundary.
`validate_normative_requirement_registry` validates all 740 embedded routes,
their uniqueness, recognized handlers, and exact per-part totals without heap
allocation. Unknown, non-canonical, or newly introduced identifiers cannot be
silently treated as covered.

[`requirements/requirement-trace.tsv`](requirements/requirement-trace.tsv)
maps every one of those identifiers, plus all 229 rows in the EU profile
ledger, to a source edition, applicability predicate, EU-profile status,
owning repository, exact code and test symbol, required external evidence, or
a fixed non-applicability justification. The 969-row trace deliberately keeps
`external_evidence_required` distinct from code-backed policy gates: inventory
closure is not evidence that an unperformed deployment or operational control
passed.

The EU-specific coverage ledger is
[`requirements/eu-2026-profile.tsv`](requirements/eu-2026-profile.tsv). Every
row is classified as directly enforced, composed evidence, or void under the
EU adaptation. `direct` identifies an executable API in this crate; `composed`
identifies an operational, trust-service, UI, deployment, or legal-retention
control that no pure library can truthfully prove by itself.

## Credential and PID Scope

The crate covers these attestation realizations:

- SD-JWT VC;
- ISO/IEC mdoc;
- JSON-LD W3C VC secured with JOSE;
- JSON-LD W3C VC secured with SD-JWT;
- X.509 Attribute Certificate.

It distinguishes generic EAA, qualified EAA (QEAA), EAA issued by or on behalf
of a public body responsible for an authentic source, natural-person PID, and
legal-person PID.

Natural-person PID coverage includes all mandatory Annex attributes:
`family_name`, `given_name`, `birth_date`, `birth_place`, `nationality`, and
`portrait`. It also covers all optional attributes: residence address and its
components, personal administrative number, names at birth, sex, email address,
and mobile phone number. The validator requires independent selective
disclosure of every PID data identifier, including portrait, and validates the
mandatory issuer metadata. The validator receives the actual borrowed values
and validates Unicode/text bounds, Gregorian dates, structured birth place,
assigned country codes plus `QU`/`QS`, duplicate nationalities, the legal sex
code set, RFC 5322 email syntax, international mobile-number syntax, ISO 3166-2
jurisdiction/country consistency, canonical base64, JPEG framing, and
format-specific portrait representation. From 11 August 2028 it also requires
an ISO/IEC 39794-5 or permitted legacy ISO/IEC 19794-5 portrait-quality
assessment. A Member State opt-out is represented by the mandatory portrait
identifier carrying an empty value, exactly as the Annex requires.

The SD-JWT VC PID profile uses `urn:eudi:pid:1`. The ISO/IEC mdoc PID profile
uses `eu.europa.ec.eudi.pid.1` as both document type and standard namespace.
Domestic extensions remain the responsibility of the Member State and must be
validated against the separately published domestic scheme before these facts
are marked valid.

Legal-person PID coverage validates the mandatory current legal name and
cross-border persistent identifier and permits separately validated address,
VAT, tax, EUID, LEI, EORI, and excise identifiers. The 2024/2977 Annex does not
define a common SD-JWT VC or mdoc wire mapping for that legal-person set, so the
crate does not invent one.

## Conformance Boundaries

This crate enforces implementation-checkable profile invariants for:

- common EAA type/context/schema metadata, identity, issuance and validity,
  usage constraints, attribute evidence, renewal, subject binding, status,
  selective disclosure, key binding, and issuer-signature assurance;
- the two regulated PID encodings and their WSCD key binding and protected
  certificate-reference headers;
- binary, irreversible revocation semantics and the at-most-24-hour short-lived
  exception introduced by the current 2024/2979 adaptation;
- SD-JWT+KB presentation, ISO/IEC mdoc request/response, and the mandatory
  non-API OpenID4VC-HAIP presentation lane;
- optional API-mediated presentation privacy and lifecycle controls;
- signed Credential Issuer Metadata, access and registration certificates,
  reuse policy, embedded disclosure policy, WIA/WUA processing, distinct
  per-credential key binding, and required AES-GCM suites.

The owning adapters must establish only facts that this crate cannot safely
derive without raw credential or transport input. In particular, this crate
does not parse a complete credential, perform cryptography, fetch a status
list, resolve a trusted list, operate a registrar, execute HTTP, assess a face
image against an ISO biometric quality standard, or render wallet UI. It does
validate the exact values and decisions supplied by those layers and rejects
inconsistent combinations. Conformance evidence therefore combines these
validators with parser, signature, trust, status, OpenID, wallet-runtime,
biometric-assessment, UI, and end-to-end tests. A caller must not claim
whole-product regulatory conformity from a successful library validation
alone.

## Product Integration Contract

The canonical cross-language facts are defined in
`crates/proto/proto/identity/eudi/v1/pid.proto`; the requirement source,
registry summary, exact-reference lookup, applicability, disposition, and
evidence records are defined in the adjacent `requirements.proto`. These
messages are inputs and audit records, not alternative profile semantics: this
crate remains the implementation that converts verified facts into a typed
accept-or-reject decision.

The Identity operation envelope exposes registry validation, exact requirement
resolution, natural-person PID, legal-person PID, issuance authorization,
allocation, and revocation as distinct operations. Its Rust, Swift, Kotlin,
TypeScript, Go, Python, and C# facades all use the same generated messages and
stable typed error. This keeps the 740 ETSI identifiers, 229 EU profile rows,
and every regulated PID field visible through the product boundary without
duplicating conformance rules in individual SDKs.

## EU 2026 Enforcement APIs

- `validate_natural_person_pid`, `validate_pid_allocation`,
  `validate_pid_issuance_authorization`, and `validate_pid_revocation` cover the
  current 2024/2977 PID data and lifecycle boundary.
- `PortraitDisclosureGate` enforces warning, transaction-specific explicit
  confirmation, rejection, and one-shot portrait disclosure.
- `validate_openid4vp_presentation_for_profile` keeps the EU-incorporated Part
  2 V1.2.1 behavior separate from V1.3.1; `validate_eu_mediating_api` covers the
  dual OpenID4VP/ISO 18013-7 API, privacy, lifecycle, format, and proximity
  requirements.
- `authorize_eu_presentation` compares actual requested type/attribute pairs
  with the registration certificate and requires the exact explicit decision
  appropriate to validation or overasking warnings.
- `validate_eu_mdoc_status` validates the current CWT/list profile and rejects
  repeated MSO correlation keys; `validate_eu_mdoc_status_capabilities` closes
  the two-mechanism WIA/KA support boundary.
- `validate_eu_issuance` applies the Part 3 registration-certificate and Annex
  A adaptations. Reuse-policy validation treats an omitted policy as
  unrestricted, requires the associated thresholds, and proves that the wallet
  selected the first issuer preference it actually supports.
- `WalletOperationGate`, `validate_wallet_cryptographic_capabilities`,
  `validate_wallet_format_capabilities`,
  `validate_wallet_attestation_revocation`,
  `validate_wallet_transaction_log`, `evaluate_wallet_disclosure_policy`, and
  `validate_relying_party_pseudonym` cover the locally enforceable 2024/2979
  core-wallet, revocation, Annex II format, and pairwise-pseudonym boundaries.
- `validate_wallet_attestation_profile` covers WIA/KA format, transport,
  content, lifecycle, proof, status-index privacy, status maintenance, PID
  validity chaining, and algorithm requirements added by the 2026 amendment.

## Verification

Run:

```sh
cargo test -p reallyme-etsi-eaa-conformance --all-features
cargo clippy -p reallyme-etsi-eaa-conformance --all-targets --all-features -- -D warnings
```

The tests cover valid and malicious PID values, all four Part 1 realization
families, format-mismatched and
non-canonical portraits, 2028 quality applicability, disclosure gaps, calendar
dates, issuer metadata, lifecycle and revocation timing, status correlation,
registration/overasking decisions, Part 2 edition differences, mediating API
capabilities, Part 3 EU adaptations, wallet authentication, cryptographic
capabilities, transaction logs, disclosure policies, and the WIA/KA lifecycle.
