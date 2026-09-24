# Normative Requirement Index

`etsi-ts-119-472.tsv` contains requirement identifiers only. It is the
completeness index used to prevent an ETSI topic from disappearing silently
from review. Normative text is not copied into this repository.

| Part | Edition | Identifiers | Official PDF SHA-256 |
| --- | --- | ---: | --- |
| 1 | V1.2.1 (2026-02) | 548 | `0f76ce7cad5f046802146b0c2a9cd8af9db3c1db77db5eeca86d2a4559fcfc3f` |
| 2 | V1.3.1 (2026-07) | 88 | `e403e7d5a4c70d04868989cc623b57d379a5f3dfe282f9f98f7390c8e327310b` |
| 3 | V1.1.1 (2026-03) | 104 | `2919437478c7469881afc5acd5aa68d847a4cfdc1bbf6da9224f4c9fae7167ba` |

EU law separately incorporates Part 2 V1.2.1 (2026-03), with adaptations. The
current V1.3.1 identifier inventory is retained as the latest ETSI edition;
runtime validation selects the EU legal or latest profile explicitly.

The index includes mandatory, optional, conditional, recommended, and void
identifiers. Applicability and disposition belong in the assessment evidence;
an identifier's presence in this file does not turn an optional provision into
a mandatory implementation feature.

`requirement-trace.tsv` replaces a former three-row part-level default with an
explicit row for every ETSI identifier and every EU ledger entry. Each row
records source edition, applicability, EU-profile status, owner, exact code and
test symbols, required external evidence, or a fixed non-applicability
justification. `code_and_composed_evidence` never means that a Boolean supplied
by a caller proves cryptography, trust, transport, UI, hardware, or deployed
operations. `external_evidence_required` is intentionally open until the named
evidence exists. `not_applicable` is accepted only where current consolidated
EU law deletes or voids the obligation.

The production `requirements` module consumes this trace directly. Every one
of the 740 ETSI rows must resolve to a recognized typed handler and the correct
applicability predicate, EU-profile status, and credential-verification,
presentation-protocol, or issuance-protocol evidence boundary. Registry
validation fails closed on unknown handlers, applicability/status values,
duplicate identifiers, malformed rows, missing evidence boundaries, or count
drift.

Executable coverage is split by the layer that can establish the requirement:

| Area | Enforced here | Required composed evidence |
| --- | --- | --- |
| Common EAA/PID data | Conditional context presence; bounded and unique context/schema/terms URIs; optional attestation identifier and issuance time; actual technical and administrative intervals; audience identifiers; evidence references with fixed SHA-256 digests; renewal endpoint and timing; category, disclosure, status, key-binding, and signature policy. | Envelope parsing, signature validation, trust-path evaluation, and authenticated status retrieval. |
| EU PID | Actual borrowed mandatory/optional values; exact mdoc and SD-JWT VC identifiers; disclosure masks; provider metadata; JPEG/base64 and 2028 biometric-quality applicability; allocation, issuance authorization, and revocation lifecycle. | Envelope name/type mapping, biometric assessor, trust resolver, provider publication, and deployed issuer evidence. |
| Presentation | SD-JWT key binding; mdoc and HAIP profiles; EU V1.2.1/V1.3.1 edition split; dual mediating API; proximity; registration/overasking comparison; explicit-decision policy. | OpenID4VP transport/state machine, wallet UI event provenance, registrar, and deployed trust evidence. |
| Issuance | Signed metadata; unrestricted semantics for omitted reuse policy; first-supported-method selection and reuse thresholds; disclosure policy; proof and key counts; notification structure; EU registration-certificate/Annex A adaptations; detailed WIA/KA lifecycle and status privacy. | OpenID4VCI transport/state machine, signature/path verification, status retrieval, issuer service, and key-custody evidence. |
| Wallet core | Authentication gate, WSCA/WSCD capability policy, ETSI format capability closure, wallet-attestation revocation, transaction-log records and controls, embedded disclosure evaluation, and RP-specific pseudonym allocation. | Hardware certification, platform enforcement, storage deployment, qualified-signature applications, portability, user-interface evidence, statutory retention, and trust-mark rendering/status integration. |

`eu-2026-profile.tsv` is the legal coverage ledger for the consolidated
2024/2977, 2024/2979, and 2024/2982 texts and their ETSI adaptations. Its
disposition column is intentionally closed: `direct`, `composed`, or `void`.

Official sources:

- <https://www.etsi.org/deliver/etsi_ts/119400_119499/11947201/01.02.01_60/ts_11947201v010201p.pdf>
- <https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.03.01_60/ts_11947202v010301p.pdf>
- <https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf>
- <https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf>
- <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2977-20260811>
- <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2979-20260811>
- <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2982-20260811>
- <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R1731>

The index was extracted from the three pinned PDFs and then sorted and
deduplicated per part. Tests pin both the per-part counts and global uniqueness.
They also prove a one-to-one join between the 740 ETSI identifiers, the 229 EU
profile rows, and the 969-row requirement trace.
