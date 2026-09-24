# EUDI RP registration vectors

These reusable vectors exercise the pinned EUDI TS5 v1.5 object and envelope
shapes and the ETSI TS 119 475 V1.2.1 WRPRC payload profile. The duplicate-key
vector is intentionally invalid JSON-object input and must be rejected before
semantic deserialization.

`wrpac-ncp-legal.der.b64` is a non-production EC test certificate exercising
the TS 119 411-8 non-qualified legal-person policy, standardized
`organizationIdentifier`, contact URI, issuer pointer, revocation pointer, and
CPS policy qualifier. Its private key is not retained.

Normative sources:

- [EUDI TS5 v1.5 pinned source](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/tree/fce24dbb59af093e189deaac280ed65a1aca65c3)
- [EUDI TS6 v1.2.2 pinned source](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/9c59198922c5a1f1a305ca9eecff1d587e8a6258/docs/technical-specifications/ts6-common-set-of-rp-information-to-be-registered.md)
- [ETSI TS 119 475 V1.2.1](https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf)
- [ETSI TS 119 411-8 V1.1.1](https://www.etsi.org/deliver/etsi_ts/119400_119499/11941108/01.01.01_60/ts_11941108v010101p.pdf)
- [Commission Implementing Regulation (EU) 2026/1730](https://eur-lex.europa.eu/eli/reg_impl/2026/1730/oj)
