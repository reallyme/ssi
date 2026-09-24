# Pinned trusted-list schemas

The native trusted-list ingestion boundary validates documents against the
ETSI TS 119 612 schema before semantic projection. `19612_xsd.xsd` is pinned
from the ETSI `x19_612_trusted_lists` repository at tag `v2.4.1`, commit
`812fe781d37ead5b0ad562f2874ef5f67fc3a4dd`. Its license is retained in
`ETSI-LICENSE`.

The two imported W3C schemas are pinned locally so validation never performs
network I/O. Their original notices remain in the schema files. The build
rewrites only the two `schemaLocation` values in its generated copy; the
normative source files in this directory remain byte-for-byte upstream.
