#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

SSI_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_CRATES_ROOT="${SSI_ROOT}/crates/proto"
PROTO_ROOT="${PROTO_CRATES_ROOT}/proto"
COMMON_PROTO="${PROTO_ROOT}/reallyme/identity/common/v1/errors.proto"
IDENTITY_CORE_ERROR_PROTO="${PROTO_ROOT}/reallyme/identity_core/v1/errors.proto"
DID_PROTO="${PROTO_ROOT}/identity/did/v1/did.proto"
DID_ME_PROTO="${PROTO_ROOT}/identity/did/me/v1/did_me.proto"
AUDIT_PROTO="${PROTO_ROOT}/identity/audit/v1/audit.proto"
PRESENTATION_PROTO="${PROTO_ROOT}/identity/presentation/v1/presentation.proto"
TRUST_PROTO="${PROTO_ROOT}/identity/trust/v1/trust.proto"

require_contains() {
  file="$1"
  needle="$2"

  if ! grep -Fq "${needle}" "${file}"; then
    echo "missing expected protobuf contract text in ${file}: ${needle}" >&2
    exit 1
  fi
}

if find "${PROTO_CRATES_ROOT}" -path '*/proto/*' -name 'crypto.proto' | grep -q .; then
  echo "ssi must import reallyme/crypto protobufs, not own crypto.proto" >&2
  exit 1
fi

if find "${PROTO_CRATES_ROOT}" -path '*/proto/*.proto' -type f \
  -exec grep -l -E '^[[:space:]]*(service|rpc)[[:space:]]' {} + | grep -q .; then
  echo "ssi protobufs are message contracts only; Connect services live in protocol, wallet, service, or SDK adapter repositories" >&2
  exit 1
fi

require_contains \
  "${COMMON_PROTO}" \
  'package reallyme.identity.common.v1;'
require_contains \
  "${COMMON_PROTO}" \
  "IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE = 4;"
require_contains \
  "${COMMON_PROTO}" \
  "IDENTITY_STACK_ERROR_DOMAIN_CODEC = 10;"
require_contains \
  "${COMMON_PROTO}" \
  'option java_package = "me.really.identity.common.v1";'
require_contains \
  "${IDENTITY_CORE_ERROR_PROTO}" \
  'package reallyme.identity_core.v1;'
require_contains \
  "${IDENTITY_CORE_ERROR_PROTO}" \
  "IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT = 1;"
require_contains \
  "${IDENTITY_CORE_ERROR_PROTO}" \
  'option java_package = "me.really.identity.core.v1";'
require_contains \
  "${DID_PROTO}" \
  'import "reallyme/crypto/v1/crypto.proto";'
require_contains \
  "${DID_PROTO}" \
  "reallyme.crypto.v1.CryptoAlgorithmIdentifier"
require_contains \
  "${DID_PROTO}" \
  'option java_package = "me.really.identity.did.v1";'
require_contains \
  "${DID_ME_PROTO}" \
  'option java_package = "me.really.identity.did.me.v1";'
require_contains \
  "${AUDIT_PROTO}" \
  'option java_package = "me.really.identity.audit.v1";'
require_contains \
  "${PRESENTATION_PROTO}" \
  'option java_package = "me.really.identity.presentation.v1";'
require_contains \
  "${TRUST_PROTO}" \
  'package identity.trust.v1;'
require_contains \
  "${TRUST_PROTO}" \
  "message TrustDecision"
require_contains \
  "${TRUST_PROTO}" \
  "enum TrustDecisionFailure"
require_contains \
  "${TRUST_PROTO}" \
  'option java_package = "me.really.identity.trust.v1";'
echo "protobuf contract checks passed"
