#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# This file is sourced by proto entrypoints. Keeping the module inventory in
# one place prevents generation and lint from silently resolving different
# copies of the same contract.
PROTO_SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
SSI_ROOT="$(cd "${PROTO_SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC2034 # Exported to scripts that source this inventory.
GITHUB_ROOT="$(cd "${SSI_ROOT}/../.." && pwd)"

# shellcheck disable=SC2034 # Exported to scripts that source this inventory.
BUF_CONFIG_JSON='{"version":"v2","modules":[{"path":"me-id/protos"},{"path":"reallyme/ssi/crates/proto/proto"}],"lint":{"use":["STANDARD"]},"breaking":{"use":["FILE"]},"deps":["buf.build/googleapis/googleapis"]}'

# Stage the generation workspace in a private temporary directory so buf reads
# the committed buf.lock. An inline --config against GITHUB_ROOT has no lock
# file and would silently resolve the newest remote dependency revision.
stage_buf_workspace() {
  BUF_WORKSPACE="$(mktemp -d "${TMPDIR:-/tmp}/ssi-buf-workspace.XXXXXX")"
  trap 'rm -rf "${BUF_WORKSPACE}"' EXIT INT TERM
  mkdir -p "${BUF_WORKSPACE}/me-id" "${BUF_WORKSPACE}/reallyme/ssi/crates/proto"
  ln -s "${GITHUB_ROOT}/me-id/protos" "${BUF_WORKSPACE}/me-id/protos"
  ln -s "${SSI_ROOT}/crates/proto/proto" "${BUF_WORKSPACE}/reallyme/ssi/crates/proto/proto"
  printf '%s\n' "${BUF_CONFIG_JSON}" > "${BUF_WORKSPACE}/buf.yaml"
  cp "${SSI_ROOT}/buf.lock" "${BUF_WORKSPACE}/buf.lock"
}
