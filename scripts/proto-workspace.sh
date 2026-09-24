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
