#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

# shellcheck source=scripts/proto-workspace.sh
. "${SCRIPT_DIR}/proto-workspace.sh"

# Generate every SSI-owned package in one descriptor set so imported messages
# resolve inside the canonical Rust proto crate instead of through compatibility
# packages. The external crypto package remains owned by its source repository.
buf generate "${GITHUB_ROOT}" \
  --config "${BUF_CONFIG_JSON}" \
  --template "${SSI_ROOT}/buf.gen.yaml" \
  --include-imports \
  --path crates/proto/proto/identity \
  --path crates/proto/proto/reallyme

node "${SSI_ROOT}/scripts/sync-did-crypto-proto-boundary.mjs"
