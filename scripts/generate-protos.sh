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
stage_buf_workspace
buf generate "${BUF_WORKSPACE}" \
  --template "${SSI_ROOT}/buf.gen.yaml" \
  --include-imports \
  --path "${BUF_WORKSPACE}/reallyme/ssi/crates/proto/proto/identity" \
  --path "${BUF_WORKSPACE}/reallyme/ssi/crates/proto/proto/reallyme"

node "${SSI_ROOT}/scripts/sync-did-crypto-proto-boundary.mjs"
node "${SSI_ROOT}/scripts/harden-generated-private-protos.mjs"

# Keep generated Rust byte-for-byte aligned with the repository formatter so
# freshness checks and `cargo fmt --check` agree on the canonical output.
cargo fmt --package reallyme-ssi-proto --manifest-path "${SSI_ROOT}/Cargo.toml"
