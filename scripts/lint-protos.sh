#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

# shellcheck source=scripts/proto-workspace.sh
. "$(dirname "$0")/proto-workspace.sh"

stage_buf_workspace
buf lint "${BUF_WORKSPACE}" \
  --path "${BUF_WORKSPACE}/reallyme/ssi/crates/proto/proto/identity" \
  --path "${BUF_WORKSPACE}/reallyme/ssi/crates/proto/proto/reallyme"
