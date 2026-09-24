#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

# shellcheck source=scripts/proto-workspace.sh
. "$(dirname "$0")/proto-workspace.sh"

buf lint "${GITHUB_ROOT}" \
  --config "${BUF_CONFIG_JSON}" \
  --path crates/proto/proto/identity \
  --path crates/proto/proto/reallyme
