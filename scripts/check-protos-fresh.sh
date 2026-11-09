#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

SSI_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GENERATED_DIR="${SSI_ROOT}/crates/proto/src/generated/buffa"
SNAPSHOT_DIR="$(mktemp -d)"
trap 'rm -rf "${SNAPSHOT_DIR}"' EXIT HUP INT TERM

# Compare the generated working tree with its own pre-run bytes. A Git diff
# against HEAD would reject valid, uncommitted schema and binding changes.
cp -R "${GENERATED_DIR}" "${SNAPSHOT_DIR}/buffa"
"${SSI_ROOT}/scripts/generate-protos.sh"

cargo fmt -p reallyme-ssi-proto

if git -C "${SSI_ROOT}" check-ignore -q \
  "crates/proto/src/generated/buffa/mod.rs"; then
  echo "canonical generated bindings are ignored and cannot be freshness-checked" >&2
  exit 1
fi

if ! diff -qr "${SNAPSHOT_DIR}/buffa" "${GENERATED_DIR}"; then
  echo "generated protobuf bindings differ from the pre-run working tree" >&2
  exit 1
fi

GENERATED_STATUS="$(git -C "${SSI_ROOT}" status --porcelain --untracked-files=all -- \
  crates/proto/src/generated/buffa)"
if printf '%s\n' "${GENERATED_STATUS}" | grep -q '^??'; then
  echo "protobuf regeneration produced untracked generated files" >&2
  exit 1
fi

echo "generated protobuf bindings are fresh"
