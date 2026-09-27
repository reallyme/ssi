#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

SSI_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

"${SSI_ROOT}/scripts/generate-protos.sh"

cargo fmt -p reallyme-ssi-proto

if git -C "${SSI_ROOT}" check-ignore -q \
  "crates/proto/src/generated/buffa/mod.rs"; then
  echo "canonical generated bindings are ignored and cannot be freshness-checked" >&2
  exit 1
fi

git -C "${SSI_ROOT}" diff --exit-code -- \
  crates/proto/src/generated/buffa

if git -C "${SSI_ROOT}" status --porcelain --untracked-files=all -- \
  crates/proto/src/generated/buffa | grep -q '^??'; then
  echo "protobuf regeneration produced untracked generated files" >&2
  exit 1
fi

echo "generated protobuf bindings are fresh"
