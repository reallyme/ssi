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

echo "generated protobuf bindings are fresh"
