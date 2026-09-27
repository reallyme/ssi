#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: scripts/check-protos-breaking.sh <baseline-git-ref>" >&2
  exit 2
fi

BASELINE_REF=$1
case "${BASELINE_REF}" in
  -* | *[!A-Za-z0-9._/-]*)
    echo "baseline Git ref contains unsupported characters" >&2
    exit 2
    ;;
esac

git cat-file -e "${BASELINE_REF}^{commit}"

# shellcheck source=scripts/proto-workspace.sh
. "$(dirname "$0")/proto-workspace.sh"

BREAKING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ssi-proto-breaking.XXXXXX")"
trap 'rm -rf "${BREAKING_ROOT}"' EXIT INT TERM

mkdir -p \
  "${BREAKING_ROOT}/baseline-source" \
  "${BREAKING_ROOT}/baseline/me-id" \
  "${BREAKING_ROOT}/baseline/reallyme/ssi/crates/proto" \
  "${BREAKING_ROOT}/current/me-id" \
  "${BREAKING_ROOT}/current/reallyme/ssi/crates/proto"

git archive "${BASELINE_REF}" crates/proto/proto \
  | tar -x -C "${BREAKING_ROOT}/baseline-source"

ln -s "${GITHUB_ROOT}/me-id/protos" "${BREAKING_ROOT}/baseline/me-id/protos"
ln -s "${BREAKING_ROOT}/baseline-source/crates/proto/proto" \
  "${BREAKING_ROOT}/baseline/reallyme/ssi/crates/proto/proto"
ln -s "${GITHUB_ROOT}/me-id/protos" "${BREAKING_ROOT}/current/me-id/protos"
ln -s "${SSI_ROOT}/crates/proto/proto" \
  "${BREAKING_ROOT}/current/reallyme/ssi/crates/proto/proto"

for workspace in baseline current; do
  printf '%s\n' "${BUF_CONFIG_JSON}" > "${BREAKING_ROOT}/${workspace}/buf.yaml"
  cp "${SSI_ROOT}/buf.lock" "${BREAKING_ROOT}/${workspace}/buf.lock"
  buf build "${BREAKING_ROOT}/${workspace}" \
    --output "${BREAKING_ROOT}/${workspace}.binpb"
done

buf breaking "${BREAKING_ROOT}/current.binpb" \
  --against "${BREAKING_ROOT}/baseline.binpb" \
  --config '{"version":"v2","breaking":{"use":["WIRE_JSON"]}}'
