#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly GITLEAKS_VERSION="8.30.1"
readonly GITLEAKS_ARCHIVE_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"

scan_directory="$(mktemp -d)"
readonly scan_directory
trap 'rm -rf -- "${scan_directory}"' EXIT

readonly archive_path="${scan_directory}/gitleaks.tar.gz"
readonly binary_path="${scan_directory}/gitleaks"
readonly download_url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"

curl --fail --show-error --silent --location \
  --output "${archive_path}" \
  "${download_url}"
printf '%s  %s\n' "${GITLEAKS_ARCHIVE_SHA256}" "${archive_path}" \
  | sha256sum --check --strict
tar --extract --gzip --file "${archive_path}" --directory "${scan_directory}" gitleaks
chmod 0755 "${binary_path}"

"${binary_path}" git --redact --no-banner --verbose .
