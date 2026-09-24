#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

require "rbconfig"

root = File.expand_path("..", __dir__)
taxonomy_root = ENV.fetch("REALLYME_IDENTITY_TAXONOMY_ROOT", File.expand_path("../identity-taxonomy", root))
arguments = [
  RbConfig.ruby,
  File.join(taxonomy_root, "scripts", "generate_repository_conformance_ledger.rb"),
  "--repository", "reallyme/ssi",
  "--consumer-root", root,
  "--inventory", File.join(taxonomy_root, "conformance", "inventory", "requirements.json"),
  "--evidence-map", File.join(root, "conformance", "taxonomy", "conformance-evidence.yaml"),
  "--artifact-map", File.join(root, "conformance", "taxonomy", "conformance-artifacts.yaml"),
  "--output", File.join(root, "conformance", "taxonomy", "conformance-ledger-evidence.json"),
  *ARGV
]
exec(*arguments)
