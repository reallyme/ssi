// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// The test runner and the linked wasm-bindgen crate use an exact-match binary
// schema. Check the resolved version so a lockfile refresh cannot break CI.
export function wasmBindgenCliPinFailures(lockfile, workflow) {
  if (typeof lockfile !== "string" || typeof workflow !== "string") {
    return ["invalid Cargo.lock or Rust CI workflow"];
  }

  const resolvedVersions = [...lockfile.matchAll(/^name = "wasm-bindgen"\r?\nversion = "([0-9]+\.[0-9]+\.[0-9]+)"$/gmu)]
    .map((match) => match[1]);
  if (resolvedVersions.length !== 1) {
    return ["Cargo.lock must resolve exactly one wasm-bindgen version"];
  }

  const runnerVersions = [...workflow.matchAll(
    /^[ \t]+run: cargo install wasm-bindgen-cli --version ([0-9]+\.[0-9]+\.[0-9]+) --locked[ \t]*$/gmu,
  )].map((match) => match[1]);
  if (runnerVersions.length !== 1 || runnerVersions[0] !== resolvedVersions[0]) {
    return ["Rust CI wasm-bindgen-cli version does not match Cargo.lock"];
  }
  return [];
}
