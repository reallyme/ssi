// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { wasmBindgenCliPinFailures } from "./check_wasm_bindgen_cli_pin.mjs";

const lockfile = readFileSync(new URL("../Cargo.lock", import.meta.url), "utf8");
const workflow = readFileSync(new URL("../.github/workflows/rust-ci.yml", import.meta.url), "utf8");

test("Wasm test runner matches the locked wasm-bindgen version", () => {
  assert.deepEqual(wasmBindgenCliPinFailures(lockfile, workflow), []);
});

test("a stale Wasm test runner version is rejected", () => {
  const installCommand = /cargo install wasm-bindgen-cli --version [0-9]+\.[0-9]+\.[0-9]+ --locked/u
    .exec(workflow)?.[0];
  assert.ok(installCommand);
  const stale = workflow.replace(
    installCommand,
    "cargo install wasm-bindgen-cli --version 0.0.0 --locked",
  );
  assert.deepEqual(wasmBindgenCliPinFailures(lockfile, stale), [
    "Rust CI wasm-bindgen-cli version does not match Cargo.lock",
  ]);
});

test("ambiguous lockfile or runner versions are rejected", () => {
  const duplicateLockfile = `${lockfile}\n[[package]]\nname = "wasm-bindgen"\nversion = "0.2.127"\n`;
  assert.deepEqual(wasmBindgenCliPinFailures(duplicateLockfile, workflow), [
    "Cargo.lock must resolve exactly one wasm-bindgen version",
  ]);
  const duplicateRunner = `${workflow}\n      - name: Duplicate runner\n        run: cargo install wasm-bindgen-cli --version 0.2.129 --locked\n`;
  assert.deepEqual(wasmBindgenCliPinFailures(lockfile, duplicateRunner), [
    "Rust CI wasm-bindgen-cli version does not match Cargo.lock",
  ]);
});
