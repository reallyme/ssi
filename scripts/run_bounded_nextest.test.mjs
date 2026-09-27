// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./run_bounded_nextest.mjs", import.meta.url));

test("bounded nextest locks dependency resolution for discovery and execution", () => {
  const directory = mkdtempSync(join(tmpdir(), "ssi-nextest-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const preloadPath = join(directory, "mock.mjs");
    writeFileSync(preloadPath, `
import childProcess from "node:child_process";
import { writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const calls = [];
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  if (args[1] === "list") {
    return {
      status: 0,
      stdout: JSON.stringify({
        "rust-binaries": { "fixture::tests": { "binary-id": "fixture::tests" } },
      }),
    };
  }
  return { status: 0, stdout: "" };
};
syncBuiltinESMExports();
`);

    const result = spawnSync(
      process.execPath,
      ["--import", pathToFileURL(preloadPath).href, script, "default"],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);

    const calls = JSON.parse(readFileSync(callsPath, "utf8"));
    assert.equal(calls.length, 2);
    assert.deepEqual(calls.map((call) => call.slice(0, 4)), [
      ["cargo", "nextest", "list", "--locked"],
      ["cargo", "nextest", "run", "--locked"],
    ]);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
