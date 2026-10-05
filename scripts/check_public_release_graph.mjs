#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  publicReleaseGraphFailures,
  publicReleaseVersions,
} from "./public_release_graph_core.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
if (process.argv.length !== 2) {
  console.error("usage: node scripts/check_public_release_graph.mjs");
  process.exit(2);
}
const fail = (reason) => {
  console.error(`public release graph check failed: ${reason}`);
  process.exit(1);
};

let workspace;
try {
  workspace = JSON.parse(
    execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 32_000_000,
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
} catch {
  fail("Cargo could not inspect the workspace manifests");
}
const failures = publicReleaseGraphFailures(workspace);
if (failures.length !== 0) fail(failures.join("; "));

const { facadeVersion, peerVersion } = publicReleaseVersions(workspace);

console.log(`public release graph passed for SSI ${peerVersion} and trust ${facadeVersion}`);
