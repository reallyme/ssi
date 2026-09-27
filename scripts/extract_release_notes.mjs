// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";

const MAX_CHANGELOG_BYTES = 1_048_576;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;

const version = process.argv[2];
if (typeof version !== "string" || !VERSION_PATTERN.test(version)) {
  process.stderr.write("invalid release version\n");
  process.exitCode = 1;
} else {
  const changelog = readFileSync("CHANGELOG.md");
  if (changelog.length > MAX_CHANGELOG_BYTES) {
    process.stderr.write("changelog exceeds release-note limit\n");
    process.exitCode = 1;
  } else {
    const text = changelog.toString("utf8");
    const heading = `## ${version}`;
    const lines = text.split(/\r?\n/u);
    const start = lines.findIndex((line) => line === heading);
    const duplicate = lines.findIndex((line, index) => index > start && line === heading);
    if (start < 0 || duplicate >= 0) {
      process.stderr.write("release changelog section is missing or duplicated\n");
      process.exitCode = 1;
    } else {
      const next = lines.findIndex((line, index) => index > start && /^## /u.test(line));
      const body = lines.slice(start + 1, next < 0 ? lines.length : next).join("\n").trim();
      if (body.length === 0) {
        process.stderr.write("release changelog section is empty\n");
        process.exitCode = 1;
      } else {
        process.stdout.write(`${body}\n`);
      }
    }
  }
}
