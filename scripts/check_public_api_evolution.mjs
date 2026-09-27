// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import process from "node:process";

function rustSources(directory) {
  const sources = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const relativeParts = relative(process.cwd(), path).split(sep);
    if (relativeParts.includes("generated")) {
      continue;
    }
    if (statSync(path).isDirectory()) {
      sources.push(...rustSources(path));
    } else if (path.endsWith(".rs")) {
      sources.push(path);
    }
  }
  return sources;
}

function precedingAttributesContain(lines, declarationIndex, attribute) {
  for (let index = declarationIndex - 1; index >= 0; index -= 1) {
    const line = lines[index].trim();
    if (line === "" || line.startsWith("///") || line.startsWith("#[")) {
      if (line === attribute) {
        return true;
      }
      continue;
    }
    break;
  }
  return false;
}

const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
    encoding: "utf8",
  }),
);
const publishedPackages = metadata.packages.filter(
  (pkg) => pkg.publish === null || (Array.isArray(pkg.publish) && pkg.publish.length > 0),
);

const violations = [];
let publicEnumCount = 0;
for (const pkg of publishedPackages) {
  const sourceDirectory = join(dirname(pkg.manifest_path), "src");
  for (const source of rustSources(sourceDirectory)) {
    const lines = readFileSync(source, "utf8").split(/\r?\n/u);
    for (let index = 0; index < lines.length; index += 1) {
      if (!/^\s*pub(?:\([^)]*\))?\s+enum\s+[A-Za-z_][A-Za-z0-9_]*/u.test(lines[index])) {
        continue;
      }
      publicEnumCount += 1;
      if (!precedingAttributesContain(lines, index, "#[non_exhaustive]")) {
        violations.push(`${relative(process.cwd(), source)}:${index + 1}`);
      }
    }
  }
}

if (violations.length > 0) {
  process.stderr.write(
    `public enums in published crates must be #[non_exhaustive]:\n${violations.join("\n")}\n`,
  );
  process.exitCode = 1;
} else {
  process.stdout.write(
    `public API evolution check passed for ${publicEnumCount} handwritten enums\n`,
  );
}
