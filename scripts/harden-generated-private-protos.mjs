// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "..");
const generatedPath = path.join(
  repositoryRoot,
  "crates/proto/src/generated/buffa/identity.credential.v1.subject_bundle.rs",
);

let source = await readFile(generatedPath, "utf8");

for (const typeName of ["SubjectPrivateBundle", "ClaimOpening"]) {
  const declaration = `#[serde(default)]\npub struct ${typeName} {`;
  const declarationOffset = source.indexOf(declaration);
  if (declarationOffset < 0) {
    throw new Error(`generated declaration not found for ${typeName}`);
  }

  const bodyStart = declarationOffset + declaration.length;
  const bodyEnd = source.indexOf("\n}\nimpl ", bodyStart);
  if (bodyEnd < 0) {
    throw new Error(`generated declaration boundary not found for ${typeName}`);
  }

  const body = source.slice(bodyStart, bodyEnd);
  const fieldAttributes = body.match(/#\[serde\(\n/g) ?? [];
  if (fieldAttributes.length !== 5) {
    throw new Error(`unexpected generated field count for ${typeName}`);
  }

  const hardenedBody = body.replaceAll("#[serde(\n", "#[serde(\n        default,\n");
  source =
    source.slice(0, declarationOffset) +
    `pub struct ${typeName} {` +
    hardenedBody +
    source.slice(bodyEnd);
}

await writeFile(generatedPath, source, "utf8");
