// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const PINNED_CHECKOUTS = [
  {
    package: "reallyme-cose",
    step: "Checkout pinned COSE conformance source",
    repository: "reallyme/cose",
    path: "reallyme/cose",
  },
  {
    package: "reallyme-jose",
    step: "Checkout pinned JOSE conformance source",
    repository: "reallyme/jose",
    path: "reallyme/jose",
  },
];

const SHA_PATTERN = /^[0-9a-f]{40}$/u;

function checkoutFields(workflow, stepName) {
  const lines = workflow.split(/\r?\n/u);
  const marker = `      - name: ${stepName}`;
  const matches = lines.flatMap((line, index) => (line === marker ? [index] : []));
  if (matches.length !== 1) return null;
  const fields = new Map();
  for (let index = matches[0] + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.startsWith("      - name:") || (line.startsWith("  ") && !line.startsWith("      "))) {
      break;
    }
    const field = /^          (repository|ref|path): ([^#\s]+)\s*$/u.exec(line);
    if (field !== null) {
      if (fields.has(field[1])) return null;
      fields.set(field[1], field[2]);
    }
  }
  return fields;
}

// Shallow CI checkouts must contain exactly the source commits whose tests are
// named in the manifest; a different checkout cannot provide that evidence.
export function upstreamCheckoutPinFailures(manifest, workflow) {
  if (
    typeof manifest !== "object" ||
    manifest === null ||
    manifest.schema !== "reallyme.identity.conformance.upstream.v2" ||
    !Array.isArray(manifest.sources) ||
    typeof workflow !== "string"
  ) {
    return ["invalid upstream manifest or workflow"];
  }

  const externalSources = manifest.sources.filter(
    (source) => typeof source?.path === "string" && source.path.startsWith("crates.io:"),
  );
  const expectedPackages = new Set(PINNED_CHECKOUTS.map((checkout) => checkout.package));
  const failures = [];
  for (const source of externalSources) {
    if (!expectedPackages.has(source.execution?.package)) {
      failures.push("unexpected external conformance package");
    }
  }
  for (const checkout of PINNED_CHECKOUTS) {
    const packageSources = externalSources.filter(
      (source) => source.execution?.package === checkout.package,
    );
    if (
      packageSources.some(
        (source) => source.execution?.repository !== `https://github.com/${checkout.repository}`,
      )
    ) {
      failures.push(`${checkout.package} source repository does not match its CI checkout`);
    }
    const commits = new Set(
      packageSources.map((source) => source.execution?.source_commit),
    );
    if (commits.size !== 1 || !SHA_PATTERN.test([...commits][0])) {
      failures.push(`${checkout.package} has no unique source commit`);
      continue;
    }
    const fields = checkoutFields(workflow, checkout.step);
    if (
      fields === null ||
      fields.get("repository") !== checkout.repository ||
      fields.get("path") !== checkout.path ||
      fields.get("ref") !== [...commits][0]
    ) {
      failures.push(`${checkout.package} CI checkout does not match its source commit`);
    }
  }
  return failures;
}
