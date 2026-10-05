// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const FACADE_NAME = "reallyme-trust";
const PEER_NAME = "reallyme-credential";
const REQUIRED_FACADE_PEERS = Object.freeze([
  "reallyme-trust-x509",
  "reallyme-trust-core",
  "reallyme-revocation",
  "reallyme-ssi-proto",
]);

export function publicReleaseGraphFailures(metadata) {
  if (!Array.isArray(metadata?.packages)) {
    return ["Cargo metadata omitted package records"];
  }
  const publicPackages = metadata.packages.filter((pkg) => pkg.publish === null);
  const byName = new Map(publicPackages.map((pkg) => [pkg.name, pkg]));
  if (byName.size !== publicPackages.length) {
    return ["public package names are duplicated in the workspace"];
  }
  const facade = byName.get(FACADE_NAME);
  const peer = byName.get(PEER_NAME);
  if (facade === undefined || peer === undefined) {
    return ["trust facade or credential peer is absent from the public package set"];
  }

  const failures = [];
  const peerVersion = peer.version;
  const sameRelease = facade.version === peerVersion;
  if (!sameRelease) {
    failures.push("trust facade must share the workspace release version");
  }

  for (const pkg of metadata.packages) {
    if (pkg.version !== peerVersion) {
      failures.push(`${pkg.name} is ${pkg.version}; workspace release must be ${peerVersion}`);
    }
    if (!Array.isArray(pkg.dependencies)) {
      failures.push(`${pkg.name} has no dependency records`);
      continue;
    }
    const seenFacadePeers = new Set();
    for (const dep of pkg.dependencies) {
      if (!byName.has(dep.name)) continue;
      if (pkg.name === FACADE_NAME) seenFacadePeers.add(dep.name);
      const exact = `=${peerVersion}`;
      const compatible = `^${peerVersion}`;
      if (dep.req !== exact && (pkg.name === FACADE_NAME || dep.req !== compatible)) {
        failures.push(`${pkg.name} pins ${dep.name} to ${dep.req}; expected ${exact}`);
      }
      if (dep.source != null || dep.path == null) {
        failures.push(`${pkg.name} must consume the ${peerVersion} workspace ${dep.name}`);
      }
    }
    if (pkg.name === FACADE_NAME) {
      for (const name of REQUIRED_FACADE_PEERS) {
        if (!seenFacadePeers.has(name)) {
          failures.push(`${pkg.name} is missing required public peer ${name}`);
        }
      }
    }
  }
  return failures;
}

export function publicReleaseVersions(metadata) {
  const packages = metadata.packages ?? [];
  return {
    facadeVersion: packages.find((pkg) => pkg.name === FACADE_NAME)?.version,
    peerVersion: packages.find((pkg) => pkg.name === PEER_NAME)?.version,
  };
}
