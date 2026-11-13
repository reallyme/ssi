// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MAX_ARCHIVE_BYTES = 8 * 1024 * 1024;
const MAX_MEMBER_BYTES = 8 * 1024 * 1024;
const MAX_MEMBERS = 512;
const MAX_POLICY_BYTES = 65_536;
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const digest = (value, pattern) => typeof value === "string" && pattern.test(value);
const POLICY_URL = new URL("./prepublished_crates.json", import.meta.url);

export class ReusedArchiveError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReusedArchiveError";
    this.code = code;
  }
}
const fail = (code) => { throw new ReusedArchiveError(code); };
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value, keys) => record(value) && Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
const safeMember = (value) => typeof value === "string" && value.length <= 512 &&
  /^[A-Za-z0-9_./-]+$/u.test(value) && value.split("/").every((part) => part.length !== 0 && part !== "." && part !== "..");

/** An explicit, version-scoped registry pin, never a general permission to skip source comparison. */
export function parseReusePolicy(value, version, packageNames) {
  if (!exactKeys(value, ["schema", "release_version", "crates"]) ||
      value.schema !== "reallyme.ssi.prepublished-crates.v1" ||
      typeof value.release_version !== "string" || !/^\d+\.\d+\.\d+$/u.test(value.release_version) ||
      !Array.isArray(value.crates) || value.crates.length === 0 || value.crates.length > 16) fail("invalid-policy");
  const pins = new Map();
  for (const pin of value.crates) {
    if (!exactKeys(pin, ["name", "version", "sha256", "source_commit", "path_in_vcs", "allowed_changes"]) ||
        typeof pin.name !== "string" || !/^reallyme-[a-z0-9-]+$/u.test(pin.name) ||
        pin.version !== value.release_version || !digest(pin.sha256, SHA256) || !digest(pin.source_commit, COMMIT) ||
        !safeMember(pin.path_in_vcs) || !Array.isArray(pin.allowed_changes) || pin.allowed_changes.length > 16 || pins.has(pin.name)) fail("invalid-policy");
    const seen = new Set();
    for (const change of pin.allowed_changes) {
      if (!exactKeys(change, ["path", "before_sha256", "after_sha256", "reason"]) ||
          !safeMember(change.path) || !change.path.startsWith("src/") || !change.path.endsWith(".rs") ||
          !digest(change.before_sha256, SHA256) || !digest(change.after_sha256, SHA256) ||
          change.before_sha256 === change.after_sha256 || change.reason !== "test-helper-relocation" || seen.has(change.path)) fail("invalid-policy");
      seen.add(change.path);
    }
    pins.set(pin.name, pin);
  }
  if (version !== value.release_version) return new Map();
  if ([...pins.keys()].some((name) => !packageNames.has(name))) fail("policy-package-missing");
  return pins;
}

export function loadReusePolicy(version, packageNames) {
  const status = fs.lstatSync(POLICY_URL);
  if (!status.isFile() || status.isSymbolicLink() || status.size > MAX_POLICY_BYTES) fail("invalid-policy");
  let value;
  try { value = JSON.parse(fs.readFileSync(POLICY_URL, "utf8")); }
  catch { fail("invalid-policy"); }
  return parseReusePolicy(value, version, packageNames);
}

function command(commandName, args, maximum = MAX_MEMBER_BYTES) {
  const result = spawnSync(commandName, args, { maxBuffer: maximum });
  if (result.error || result.status !== 0) fail("archive-command-failed");
  return result.stdout;
}

/** Read members without extracting untrusted paths into the filesystem. */
export function readArchiveMembers(archive, pin) {
  const status = fs.lstatSync(archive);
  if (!status.isFile() || status.isSymbolicLink() || status.size === 0 || status.size > MAX_ARCHIVE_BYTES) fail("archive-resource-limit");
  const prefix = `${pin.name}-${pin.version}/`;
  const listing = command("tar", ["-tzf", archive], 262_144).toString("utf8").trimEnd().split("\n");
  if (listing.length > MAX_MEMBERS) fail("archive-resource-limit");
  const members = new Map();
  let total = 0;
  for (const name of listing) {
    const member = name.slice(prefix.length);
    if (!name.startsWith(prefix) || !safeMember(member) || members.has(member)) fail("invalid-archive-member");
    const bytes = command("tar", ["-xOf", archive, name]);
    total += bytes.length;
    if (total > 64 * 1024 * 1024) fail("archive-resource-limit");
    members.set(member, bytes);
  }
  return members;
}

function provenance(members, pin, expectedSha, allowDirty) {
  let vcs;
  try { vcs = JSON.parse(members.get(".cargo_vcs_info.json").toString("utf8")); }
  catch { fail("invalid-source-provenance"); }
  if (!exactKeys(vcs, ["git", "path_in_vcs"]) || !record(vcs.git) ||
      !(exactKeys(vcs.git, ["sha1"]) || exactKeys(vcs.git, ["sha1", "dirty"])) || vcs.git.sha1 !== expectedSha ||
      vcs.path_in_vcs !== pin.path_in_vcs || (vcs.git.dirty !== undefined && vcs.git.dirty !== false && !(allowDirty && vcs.git.dirty === true))) fail("invalid-source-provenance");
}

/** Every byte remains checked, except source-commit metadata and pinned test-only edits. */
export function verifyReusedMembers(original, current, pin, currentSha, allowDirty = false) {
  if (!digest(currentSha, COMMIT)) fail("invalid-source-provenance");
  provenance(original, pin, pin.source_commit, false);
  provenance(current, pin, currentSha, allowDirty);
  const originalNames = [...original.keys()].sort();
  if (originalNames.join("\n") !== [...current.keys()].sort().join("\n")) fail("archive-member-set-mismatch");
  const changes = new Map(pin.allowed_changes.map((change) => [change.path, change]));
  for (const name of originalNames) {
    if (name === ".cargo_vcs_info.json") continue;
    const before = original.get(name);
    const after = current.get(name);
    const approved = changes.get(name);
    if (approved) {
      if (sha256(before) !== approved.before_sha256 || sha256(after) !== approved.after_sha256) fail("unapproved-content-change");
      changes.delete(name);
    } else if (!before.equals(after)) fail("unapproved-content-change");
  }
  if (changes.size !== 0) fail("approved-change-missing");
}

/** Fetch the immutable original, reproduce current sources, and compare before adoption. */
export function prepareReusedArchive(pkg, pin, packageDirectory, run, allowDirty) {
  if (pkg.name !== pin.name || pkg.version !== pin.version) fail("policy-package-mismatch");
  fs.mkdirSync(packageDirectory, { recursive: true });
  const directory = fs.mkdtempSync(path.join(packageDirectory, "reuse-validation-"));
  const originalPath = path.join(directory, `${pkg.name}-${pkg.version}.crate`);
  try {
    const url = `https://static.crates.io/crates/${pin.name}/${pin.name}-${pin.version}.crate`;
    const result = run("curl", ["--fail-with-body", "--location", "--proto", "=https", "--tlsv1.2",
      "--retry", "5", "--retry-all-errors", "--max-filesize", String(MAX_ARCHIVE_BYTES), "--output", originalPath, url], { capture: true });
    if (result.status !== 0) fail("archive-download-failed");
    const status = fs.lstatSync(originalPath);
    if (!status.isFile() || status.isSymbolicLink() || status.size === 0 || status.size > MAX_ARCHIVE_BYTES) fail("archive-resource-limit");
    const originalBytes = fs.readFileSync(originalPath);
    if (sha256(originalBytes) !== pin.sha256) fail("archive-checksum-mismatch");
    const original = readArchiveMembers(originalPath, pin);
    // Package individually: dependencies already in the registry must keep
    // their real checksums rather than temporary workspace-registry hashes.
    const args = ["package", "-p", pkg.name, "--no-verify", "--locked"];
    if (allowDirty) args.push("--allow-dirty");
    const packaged = run("cargo", args);
    if (packaged.status !== 0) fail("archive-packaging-failed");
    const currentPath = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
    const current = readArchiveMembers(currentPath, pin);
    const head = run("git", ["rev-parse", "HEAD"], { capture: true });
    if (head.status !== 0) fail("invalid-source-provenance");
    verifyReusedMembers(original, current, pin, head.stdout.trim(), allowDirty);
    fs.writeFileSync(currentPath, originalBytes);
    console.log(`verified immutable ${pkg.name} ${pkg.version} from ${pin.source_commit}`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
