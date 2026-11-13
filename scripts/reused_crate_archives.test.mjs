// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseReusePolicy, prepareReusedArchive, readArchiveMembers, ReusedArchiveError, verifyReusedMembers } from "./reused_crate_archives.mjs";

const originalSha = "1".repeat(40);
const currentSha = "2".repeat(40);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const text = (value) => Buffer.from(value);
function fixture() {
  const pin = {
    name: "reallyme-test-fixture", version: "0.7.0", sha256: "a".repeat(64),
    source_commit: originalSha, path_in_vcs: "crates/fixture", allowed_changes: [],
  };
  const vcs = (sha, dirty) => text(JSON.stringify({ git: { sha1: sha, ...(dirty === undefined ? {} : { dirty }) }, path_in_vcs: pin.path_in_vcs }));
  const original = new Map([
    [".cargo_vcs_info.json", vcs(originalSha)], ["Cargo.toml", text("version = '0.7.0'\n")],
    ["Cargo.lock", text("locked dependencies")], ["src/lib.rs", text("pub fn value() -> u8 { 1 }\n")],
    ["src/tests.rs", text("original tests")], ["tests/binary.der", Buffer.from([0xff, 0, 0x80])],
  ]);
  const current = new Map(original); current.set(".cargo_vcs_info.json", vcs(currentSha));
  return { pin, original, current, vcs };
}
const fails = (action, code) => assert.throws(action, (error) => error instanceof ReusedArchiveError && error.code === code);
const policy = (pin) => ({ schema: "reallyme.ssi.prepublished-crates.v1", release_version: "0.7.0", crates: [pin] });

function approveChange(f, name, after) {
  f.pin.allowed_changes.push({ path: name, before_sha256: hash(f.original.get(name)), after_sha256: hash(text(after)), reason: "test-helper-relocation" });
  f.current.set(name, text(after));
}

test("version-scoped pins do not change future release packaging", () => {
  const f = fixture(); const names = new Set([f.pin.name]);
  assert.equal(parseReusePolicy(policy(f.pin), "0.7.0", names).size, 1);
  assert.equal(parseReusePolicy(policy(f.pin), "0.8.0", new Set()).size, 0);
  fails(() => parseReusePolicy(policy(f.pin), "0.7.0", new Set()), "policy-package-missing");
});

test("pins reject malformed identities, duplicate names, unsafe paths, and manifest exceptions", () => {
  const { pin } = fixture();
  for (const mutation of [
    (p) => { p.schema = "unknown"; }, (p) => { p.extra = true; }, (p) => { p.crates.push(p.crates[0]); },
    (p) => { p.crates[0].sha256 = "invalid"; }, (p) => { p.crates[0].source_commit = "short"; },
    (p) => { p.crates[0].path_in_vcs = "../outside"; }, (p) => { p.crates[0].version = "0.6.2"; },
    (p) => { p.crates[0].allowed_changes = [{ path: "Cargo.toml", before_sha256: "a".repeat(64), after_sha256: "b".repeat(64), reason: "test-helper-relocation" }]; },
  ]) {
    const p = structuredClone(policy(pin)); mutation(p);
    fails(() => parseReusePolicy(p, "0.7.0", new Set([pin.name])), "invalid-policy");
  }
});

test("identical packaged members accept only the verified source-commit metadata difference", () => {
  const f = fixture(); verifyReusedMembers(f.original, f.current, f.pin, currentSha);
  for (const member of ["Cargo.toml", "Cargo.lock", "src/lib.rs", "tests/binary.der"]) {
    const changed = new Map(f.current); changed.set(member, text("unexpected change"));
    fails(() => verifyReusedMembers(f.original, changed, f.pin, currentSha), "unapproved-content-change");
  }
});

test("test-only edits require both exact original and replacement hashes", () => {
  const f = fixture(); approveChange(f, "src/tests.rs", "relocated test helper");
  verifyReusedMembers(f.original, f.current, f.pin, currentSha);
  f.current.set("src/tests.rs", text("a different helper"));
  fails(() => verifyReusedMembers(f.original, f.current, f.pin, currentSha), "unapproved-content-change");
  const other = fixture(); approveChange(other, "src/tests.rs", "relocated test helper");
  other.original.set("src/tests.rs", text("wrong original tests"));
  fails(() => verifyReusedMembers(other.original, other.current, other.pin, currentSha), "unapproved-content-change");
});

test("added, missing, and stale approved members fail closed", () => {
  const f = fixture(); const added = new Map(f.current); added.set("new.rs", text("added"));
  fails(() => verifyReusedMembers(f.original, added, f.pin, currentSha), "archive-member-set-mismatch");
  const missing = new Map(f.current); missing.delete("tests/binary.der");
  fails(() => verifyReusedMembers(f.original, missing, f.pin, currentSha), "archive-member-set-mismatch");
  f.pin.allowed_changes.push({ path: "src/missing.rs", before_sha256: "a".repeat(64), after_sha256: "b".repeat(64), reason: "test-helper-relocation" });
  fails(() => verifyReusedMembers(f.original, f.current, f.pin, currentSha), "approved-change-missing");
});

test("source SHA, repository path, and clean provenance remain mandatory", () => {
  const f = fixture();
  for (const value of [f.vcs(originalSha), f.vcs(currentSha, true), text("{}"), text("invalid JSON")]) {
    const changed = new Map(f.current); changed.set(".cargo_vcs_info.json", value);
    fails(() => verifyReusedMembers(f.original, changed, f.pin, currentSha), "invalid-source-provenance");
  }
  const dirty = new Map(f.current); dirty.set(".cargo_vcs_info.json", f.vcs(currentSha, true));
  verifyReusedMembers(f.original, dirty, f.pin, currentSha, true);
  const originalDirty = new Map(f.original); originalDirty.set(".cargo_vcs_info.json", f.vcs(originalSha, true));
  fails(() => verifyReusedMembers(originalDirty, dirty, f.pin, currentSha, true), "invalid-source-provenance");
});

function tarFixture(directory, label, pin, members) {
  const root = path.join(directory, label); const prefix = `${pin.name}-${pin.version}`;
  for (const [name, bytes] of members) {
    const destination = path.join(root, prefix, name); fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.writeFileSync(destination, bytes);
  }
  const archive = path.join(directory, `${label}.crate`);
  const args = ["-czf", archive, "-C", root, ...[...members.keys()].map((name) => `${prefix}/${name}`)];
  const result = spawnSync("tar", args); assert.equal(result.status, 0);
  return archive;
}

test("immutable preparation validates real tar contents and restores exact registry bytes", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssi-reuse-test-"));
  try {
    const f = fixture(); approveChange(f, "src/tests.rs", "relocated test helper");
    const original = tarFixture(directory, "original", f.pin, f.original);
    const current = tarFixture(directory, "current", f.pin, f.current);
    f.pin.sha256 = hash(fs.readFileSync(original));
    const packageDirectory = path.join(directory, "package"); fs.mkdirSync(packageDirectory);
    const currentPath = path.join(packageDirectory, `${f.pin.name}-${f.pin.version}.crate`);
    const calls = [];
    const run = (command, args) => {
      calls.push([command, ...args]);
      if (command === "curl") fs.copyFileSync(original, args[args.indexOf("--output") + 1]);
      else if (command === "cargo") fs.copyFileSync(current, currentPath);
      else if (command === "git") return { status: 0, stdout: currentSha + "\n" };
      else assert.fail("unexpected external command");
      return { status: 0 };
    };
    prepareReusedArchive({ name: f.pin.name, version: f.pin.version }, f.pin, packageDirectory, run, false);
    assert.equal(hash(fs.readFileSync(currentPath)), f.pin.sha256);
    assert.deepEqual(readArchiveMembers(currentPath, f.pin), f.original);
    assert.ok(calls.filter(([command]) => command === "cargo").every((call) => call[1] === "package"));
    const badPin = { ...f.pin, sha256: "0".repeat(64) };
    fails(() => prepareReusedArchive({ name: f.pin.name, version: f.pin.version }, badPin, packageDirectory, run, false), "archive-checksum-mismatch");
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
