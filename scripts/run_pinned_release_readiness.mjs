#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const RELEASE_READINESS_COMMIT = "dc6a067b31ec731a44eeb416a514ab218d27dd06";
const RELEASE_READINESS_CORE_SHA256 =
  "eb2cefa283a60fb21a2e51b5cc8d03600bb986ca0409d0318f764338a20395ba";
const RELEASE_READINESS_RUNNER_SHA256 =
  "ff5a11153e9fa365bbb0bbd98b6215eb50f91dbe1f2fbf20d498ecc512e37699";
const RELEASE_READINESS_BASE_URL =
  `https://raw.githubusercontent.com/reallyme/release-readiness/${RELEASE_READINESS_COMMIT}`;
const LOCAL_CHECKER_PATH = "scripts/check_release_readiness.mjs";
const MAX_CORE_BYTES = 262_144;
const MAX_RUNNER_BYTES = 65_536;
const FETCH_TIMEOUT_MILLISECONDS = 30_000;

const BootstrapFailureCode = Object.freeze({
  CheckerInvalid: "local checker is missing or invalid",
  DownloadFailed: "pinned public release could not be downloaded",
  DownloadInvalid: "pinned public release returned invalid content",
  DigestMismatch: "pinned public release digest does not match the reviewed commit",
  RunnerFailed: "pinned public runner could not be started",
  RunnerIndeterminate: "pinned public runner ended without a deterministic status",
});

class PinnedReleaseReadinessError extends Error {
  constructor(code) {
    super(code);
    this.name = "PinnedReleaseReadinessError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new PinnedReleaseReadinessError(code);
};

const sha256 = (value) => createHash("sha256").update(value).digest();

const expectedDigest = (hexDigest) => {
  const digest = Buffer.from(hexDigest, "hex");
  if (digest.length !== 32) {
    fail(BootstrapFailureCode.DigestMismatch);
  }
  return digest;
};

const fetchPinnedFile = async ({ path, maximumBytes, digest }) => {
  let response;
  try {
    response = await fetch(`${RELEASE_READINESS_BASE_URL}/${path}`, {
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MILLISECONDS),
    });
  } catch {
    fail(BootstrapFailureCode.DownloadFailed);
  }
  if (!response.ok || response.body === null) {
    fail(BootstrapFailureCode.DownloadInvalid);
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^[1-9][0-9]*$/u.test(contentLength)) {
      fail(BootstrapFailureCode.DownloadInvalid);
    }
    const parsedLength = Number.parseInt(contentLength, 10);
    if (
      !Number.isSafeInteger(parsedLength) ||
      parsedLength <= 0 ||
      parsedLength > maximumBytes
    ) {
      fail(BootstrapFailureCode.DownloadInvalid);
    }
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalLength = 0;
  while (true) {
    let result;
    try {
      result = await reader.read();
    } catch {
      fail(BootstrapFailureCode.DownloadFailed);
    }
    if (result.done) {
      break;
    }
    const chunk = result.value;
    if (!(chunk instanceof Uint8Array) || chunk.length > maximumBytes - totalLength) {
      fail(BootstrapFailureCode.DownloadInvalid);
    }
    chunks.push(chunk);
    totalLength += chunk.length;
  }
  if (totalLength === 0) {
    fail(BootstrapFailureCode.DownloadInvalid);
  }
  const contents = Buffer.concat(chunks, totalLength);
  if (!timingSafeEqual(sha256(contents), expectedDigest(digest))) {
    fail(BootstrapFailureCode.DigestMismatch);
  }
  return contents;
};

let temporaryPackageRoot;
let exitCode = 1;
try {
  const checkerStatus = lstatSync(LOCAL_CHECKER_PATH);
  if (checkerStatus.isSymbolicLink() || !checkerStatus.isFile()) {
    fail(BootstrapFailureCode.CheckerInvalid);
  }

  const [core, runner] = await Promise.all([
    fetchPinnedFile({
      path: "core.mjs",
      maximumBytes: MAX_CORE_BYTES,
      digest: RELEASE_READINESS_CORE_SHA256,
    }),
    fetchPinnedFile({
      path: "scripts/run-consumer-check.mjs",
      maximumBytes: MAX_RUNNER_BYTES,
      digest: RELEASE_READINESS_RUNNER_SHA256,
    }),
  ]);

  temporaryPackageRoot = mkdtempSync(join(tmpdir(), "reallyme-release-readiness-"));
  const temporaryScripts = join(temporaryPackageRoot, "scripts");
  mkdirSync(temporaryScripts, { mode: 0o700 });
  const temporaryCore = join(temporaryPackageRoot, "core.mjs");
  const temporaryRunner = join(temporaryScripts, "run-consumer-check.mjs");
  writeFileSync(temporaryCore, core, { mode: 0o600 });
  writeFileSync(temporaryRunner, runner, { mode: 0o600 });

  const child = spawnSync(
    process.execPath,
    [temporaryRunner, ...process.argv.slice(2)],
    { env: process.env, stdio: "inherit" },
  );
  if (child.error !== undefined) {
    fail(BootstrapFailureCode.RunnerFailed);
  }
  if (!Number.isInteger(child.status)) {
    fail(BootstrapFailureCode.RunnerIndeterminate);
  }
  exitCode = child.status;
} catch (error) {
  const code =
    error instanceof PinnedReleaseReadinessError
      ? error.code
      : BootstrapFailureCode.CheckerInvalid;
  console.error(`pinned release readiness failed: ${code}`);
} finally {
  if (typeof temporaryPackageRoot === "string") {
    try {
      rmSync(temporaryPackageRoot, { recursive: true, force: true });
    } catch {
      console.error("pinned release readiness failed: temporary package cleanup failed");
      exitCode = 1;
    }
  }
}

process.exitCode = exitCode;
