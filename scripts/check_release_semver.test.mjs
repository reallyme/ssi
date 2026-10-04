// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compareVersions,
  parseVersion,
  publishedVersionFromResponse,
  requiresApiCompatibilityCheck,
  SemverGateError,
} from "./check_release_semver.mjs";

test("a pre-1.0 minor bump does not compile the incompatible baseline", () => {
  assert.equal(
    requiresApiCompatibilityCheck(parseVersion("0.4.0"), parseVersion("0.3.4")),
    false,
  );
});

test("compatible releases retain the API check", () => {
  assert.equal(
    requiresApiCompatibilityCheck(parseVersion("0.4.1"), parseVersion("0.4.0")),
    true,
  );
  assert.equal(
    requiresApiCompatibilityCheck(parseVersion("1.2.0"), parseVersion("1.1.9")),
    true,
  );
  assert.equal(
    requiresApiCompatibilityCheck(parseVersion("0.4.0"), parseVersion("0.4.0")),
    true,
  );
});

test("major releases do not run compatibility checks", () => {
  assert.equal(
    requiresApiCompatibilityCheck(parseVersion("1.0.0"), parseVersion("0.9.9")),
    false,
  );
  assert.equal(
    requiresApiCompatibilityCheck(parseVersion("2.0.0"), parseVersion("1.9.9")),
    false,
  );
});

test("an older planned version fails closed", () => {
  assert.equal(compareVersions(parseVersion("0.3.4"), parseVersion("0.4.0")), -1);
  assert.throws(
    () => requiresApiCompatibilityCheck(parseVersion("0.3.4"), parseVersion("0.4.0")),
    (error) =>
      error instanceof SemverGateError &&
      error.code === "planned-version-precedes-published-version",
  );
});

test("invalid versions fail closed", () => {
  for (const value of ["0.4", "v0.4.0", "00.4.0", "0.4.0-beta", "999999999999999999999.0.0"]) {
    assert.throws(
      () => parseVersion(value),
      (error) => error instanceof SemverGateError && error.code === "invalid-version",
    );
  }
});

test("malformed registry responses fail closed", () => {
  for (const body of [null, {}, { crate: null }, { crate: { max_stable_version: 4 } }]) {
    assert.throws(
      () => publishedVersionFromResponse(body),
      (error) => error instanceof SemverGateError && error.code === "invalid-registry-response",
    );
  }
  assert.deepEqual(publishedVersionFromResponse({ crate: { max_stable_version: "0.3.4" } }), {
    major: 0,
    minor: 3,
    patch: 4,
  });
});
