#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  changelogContainsRelease,
  ReleaseSourceError,
  permitsRecordedRunResume,
  resolveReleaseVersion,
} from "./verify_release_source.mjs";

test("release changelog contains exactly one exact version heading", () => {
  assert.equal(changelogContainsRelease("# Changelog\n\n## 0.3.0\n", "0.3.0"), true);
  assert.equal(changelogContainsRelease("# Changelog\n\n## v0.3.0\n", "0.3.0"), false);
  assert.equal(
    changelogContainsRelease("# Changelog\n\n## 0.3.0\n\n## 0.3.0\n", "0.3.0"),
    false,
  );
});

test("release version is derived only when every publishable crate agrees", () => {
  assert.equal(
    resolveReleaseVersion({
      derivesVersion: true,
      manifestVersions: ["0.1.0", "0.1.0"],
      requestedVersion: undefined,
    }),
    "0.1.0",
  );
  assert.throws(
    () =>
      resolveReleaseVersion({
        derivesVersion: true,
        manifestVersions: ["0.1.0", "0.2.0"],
        requestedVersion: undefined,
      }),
    ReleaseSourceError,
  );
});

test("only a rerun of the exact main release workflow may resume a recorded SHA", () => {
  const valid = {
    GITHUB_ACTIONS: "true",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_WORKFLOW_REF:
      "reallyme/ssi/.github/workflows/crates-release.yml@refs/heads/main",
    GITHUB_RUN_ATTEMPT: "2",
  };
  assert.equal(permitsRecordedRunResume(valid), true);
  assert.equal(permitsRecordedRunResume({ ...valid, GITHUB_RUN_ATTEMPT: "1" }), false);
  assert.equal(permitsRecordedRunResume({ ...valid, GITHUB_EVENT_NAME: "push" }), false);
  assert.equal(
    permitsRecordedRunResume({
      ...valid,
      GITHUB_WORKFLOW_REF: "reallyme/ssi/.github/workflows/other.yml@refs/heads/main",
    }),
    false,
  );
  assert.equal(
    permitsRecordedRunResume({
      ...valid,
      GITHUB_WORKFLOW_REF:
        "reallyme/ssi/.github/workflows/crates-release.yml@refs/heads/release",
    }),
    false,
  );
});

test("explicit preflight version remains bound to every crate manifest", () => {
  assert.equal(
    resolveReleaseVersion({
      derivesVersion: false,
      manifestVersions: ["0.1.0", "0.1.0"],
      requestedVersion: "0.1.0",
    }),
    "0.1.0",
  );
  for (const requestedVersion of [undefined, "v0.1.0", "0.2.0"]) {
    assert.throws(
      () =>
        resolveReleaseVersion({
          derivesVersion: false,
          manifestVersions: ["0.1.0", "0.1.0"],
          requestedVersion,
        }),
      ReleaseSourceError,
    );
  }
});
