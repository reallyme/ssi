#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const protoRoot = join(root, "crates/proto/proto");
const COVERAGE_SOURCE_BY_PROTO = new Map([
  ["identity/audit/v1/audit.proto", ["crates/proto/src/zeroize_credential.rs"]],
  ["identity/credential/v1/credential.proto", ["crates/proto/src/zeroize_credential.rs"]],
  ["identity/credential/v1/subject_bundle.proto", ["crates/proto/src/zeroize_credential.rs"]],
  ["identity/eudi/v1/catalogue.proto", ["crates/proto/src/zeroize_eudi_pid.rs"]],
  ["identity/eudi/v1/pid.proto", ["crates/proto/src/zeroize_eudi_pid.rs"]],
  [
    "identity/presentation/v1/presentation.proto",
    ["crates/proto-codec/src/presentation/own_presentation_proto.rs"],
  ],
  ["identity/status/v1/status_list.proto", ["crates/proto/src/zeroize_status.rs"]],
]);

const ONEOF_VARIANT_FIELDS = new Set([
  "cryptographic_key",
  "claims_based",
  "cose_key",
  "certificate_sha256",
  "did",
  "did_verification_method",
  "jwk_json",
  "federation_entity_id",
  "hardware_attestation",
  "issuer_and_serial",
  "key_attestation",
  "mdoc",
  "mdoc_jpeg",
  "multikey",
  "opaque_identifier",
  "public_key",
  "range",
  "raw",
  "revealed_value",
  "sd_jwt",
  "sd_jwt_jpeg_data_url",
  "sd_jwt_vc",
  "set",
  "subject_public_key_info_der",
  "threshold",
  "uri",
  "validated_certificate_der",
  "x509_certificate_der",
  "x509_chain",
  "x509_subject",
  "zk",
]);

function walk(directory) {
  const paths = [];
  for (const entry of readdirSync(directory).sort()) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      paths.push(...walk(path));
    } else if (path.endsWith(".proto")) {
      paths.push(path);
    }
  }
  return paths;
}

function pascalCase(field) {
  return field
    .split("_")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join("");
}

function annotatedFields(source) {
  const fields = [];
  for (const line of source.split(/\r?\n/u)) {
    if (!line.includes("debug_redact = true")) {
      continue;
    }
    const match = /^\s*(?:optional\s+|repeated\s+)?(?:map<[^>]+>|[.A-Za-z0-9_]+)\s+([a-z][a-z0-9_]*)\s*=\s*[0-9]+\s*\[/u.exec(
      line,
    );
    if (match?.[1] === undefined) {
      throw new Error(`unable to parse debug_redact field: ${line.trim()}`);
    }
    fields.push(match[1]);
  }
  return fields;
}

function fieldHasCleanup(field, cleanupSource) {
  if (cleanupSource.includes(`.${field}`)) {
    return true;
  }
  return (
    ONEOF_VARIANT_FIELDS.has(field) &&
    cleanupSource.includes(`::${pascalCase(field)}`)
  );
}

for (const protoPath of walk(protoRoot)) {
  const protoSource = readFileSync(protoPath, "utf8");
  const fields = annotatedFields(protoSource);
  if (fields.length === 0) {
    continue;
  }
  const relativeProto = relative(protoRoot, protoPath).replaceAll("\\", "/");
  const cleanupPaths = COVERAGE_SOURCE_BY_PROTO.get(relativeProto);
  if (cleanupPaths === undefined) {
    throw new Error(`${relativeProto} has redacted fields but no cleanup owner`);
  }
  const cleanupSource = cleanupPaths
    .map((path) => readFileSync(join(root, path), "utf8"))
    .join("\n");
  for (const field of fields) {
    if (!fieldHasCleanup(field, cleanupSource)) {
      throw new Error(`${relativeProto}:${field} has no structural cleanup coverage`);
    }
  }
}

console.log("every debug_redact protobuf field has a registered cleanup owner");
