#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createCipheriv, createECDH, createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vectorsDir = resolve(root, "vectors");
const vectorSourceDir = (envName, localName) => {
  if (process.env[envName]) {
    return resolve(process.env[envName]);
  }

  return resolve(root, "vectors", localName);
};
const ietfSdJwtDir = vectorSourceDir(
  "REALLYME_IETF_SD_JWT_VECTORS_DIR",
  "ietf-sd-jwt",
);
const rfc9901Dir = vectorSourceDir(
  "REALLYME_SD_JWT_RFC9901_VECTORS_DIR",
  "sd-jwt-rfc9901",
);

const readText = (path) => readFileSync(path, "utf8");
const sanitizeJsonForParsing = (input) => {
  let out = "";
  let inString = false;
  let escaped = false;

  for (const character of input) {
    if (inString) {
      if (escaped) {
        out += character;
        escaped = false;
        continue;
      }
      if (character === "\\") {
        out += character;
        escaped = true;
        continue;
      }
      if (character === '"') {
        out += character;
        inString = false;
        continue;
      }
      if (character === "\n" || character === "\r" || character === "\t") {
        out += " ";
        continue;
      }
      out += character;
      continue;
    }

    out += character;
    if (character === '"') {
      inString = true;
    }
  }

  return out;
};
const readJson = (path) => {
  const text = readText(path);
  try {
    return JSON.parse(text);
  } catch {
    return JSON.parse(sanitizeJsonForParsing(text));
  }
};
const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
const rel = (path) => relative(root, path);
const base64url = (bytes) =>
  Buffer.from(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");

const optionalText = (dir, name) => {
  const path = resolve(dir, name);
  return existsSync(path) ? readText(path).trim() : null;
};

const optionalJson = (dir, name) => {
  const path = resolve(dir, name);
  return existsSync(path) ? readJson(path) : null;
};

const fileDescriptor = (dir, name, mediaType) => {
  const path = resolve(dir, name);
  if (!existsSync(path)) {
    return null;
  }
  const bytes = readFileSync(path);
  return {
    path: rel(path),
    media_type: mediaType,
    sha256: sha256Hex(bytes),
    bytes: bytes.length,
  };
};

const existingVectorSuite = ({ id, source, path }) => {
  const absolutePath = resolve(vectorsDir, path);
  let caseCount = 0;
  if (existsSync(absolutePath)) {
    const suite = readJson(absolutePath);
    if (Array.isArray(suite.cases)) {
      caseCount = suite.cases.length;
    } else if (Array.isArray(suite.profiles) && Array.isArray(suite.formats)) {
      caseCount = suite.profiles.length * suite.formats.length;
    } else if (Array.isArray(suite.profiles)) {
      caseCount = suite.profiles.length;
    } else if (Array.isArray(suite.suites)) {
      caseCount = suite.suites.reduce((total, item) => {
        const valid = Array.isArray(item.valid) ? item.valid.length : 0;
        const invalid = Array.isArray(item.invalid) ? item.invalid.length : 0;
        return total + valid + invalid;
      }, 0);
    }
  }
  return {
    id,
    source,
    path,
    case_count: caseCount,
  };
};

const compactSdJwtCases = () =>
  readdirSync(ietfSdJwtDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const dir = resolve(ietfSdJwtDir, entry.name);
      const files = [
        fileDescriptor(dir, "sd_jwt_issuance.txt", "text/plain"),
        fileDescriptor(dir, "sd_jwt_presentation.txt", "text/plain"),
        fileDescriptor(dir, "sd_jwt_payload.json", "application/json"),
        fileDescriptor(dir, "verified_contents.json", "application/json"),
        fileDescriptor(dir, "user_claims.json", "application/json"),
      ].filter(Boolean);

      return {
        id: `ietf-sd-jwt/${entry.name}`,
        source: "RFC9901",
        format: "sd-jwt-compact",
        files,
        presentation: optionalText(dir, "sd_jwt_presentation.txt"),
        expected_verified_contents: optionalJson(dir, "verified_contents.json"),
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));

const jsonSdJwtCases = () =>
  readdirSync(ietfSdJwtDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .filter((entry) => existsSync(resolve(ietfSdJwtDir, entry.name, "sd_jwt_presentation.json")))
    .map((entry) => {
      const dir = resolve(ietfSdJwtDir, entry.name);
      return {
        id: `ietf-sd-jwt/${entry.name}`,
        source: "RFC9901",
        format: "sd-jwt-json-serialization",
        files: [
          fileDescriptor(dir, "sd_jwt_issuance.json", "application/json"),
          fileDescriptor(dir, "sd_jwt_presentation.json", "application/json"),
          fileDescriptor(dir, "sd_jwt_payload.json", "application/json"),
          fileDescriptor(dir, "verified_contents.json", "application/json"),
        ].filter(Boolean),
        presentation: optionalJson(dir, "sd_jwt_presentation.json"),
        expected_verified_contents: optionalJson(dir, "verified_contents.json"),
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));

const reallymeSdJwtCases = () => {
  const manifestPath = resolve(rfc9901Dir, "manifest.json");
  if (!existsSync(manifestPath)) {
    return [];
  }
  const manifest = readJson(manifestPath);
  return manifest.vectors.map((jsonFile) => {
    const name = jsonFile.replace(/\.json$/u, "");
    const compactFile = `${name}.compact.txt`;
    const jsonPath = resolve(rfc9901Dir, jsonFile);
    const compactPath = resolve(rfc9901Dir, compactFile);
    return {
      id: `reallyme-sd-jwt-rfc9901/${name}`,
      source: "RFC9901",
      format: "sd-jwt-compact",
      files: [
        fileDescriptor(rfc9901Dir, jsonFile, "application/json"),
        fileDescriptor(rfc9901Dir, compactFile, "text/plain"),
      ],
      presentation: readText(compactPath).trim(),
      expected_verified_contents: readJson(jsonPath),
    };
  });
};

const mdocIssuerSignedCases = () => [
  {
    id: "reallyme-mdoc-issuer-signed-digests-001",
    source: "ISO18013-5",
    format: "mdoc-issuer-signed",
    doc_type: "org.iso.18013.5.1.mDL",
    digest_algorithm: "SHA-256",
    validity_info: {
      signed: 1700000000,
      valid_from: 1700000000,
      valid_until: 1800000000,
    },
    elements: [
      {
        namespace: "org.iso.18013.5.1",
        digest_id: 1,
        element_identifier: "family_name",
        random_hex: "01010101010101010101010101010101",
        element_value_cbor_hex: "63444f45",
        issuer_signed_item_bytes_hex:
          "d8185852a4686469676573744944016672616e646f6d500101010101010101010101010101010171656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756563444f45",
        sha256_digest_hex:
          "dd0b85c33b9f18826c49f65f2983adcbc7274e69e82a8f49eb5f7c67aaecfb45",
      },
      {
        namespace: "org.iso.18013.5.1",
        digest_id: 2,
        element_identifier: "given_name",
        random_hex: "02020202020202020202020202020202",
        element_value_cbor_hex: "65414c494345",
        issuer_signed_item_bytes_hex:
          "d8185853a4686469676573744944026672616e646f6d500202020202020202020202020202020271656c656d656e744964656e7469666965726a676976656e5f6e616d656c656c656d656e7456616c756565414c494345",
        sha256_digest_hex:
          "f72eb07cd74c3d1f4f45cd121d56d37cef6e6c311bc56c6b839b00702391dfce",
      },
    ],
    expected_value_digests: {
      "org.iso.18013.5.1": {
        1: "dd0b85c33b9f18826c49f65f2983adcbc7274e69e82a8f49eb5f7c67aaecfb45",
        2: "f72eb07cd74c3d1f4f45cd121d56d37cef6e6c311bc56c6b839b00702391dfce",
      },
    },
  },
];

const compactJweDirCase = ({ id, enc, keyHex, ivHex, protectedHeader, plaintext }) => {
  const key = Buffer.from(keyHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const protectedHeaderJson = JSON.stringify(protectedHeader);
  const protectedB64 = base64url(Buffer.from(protectedHeaderJson, "utf8"));
  const plaintextJson = JSON.stringify(plaintext);
  const cipherName =
    enc === "A128GCM" ? "aes-128-gcm" : enc === "A192GCM" ? "aes-192-gcm" : "aes-256-gcm";
  const cipher = createCipheriv(cipherName, key, iv);
  cipher.setAAD(Buffer.from(protectedB64, "ascii"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintextJson, "utf8")),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const compact = [
    protectedB64,
    "",
    base64url(iv),
    base64url(ciphertext),
    base64url(tag),
  ].join(".");

  return {
    id,
    source: "RFC7516",
    format: "jwe-compact",
    alg: "dir",
    enc,
    cek_hex: keyHex,
    iv_hex: ivHex,
    protected_header: protectedHeader,
    compact,
    plaintext_json_utf8: plaintextJson,
    expected_plaintext_json: plaintext,
  };
};

const uint32be = (value) => {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value, 0);
  return out;
};

const lengthPrefixed = (bytes) => Buffer.concat([uint32be(bytes.length), Buffer.from(bytes)]);

const jwaConcatKdf = ({ sharedSecret, enc, apu, apv }) => {
  const outputLength = enc === "A128GCM" ? 16 : enc === "A192GCM" ? 24 : 32;
  const otherInfo = Buffer.concat([
    lengthPrefixed(Buffer.from(enc, "ascii")),
    lengthPrefixed(apu),
    lengthPrefixed(apv),
    uint32be(outputLength * 8),
  ]);
  const derived = [];
  let counter = 1;
  while (Buffer.concat(derived).length < outputLength) {
    derived.push(
      createHash("sha256")
        .update(uint32be(counter))
        .update(sharedSecret)
        .update(otherInfo)
        .digest(),
    );
    counter += 1;
  }
  return Buffer.concat(derived).subarray(0, outputLength);
};

const ecKeyPairFromPrivate = ({ curveName, privateKeyHex }) => {
  const ecdh = createECDH(curveName);
  ecdh.setPrivateKey(Buffer.from(privateKeyHex, "hex"));
  return {
    ecdh,
    privateKeyHex,
    publicCompressed: ecdh.getPublicKey(null, "compressed"),
    publicUncompressed: ecdh.getPublicKey(null, "uncompressed"),
  };
};

const ecEpkFromUncompressed = ({ crv, coordinateLength, publicKey }) => ({
  crv,
  kty: "EC",
  x: base64url(publicKey.subarray(1, 1 + coordinateLength)),
  y: base64url(publicKey.subarray(1 + coordinateLength, 1 + coordinateLength * 2)),
});

const compactJweEcdhEsCase = ({
  id,
  crv,
  curveName,
  coordinateLength,
  enc,
  recipientPrivateKeyHex,
  ephemeralPrivateKeyHex,
  ivHex,
  kid,
  apu,
  apv,
  plaintext,
}) => {
  const recipient = ecKeyPairFromPrivate({ curveName, privateKeyHex: recipientPrivateKeyHex });
  const ephemeral = ecKeyPairFromPrivate({ curveName, privateKeyHex: ephemeralPrivateKeyHex });
  const apuBytes = Buffer.from(apu, "utf8");
  const apvBytes = Buffer.from(apv, "utf8");
  const protectedHeader = {
    alg: "ECDH-ES",
    enc,
    kid,
    apu: base64url(apuBytes),
    apv: base64url(apvBytes),
    epk: ecEpkFromUncompressed({
      crv,
      coordinateLength,
      publicKey: ephemeral.publicUncompressed,
    }),
  };
  const sharedSecret = ephemeral.ecdh.computeSecret(recipient.publicCompressed);
  const cek = jwaConcatKdf({ sharedSecret, enc, apu: apuBytes, apv: apvBytes });
  const direct = compactJweDirCase({
    id,
    enc,
    keyHex: cek.toString("hex"),
    ivHex,
    protectedHeader,
    plaintext,
  });
  return {
    ...direct,
    alg: "ECDH-ES",
    recipient_private_key_hex: recipientPrivateKeyHex,
    recipient_public_key_sec1_hex: recipient.publicCompressed.toString("hex"),
    ephemeral_private_key_hex: ephemeralPrivateKeyHex,
    ephemeral_public_key_sec1_hex: ephemeral.publicCompressed.toString("hex"),
    derived_cek_hex: cek.toString("hex"),
    cek_hex: undefined,
  };
};

const compactJweCases = () => {
  const a128 = compactJweDirCase({
    id: "reallyme-jwe/dir-a128gcm-direct-post-json",
    enc: "A128GCM",
    keyHex: "07070707070707070707070707070707",
    ivHex: "090909090909090909090909",
    protectedHeader: { alg: "dir", enc: "A128GCM" },
    plaintext: {
      vp_token: "presented",
      state: "abc",
    },
  });
  const a256 = compactJweDirCase({
    id: "reallyme-jwe/dir-a256gcm-json",
    enc: "A256GCM",
    keyHex: "0303030303030303030303030303030303030303030303030303030303030303",
    ivHex: "040404040404040404040404",
    protectedHeader: { alg: "dir", enc: "A256GCM" },
    plaintext: {
      ok: true,
    },
  });
  const a192 = compactJweDirCase({
    id: "reallyme-jwe/dir-a192gcm-json",
    enc: "A192GCM",
    keyHex: "050505050505050505050505050505050505050505050505",
    ivHex: "060606060606060606060606",
    protectedHeader: { alg: "dir", enc: "A192GCM" },
    plaintext: {
      middle: true,
    },
  });
  const tamperedTag = {
    ...a128,
    id: "reallyme-jwe/dir-a128gcm-tampered-tag",
    compact: `${a128.compact.split(".").slice(0, 4).join(".")}.AAAAAAAAAAAAAAAAAAAAAA`,
    expected_error: "Decrypt",
    expected_plaintext_json: undefined,
  };
  const ecdhEs = compactJweEcdhEsCase({
    id: "reallyme-jwe/ecdh-es-p256-a128gcm-json",
    crv: "P-256",
    curveName: "prime256v1",
    coordinateLength: 32,
    enc: "A128GCM",
    recipientPrivateKeyHex: "0000000000000000000000000000000000000000000000000000000000000005",
    ephemeralPrivateKeyHex: "0000000000000000000000000000000000000000000000000000000000000009",
    ivHex: "050505050505050505050505",
    kid: "recipient-key-1",
    apu: "wallet",
    apv: "issuer",
    plaintext: {
      vp_token: "presented",
      state: "abc",
    },
  });
  const ecdhEsP384 = compactJweEcdhEsCase({
    id: "reallyme-jwe/ecdh-es-p384-a192gcm-json",
    crv: "P-384",
    curveName: "secp384r1",
    coordinateLength: 48,
    enc: "A192GCM",
    recipientPrivateKeyHex:
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007",
    ephemeralPrivateKeyHex:
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d",
    ivHex: "060606060606060606060606",
    kid: "recipient-key-p384",
    apu: "wallet",
    apv: "issuer",
    plaintext: {
      vp_token: "presented",
      state: "abc",
    },
  });
  const ecdhEsP521 = compactJweEcdhEsCase({
    id: "reallyme-jwe/ecdh-es-p521-a256gcm-json",
    crv: "P-521",
    curveName: "secp521r1",
    coordinateLength: 66,
    enc: "A256GCM",
    recipientPrivateKeyHex:
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b",
    ephemeralPrivateKeyHex:
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011",
    ivHex: "080808080808080808080808",
    kid: "recipient-key-p521",
    apu: "wallet",
    apv: "issuer",
    plaintext: {
      vp_token: "presented",
      state: "abc",
    },
  });
  return [a128, a192, a256, tamperedTag, ecdhEs, ecdhEsP384, ecdhEsP521];
};

const jwkThumbprint = (jwk) => {
  const required = {
    EC: ["crv", "kty", "x", "y"],
    OKP: ["crv", "kty", "x"],
    RSA: ["e", "kty", "n"],
    oct: ["k", "kty"],
  }[jwk.kty];
  const canonical = `{${required
    .map((member) => `${JSON.stringify(member)}:${JSON.stringify(jwk[member])}`)
    .join(",")}}`;
  return base64url(createHash("sha256").update(Buffer.from(canonical, "utf8")).digest());
};

const jwkThumbprintCases = () => {
  const ec = {
    kty: "EC",
    crv: "P-256",
    x: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    y: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
    kid: "ignored-by-rfc7638",
    alg: "ES256",
  };
  const okp = {
    kty: "OKP",
    crv: "Ed25519",
    x: "GawgguFyGrWKav7AX4VKUg",
    use: "sig",
  };
  const rsa = {
    kty: "RSA",
    e: "AQAB",
    n: "sXchDaQebHnPiGdKQ8F0Q1wG7oA0mEHVh8pX9sk1hH4",
    kid: "ignored-rsa-key-id",
  };
  const missingEcY = {
    kty: "EC",
    crv: "P-256",
    x: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  };

  return [
    {
      id: "reallyme-jwk-thumbprint/ec-p256-extra-members",
      source: "RFC7638",
      format: "jwk-thumbprint",
      jwk: ec,
      expected_thumbprint: jwkThumbprint(ec),
    },
    {
      id: "reallyme-jwk-thumbprint/okp-ed25519",
      source: "RFC7638",
      format: "jwk-thumbprint",
      jwk: okp,
      expected_thumbprint: jwkThumbprint(okp),
    },
    {
      id: "reallyme-jwk-thumbprint/rsa",
      source: "RFC7638",
      format: "jwk-thumbprint",
      jwk: rsa,
      expected_thumbprint: jwkThumbprint(rsa),
    },
    {
      id: "reallyme-jwk-thumbprint/ec-missing-y",
      source: "RFC7638",
      format: "jwk-thumbprint",
      jwk: missingEcY,
      expected_error: "InvalidDpopProof",
    },
  ];
};

const writeJson = (relativePath, value) => {
  const path = resolve(vectorsDir, relativePath);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

mkdirSync(vectorsDir, { recursive: true });

const suites = [
  {
    id: "jwe-compact",
    source: "RFC7516",
    path: "jwe-compact.json",
    case_count: compactJweCases().length,
  },
  {
    id: "jwk-thumbprint",
    source: "RFC7638",
    path: "jwk-thumbprint.json",
    case_count: jwkThumbprintCases().length,
  },
  {
    id: "sd-jwt-compact",
    source: "RFC9901",
    path: "sd-jwt-compact.json",
    case_count: compactSdJwtCases().length + reallymeSdJwtCases().length,
  },
  {
    id: "sd-jwt-json-serialization",
    source: "RFC9901",
    path: "sd-jwt-json-serialization.json",
    case_count: jsonSdJwtCases().length,
  },
  {
    id: "mdoc-issuer-signed",
    source: "ISO18013-5",
    path: "mdoc-issuer-signed.json",
    case_count: mdocIssuerSignedCases().length,
  },
  existingVectorSuite({
    id: "status-list",
    source: "W3C-VC-DM-2.0 credential status and ReallyMe status-list model",
    path: "status-list.json",
  }),
  existingVectorSuite({
    id: "x509-trust-policy",
    source: "RFC5280 projected certificate policy and EUDI trusted-list service policy",
    path: "x509-trust-policy.json",
  }),
  {
    id: "resource-limits",
    source: "CONTRACT",
    path: "resource-limits.json",
    case_count: 1,
  },
  existingVectorSuite({
    id: "did-methods",
    source: "DID method specifications and upstream resolver examples",
    path: "did-methods.json",
  }),
  existingVectorSuite({
    id: "claims-normalization",
    source: "ReallyMe claim normalization model",
    path: "claims/normalization.json",
  }),
  existingVectorSuite({
    id: "claims-predefined-credentials",
    source: "EU-2024-2977, ISO18013-5, ICAO9303, ELM-3, EU-2003-751",
    path: "claims/predefined-credentials.json",
  }),
  existingVectorSuite({
    id: "claims-catalog-sources",
    source:
      "EU-2024-2977, EU-2024-1183, EU-2025-1569, ISO18013-5, ICAO9303, ELM-3, EU-2003-751, EUDI-ARF, ReallyMe claim normalization model",
    path: "claims/catalog-sources.json",
  }),
  existingVectorSuite({
    id: "credential-canonical",
    source: "ReallyMe credential canonical envelope model",
    path: "credential/canonical.json",
  }),
];

writeJson("sd-jwt-compact.json", {
  schema: "reallyme.identity.conformance.vectors.v1",
  suite: "sd-jwt-compact",
  cases: [...compactSdJwtCases(), ...reallymeSdJwtCases()],
});

writeJson("jwe-compact.json", {
  schema: "reallyme.identity.conformance.vectors.v1",
  suite: "jwe-compact",
  cases: compactJweCases(),
});

writeJson("jwk-thumbprint.json", {
  schema: "reallyme.identity.conformance.vectors.v1",
  suite: "jwk-thumbprint",
  cases: jwkThumbprintCases(),
});

writeJson("sd-jwt-json-serialization.json", {
  schema: "reallyme.identity.conformance.vectors.v1",
  suite: "sd-jwt-json-serialization",
  cases: jsonSdJwtCases(),
});

writeJson("mdoc-issuer-signed.json", {
  schema: "reallyme.identity.conformance.vectors.v1",
  suite: "mdoc-issuer-signed",
  cases: mdocIssuerSignedCases(),
});

writeJson("resource-limits.json", {
  schema: "reallyme.identity.conformance.vectors.v1",
  suite: "resource-limits",
  cases: [
    {
      id: "identity-resource-limits-v1",
      source: "CONTRACT",
      format: "json",
      expected_limits: {
        compact_jwe_bytes: 65536,
        compact_jws_bytes: 65536,
        sd_jwt_disclosures: 256,
        sd_jwt_disclosure_bytes: 4096,
        mdoc_device_response_documents: 8,
        mdoc_cbor_depth: 64,
        mdoc_cbor_map_entries: 512,
        mdoc_cbor_array_items: 512,
        x509_chain_certificates: 10,
        qeaa_cert_chain_total_der_bytes: 262144,
        status_list_entries: 1000000,
      },
    },
  ],
});

writeJson("manifest.json", {
  schema: "reallyme.identity.conformance.vector_manifest.v1",
  generated_by: "scripts/generate_conformance_vectors.mjs",
  suites,
});

console.log(`generated ${suites.length} conformance vector suites`);
