#ifndef IDENTITY_OCSP_ABI_H
#define IDENTITY_OCSP_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
// =======================
// Status codes
// =======================

typedef int32_t ocsp_status_t;

#define OCSP_OK                     0
#define OCSP_INVALID_INPUT         -1
#define OCSP_VERIFY_FAILED         -2
#define OCSP_BUFFER_TOO_SMALL      -3
#define OCSP_INTERNAL_ERROR      -128

// =======================
// OCSP parse + verify (platform backends)
// =======================
//
// Implementations are expected to:
// - parse `ocsp_der` as RFC 6960 OCSPResponse DER
// - verify signature + responder authorization against issuer/extra certs
// - enforce responder certificate EKU = OCSPSigning
// - return JSON encoding of `identity-revocation-ocsp-core::ParsedOcspResponse`
//
// Extra certs are provided as a JSON array of base64url DER certificates.
//
// Two-pass output:
// - If `out_buf` is NULL or `out_buf_len` is too small, return OCSP_BUFFER_TOO_SMALL
//   and set `out_len` to the required number of bytes.
// - On success, return OCSP_OK and set `out_len` to the number of bytes written.
//
ocsp_status_t ocsp_parse_response_der_json(
    const uint8_t* ocsp_der,
    size_t ocsp_der_len,
    const uint8_t* cert_der,
    size_t cert_der_len,
    const uint8_t* issuer_der,
    size_t issuer_der_len,
    const uint8_t* extra_certs_json,
    size_t extra_certs_json_len,
    uint64_t now_unix,
    uint8_t* out_buf,
    size_t out_buf_len,
    size_t* out_len
);

#ifdef __cplusplus
}
#endif

#endif
