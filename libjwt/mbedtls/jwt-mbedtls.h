/* Copyright (C) 2025-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_MBEDTLS_H
#define JWT_MBEDTLS_H

#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>

/* A parsed JWK held as a native MbedTLS key object. This is what a MbedTLS
 * jwk_item_t.provider_data points to. MbedTLS 3.x has no single "any key"
 * container that covers every type we need (it lacks EdDSA entirely), so we
 * carry a small tagged union of the native objects.
 *
 * - RSA / RSA-PSS: mbedtls_rsa_context (JWK alg "PS*" is still an RSA key here;
 *   the PSS padding is applied at sign/verify time, avoiding the id-RSASSA-PSS
 *   PEM that mbedtls_pk_parse_key rejects).
 * - EC (P-256/384/521) and OKP X-curves (X25519/X448): mbedtls_ecp_keypair.
 * - OKP Ed-curves (Ed25519/Ed448): MbedTLS has no EdDSA support, so we only
 *   retain the raw key material and curve name. The key parses cleanly (so a
 *   keyring containing one still loads), but any sign/verify/JWE operation on
 *   it fails with a clear "not supported" error. */
typedef struct {
	jwk_key_type_t kty;	/* EC, RSA, or OKP				*/
	int is_private;		/* 1 if private components are present		*/
	int okp_is_ed;		/* For OKP: 1 = Ed-curve (raw), 0 = X-curve (ec) */
	union {
		mbedtls_rsa_context rsa;
		mbedtls_ecp_keypair ec;	/* EC and OKP X-curves			*/
		struct {		/* OKP Ed-curves (unsupported by mbedtls) */
			unsigned char *pub;
			size_t pub_len;
			unsigned char *priv;
			size_t priv_len;
		} okp_ed;
	};
} mbedtls_jwk_t;

JWT_NO_EXPORT
int mbedtls_process_eddsa(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
int mbedtls_process_rsa(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
int mbedtls_process_ec(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
void mbedtls_process_item_free(jwk_item_t *item);

/* Native-key -> JWK conversion is always done by OpenSSL, regardless of the
 * active backend (OpenSSL is always linked). Backend internal; keep out of ABI. */
JWT_NO_EXPORT
int openssl_key2jwk(const char *key, size_t len, unsigned int flags,
	jwt_json_t *out_array);

/* JWE (RFC 7516/7518) — native MbedTLS implementations. */
JWT_NO_EXPORT
int mbedtls_rng(unsigned char *out, size_t len);
JWT_NO_EXPORT
int mbedtls_encrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len);
JWT_NO_EXPORT
int mbedtls_decrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len);
JWT_NO_EXPORT
int mbedtls_encrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len);
JWT_NO_EXPORT
int mbedtls_decrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len);
JWT_NO_EXPORT
int mbedtls_wrap_aes_kw(const jwk_item_t *key, const unsigned char *cek,
	size_t cek_len, unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int mbedtls_unwrap_aes_kw(const jwk_item_t *key, const unsigned char *in,
	size_t in_len, unsigned char **cek, size_t *cek_len);
JWT_NO_EXPORT
int mbedtls_wrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
	const unsigned char *cek, size_t cek_len,
	unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int mbedtls_unwrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
	const unsigned char *in, size_t in_len,
	unsigned char **cek, size_t *cek_len);
JWT_NO_EXPORT
int mbedtls_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
	const unsigned char *cek, size_t cek_len,
	unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int mbedtls_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
	const unsigned char *in, size_t in_len,
	unsigned char **cek, size_t *cek_len);
JWT_NO_EXPORT
int mbedtls_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc,
	const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
	unsigned char **dk, size_t *dk_len);

#endif /* JWT_MBEDTLS_H */
