/* Copyright (C) 2025-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_GNUTLS_H
#define JWT_GNUTLS_H

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

/* A parsed JWK held as native GnuTLS key handles. This is what a GnuTLS
 * jwk_item_t.provider_data points to. The pubkey is always present; the privkey
 * only for private keys. The JWE RSA-OAEP and ECDH-ES ops use these directly;
 * JWS sign/verify continue to use item->pem. */
typedef struct {
	jwk_key_type_t kty;
	gnutls_pubkey_t pub;
	gnutls_privkey_t priv;	/* NULL for public-only keys */
} gnutls_jwk_t;

/* JWK parsing: build native GnuTLS key handles into provider_data. */
JWT_NO_EXPORT
int gnutls_process_eddsa(jwt_json_t *jwk, jwk_item_t *item);
#if defined(LIBJWT_HAVE_ML_DSA) && GNUTLS_VERSION_NUMBER >= 0x03080a
JWT_NO_EXPORT
int gnutls_process_mldsa(jwt_json_t *jwk, jwk_item_t *item);
#endif
JWT_NO_EXPORT
int gnutls_process_rsa(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
int gnutls_process_ec(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
void gnutls_process_item_free(jwk_item_t *item);

/* Native-key -> JWK conversion (the key2jwk_params op); see jwk-export.c. */
JWT_NO_EXPORT
int gnutls_key2jwk_params(const char *key, size_t len, jwk_export_t *out);

/* JWE (RFC 7516/7518) — native GnuTLS implementations. Backend internals
 * reached only through the jwt_crypto_ops table; keep out of ABI. */
JWT_NO_EXPORT
int gnutls_rng(unsigned char *out, size_t len);
JWT_NO_EXPORT
int gnutls_encrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len);
JWT_NO_EXPORT
int gnutls_decrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len);
JWT_NO_EXPORT
int gnutls_encrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len);
JWT_NO_EXPORT
int gnutls_decrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len);
JWT_NO_EXPORT
int gnutls_wrap_aes_kw(const jwk_item_t *key, const unsigned char *cek,
	size_t cek_len, unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int gnutls_unwrap_aes_kw(const jwk_item_t *key, const unsigned char *in,
	size_t in_len, unsigned char **cek, size_t *cek_len);
JWT_NO_EXPORT
int gnutls_wrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
	const unsigned char *cek, size_t cek_len,
	unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int gnutls_unwrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
	const unsigned char *in, size_t in_len,
	unsigned char **cek, size_t *cek_len);

JWT_NO_EXPORT
int gnutls_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
	const unsigned char *cek, size_t cek_len,
	unsigned char **out, size_t *out_len);
JWT_NO_EXPORT
int gnutls_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
	const unsigned char *in, size_t in_len,
	unsigned char **cek, size_t *cek_len);
JWT_NO_EXPORT
int gnutls_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc,
	const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
	unsigned char **dk, size_t *dk_len);

#endif /* JWT_GNUTLS_H */
