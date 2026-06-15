/* Copyright (C) 2025-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_MBEDTLS_H
#define JWT_MBEDTLS_H

#include <psa/crypto.h>

/* A parsed JWK held as PSA-importable key material. This is what a MbedTLS
 * jwk_item_t.provider_data points to.
 *
 * MbedTLS 4.x (TF-PSA-Crypto) split the crypto core out, made the classic
 * low-level API (mbedtls_rsa_*, mbedtls_ecp_*, ...) private, and removed the
 * mbedtls_ecdh_* primitives entirely. The public, version-stable crypto API is
 * now PSA Crypto (psa/crypto.h), which is also present in MbedTLS 3.6 LTS. So
 * instead of holding a native key object, we keep the raw importable material
 * and, for each operation, import a short-lived (volatile) PSA key with exactly
 * the policy that operation needs, then destroy it. This keeps one code path
 * for both 3.6 and 4.x and sidesteps PSA's single-policy-per-key model (an RSA
 * JWK may be used for PS*, RS*, or RSA-OAEP).
 *
 * Material by key type (all heap-allocated; private material scrubbed on free):
 *  - RSA:    pub  = DER PKCS#1 RSAPublicKey;  priv = DER PKCS#1 RSAPrivateKey.
 *  - EC:     pub  = uncompressed point 0x04||X||Y (big-endian, field-padded);
 *            priv = raw scalar, big-endian, left-padded to the field length.
 *  - OKP X-curve (X25519/X448): pub = raw little-endian u-coordinate;
 *            priv = raw little-endian scalar. Used for ECDH-ES only.
 *  - OKP Ed-curve (Ed25519/Ed448): neither MbedTLS nor PSA here implement EdDSA;
 *            we retain the raw pub/priv only so a keyring still loads, but any
 *            sign/verify/JWE on such a key fails with a clear "not supported". */
typedef struct {
	jwk_key_type_t kty;	/* EC, RSA, or OKP				*/
	int is_private;		/* 1 if private material is present		*/
	int okp_is_ed;		/* For OKP: 1 = Ed-curve (raw), 0 = X-curve	*/
	psa_ecc_family_t ecc_family;	/* EC/OKP-X: the PSA curve family	*/
	size_t bits;		/* key size in bits (mirrors item->bits)	*/

	unsigned char *pub;	/* public material (see above)			*/
	size_t pub_len;
	unsigned char *priv;	/* private material (NULL for a public key)	*/
	size_t priv_len;
} mbedtls_jwk_t;

/* Import a short-lived (volatile) PSA key from the stored JWK material with the
 * given algorithm/usage policy. @want_private selects the key-pair (private) vs
 * the public key. On success *kid holds a key the caller must release with
 * psa_destroy_key(). Returns 0 on success, non-zero on failure. */
JWT_NO_EXPORT
int mbedtls_jwk_to_psa(const mbedtls_jwk_t *key, int want_private,
	psa_algorithm_t alg, psa_key_usage_t usage, mbedtls_svc_key_id_t *kid);

JWT_NO_EXPORT
int mbedtls_process_eddsa(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
int mbedtls_process_rsa(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
int mbedtls_process_ec(jwt_json_t *jwk, jwk_item_t *item);
JWT_NO_EXPORT
void mbedtls_process_item_free(jwk_item_t *item);

/* Native-key -> JWK conversion (the key2jwk_params op), done natively by
 * MbedTLS via mbedtls_pk + PSA. Backend internal; keep out of ABI. */
JWT_NO_EXPORT
int mbedtls_key2jwk_params(const char *key, size_t len, jwk_export_t *out);

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
