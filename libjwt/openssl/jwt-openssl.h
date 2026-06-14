/* Copyright (C) 2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_OPENSSL_H
#define JWT_OPENSSL_H

int openssl_process_eddsa(jwt_json_t *jwk, jwk_item_t *item);
int openssl_process_rsa(jwt_json_t *jwk, jwk_item_t *item);
int openssl_process_ec(jwt_json_t *jwk, jwk_item_t *item);
void openssl_process_item_free(jwk_item_t *item);

/* JWE (RFC 7516/7518) */
int openssl_rng(unsigned char *out, size_t len);
int openssl_encrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len);
int openssl_decrypt_aes_gcm(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len);
int openssl_encrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len,
	unsigned char **tag, size_t *tag_len);
int openssl_decrypt_aes_cbc_hmac(jwe_enc_t enc, const unsigned char *cek,
	size_t cek_len, const unsigned char *iv, size_t iv_len,
	const unsigned char *aad, size_t aad_len,
	const unsigned char *ct, size_t ct_len,
	const unsigned char *tag, size_t tag_len,
	unsigned char **pt, size_t *pt_len);
int openssl_wrap_aes_kw(const jwk_item_t *key, const unsigned char *cek,
	size_t cek_len, unsigned char **out, size_t *out_len);
int openssl_unwrap_aes_kw(const jwk_item_t *key, const unsigned char *in,
	size_t in_len, unsigned char **cek, size_t *cek_len);
int openssl_wrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
	const unsigned char *cek, size_t cek_len,
	unsigned char **out, size_t *out_len);
int openssl_unwrap_aes_kw_raw(const unsigned char *kek, size_t kek_len,
	const unsigned char *in, size_t in_len,
	unsigned char **cek, size_t *cek_len);
int openssl_encrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
	const unsigned char *cek, size_t cek_len,
	unsigned char **out, size_t *out_len);
int openssl_encrypt_cek_rsa_pem(jwe_key_alg_t alg, const char *pem,
	const unsigned char *cek, size_t cek_len,
	unsigned char **out, size_t *out_len);
int openssl_decrypt_cek_rsa(jwe_key_alg_t alg, const jwk_item_t *key,
	const unsigned char *in, size_t in_len,
	unsigned char **cek, size_t *cek_len);
int openssl_decrypt_cek_rsa_pem(jwe_key_alg_t alg, const char *pem,
	const unsigned char *in, size_t in_len,
	unsigned char **cek, size_t *cek_len);
int openssl_ecdh_derive(jwe_key_alg_t alg, jwe_enc_t enc,
	const jwk_item_t *key, int for_encrypt, jwt_json_t *hdr,
	unsigned char **dk, size_t *dk_len);

#endif /* JWT_OPENSSL_H */
