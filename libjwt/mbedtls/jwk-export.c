/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* MbedTLS implementation of the key2jwk_params op: parse a native key (PEM or
 * DER) and extract its raw components into the neutral jwk_export_t. Uses only
 * the public, version-stable APIs (mbedtls_pk_* to parse, PSA to export the raw
 * material), mirroring the backend's PSA-only design — the classic low-level
 * accessors (mbedtls_rsa_ and mbedtls_ecp_ families) are private in MbedTLS 4.x.
 *
 * EC keys export as a raw point (split into x/y) and a raw scalar. RSA keys
 * export as PKCS#1 DER, parsed here into their integer components. EdDSA (OKP)
 * is not representable by mbedtls_pk, so such keys do not parse (the common
 * code then reports the input as not a key) — MbedTLS has no EdDSA anyway. */

#include <stdlib.h>
#include <string.h>

#include <mbedtls/build_info.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-mbedtls.h"

#if MBEDTLS_VERSION_MAJOR < 4
/* RNG for mbedtls_pk_parse_key (RSA key validation), backed by PSA. MbedTLS 4.x
 * dropped the RNG parameter from mbedtls_pk_parse_key, so this is only needed
 * on 3.x. */
static int psa_rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;

	return psa_generate_random(out, len) == PSA_SUCCESS ? 0 : -1;
}
#endif

/* Copy @len bytes into a fresh jwt_malloc buffer and add as JWK member @name. */
static void add_raw(jwk_export_t *out, const char *name,
		    const unsigned char *src, size_t len)
{
	unsigned char *buf;

	if (src == NULL || len == 0)
		return; // LCOV_EXCL_LINE

	buf = jwt_malloc(len);
	if (buf == NULL)
		return; // LCOV_EXCL_LINE

	memcpy(buf, src, len);
	jwk_export_add(out, name, buf, len);
}

/* Read a DER length at *p (< end), advancing *p. Returns 0 and sets *len. */
static int der_len(const unsigned char **p, const unsigned char *end,
		   size_t *len)
{
	unsigned int n;

	if (*p >= end)
		return 1; // LCOV_EXCL_LINE

	if (!(**p & 0x80)) {
		*len = *(*p)++;
		return 0;
	}

	n = *(*p)++ & 0x7f;
	if (n < 1 || n > 4 || *p + n > end)
		return 1; // LCOV_EXCL_LINE

	*len = 0;
	while (n--)
		*len = (*len << 8) | *(*p)++;

	return 0;
}

/* Read one DER INTEGER at *p, returning its content (leading zeros stripped)
 * via @val/@vlen and advancing *p past the full element. */
static int der_int(const unsigned char **p, const unsigned char *end,
		   const unsigned char **val, size_t *vlen)
{
	const unsigned char *content;
	size_t len;

	if (*p >= end || *(*p)++ != 0x02)	/* INTEGER */
		return 1; // LCOV_EXCL_LINE
	if (der_len(p, end, &len) || *p + len > end)
		return 1; // LCOV_EXCL_LINE

	content = *p;
	*p += len;

	while (len > 1 && content[0] == 0x00) {
		content++;
		len--;
	}

	*val = content;
	*vlen = len;

	return 0;
}

/* Enter a DER SEQUENCE at *p, advancing *p to its content and setting *inner
 * to the end of that content. */
static int der_enter_seq(const unsigned char **p, const unsigned char *end,
			 const unsigned char **inner)
{
	size_t len;

	if (*p >= end || *(*p)++ != 0x30)	/* SEQUENCE */
		return 1; // LCOV_EXCL_LINE
	if (der_len(p, end, &len) || *p + len > end)
		return 1; // LCOV_EXCL_LINE

	*inner = *p + len;

	return 0;
}

/* Parse a PKCS#1 RSAPublicKey (SEQ { n, e }) or RSAPrivateKey
 * (SEQ { ver, n, e, d, p, q, dp, dq, qi }) DER blob into the JWK components. */
static int parse_rsa_der(const unsigned char *der, size_t der_len_in,
			 int is_priv, jwk_export_t *out)
{
	const unsigned char *p = der, *end = der + der_len_in, *seq_end;
	const unsigned char *v;
	size_t vlen;

	if (der_enter_seq(&p, end, &seq_end))
		return 1; // LCOV_EXCL_LINE
	end = seq_end;

	if (is_priv) {
		/* version INTEGER (0) */
		if (der_int(&p, end, &v, &vlen))
			return 1; // LCOV_EXCL_LINE
	}

	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "n", v, vlen);
	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "e", v, vlen);

	if (!is_priv)
		return 0;

	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "d", v, vlen);
	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "p", v, vlen);
	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "q", v, vlen);
	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "dp", v, vlen);
	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "dq", v, vlen);
	if (der_int(&p, end, &v, &vlen))
		return 1; // LCOV_EXCL_LINE
	add_raw(out, "qi", v, vlen);

	return 0;
}

/* Map a PSA ECC family + bit size to the JWK crv/alg. Returns 0 on success. */
static int ec_curve_info(psa_ecc_family_t fam, size_t bits, char *crv,
			 char *alg)
{
	if (fam == PSA_ECC_FAMILY_SECP_R1) {
		switch (bits) {
		case 256:
			strcpy(crv, "P-256");
			strcpy(alg, "ES256");
			return 0;
		case 384:
			strcpy(crv, "P-384");
			strcpy(alg, "ES384");
			return 0;
		case 521:
			strcpy(crv, "P-521");
			strcpy(alg, "ES512");
			return 0;
		}
	} else if (fam == PSA_ECC_FAMILY_SECP_K1 && bits == 256) {
		strcpy(crv, "secp256k1");
		strcpy(alg, "ES256K");
		return 0;
	}

	return 1; // LCOV_EXCL_LINE
}

/* Import the parsed pk into PSA (with export usage) and emit the JWK components
 * for an RSA or EC key. */
static int export_via_psa(mbedtls_pk_context *pk, int is_priv,
			  jwk_export_t *out)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	unsigned char buf[8192];
	psa_key_type_t type;
	size_t blen = 0, bits, field;
	int ret = 1;

	if (mbedtls_pk_get_psa_attributes(pk,
		is_priv ? PSA_KEY_USAGE_SIGN_MESSAGE
			: PSA_KEY_USAGE_VERIFY_MESSAGE, &attr))
		return 1; // LCOV_EXCL_LINE

	psa_set_key_usage_flags(&attr,
		psa_get_key_usage_flags(&attr) | PSA_KEY_USAGE_EXPORT);

	if (mbedtls_pk_import_into_psa(pk, &attr, &kid))
		return 1; // LCOV_EXCL_LINE

	type = psa_get_key_type(&attr);
	bits = psa_get_key_bits(&attr);

	if (out->kty == JWK_KEY_TYPE_RSA) {
		/* PSA exports RSA as PKCS#1 DER (public or private). */
		if (is_priv) {
			if (psa_export_key(kid, buf, sizeof(buf), &blen))
				goto out; // LCOV_EXCL_LINE
		} else {
			if (psa_export_public_key(kid, buf, sizeof(buf), &blen))
				goto out; // LCOV_EXCL_LINE
		}
		ret = parse_rsa_der(buf, blen, is_priv, out);
		goto out;
	}

	/* EC: the public key exports as 0x04 || X || Y; the private key as the
	 * raw scalar. */
	if (ec_curve_info(PSA_KEY_TYPE_ECC_GET_FAMILY(type), bits, out->crv,
			  out->alg))
		goto out; // LCOV_EXCL_LINE

	field = (bits + 7) / 8;

	if (psa_export_public_key(kid, buf, sizeof(buf), &blen))
		goto out; // LCOV_EXCL_LINE
	if (blen != 1 + 2 * field || buf[0] != 0x04)
		goto out; // LCOV_EXCL_LINE

	add_raw(out, "x", buf + 1, field);
	add_raw(out, "y", buf + 1 + field, field);

	if (is_priv) {
		if (psa_export_key(kid, buf, sizeof(buf), &blen))
			goto out; // LCOV_EXCL_LINE
		add_raw(out, "d", buf, blen);
	}

	ret = 0;

out:
	psa_destroy_key(kid);
	mbedtls_platform_zeroize(buf, sizeof(buf));

	return ret;
}

JWT_NO_EXPORT
int mbedtls_key2jwk_params(const char *key, size_t len, jwk_export_t *out)
{
	mbedtls_pk_context pk;
	unsigned char *copy;
	psa_key_type_t kt;
	int is_priv = 0, ret = 1;
	size_t parse_len;

	if (psa_crypto_init() != PSA_SUCCESS)
		return 1; // LCOV_EXCL_LINE

	/* mbedtls_pk_parse_key wants a NUL-terminated buffer for PEM, with the
	 * NUL counted in the length. Make a terminated copy and only count the
	 * NUL when the input looks like PEM. */
	copy = jwt_malloc(len + 1);
	if (copy == NULL)
		return 1; // LCOV_EXCL_LINE
	memcpy(copy, key, len);
	copy[len] = '\0';

	parse_len = (memmem(copy, len, "-----BEGIN", 10) != NULL) ? len + 1 : len;

	mbedtls_pk_init(&pk);

#if MBEDTLS_VERSION_MAJOR < 4
	if (mbedtls_pk_parse_key(&pk, copy, parse_len, NULL, 0, psa_rng,
				 NULL) == 0)
#else
	if (mbedtls_pk_parse_key(&pk, copy, parse_len, NULL, 0) == 0)
#endif
	{
		is_priv = 1;
	} else if (mbedtls_pk_parse_public_key(&pk, copy, parse_len) != 0) {
		/* Not a parseable key; the common code may try the HMAC fallback.
		 * (EdDSA/OKP keys land here: mbedtls_pk has no OKP representation.) */
		goto out;
	}

	out->is_private = is_priv;

	/* mbedtls_pk has no RSA-PSS vs RSA distinction at the key-type level (the
	 * padding is a sign-time choice), so an RSA-PSS key exports as a plain RSA
	 * JWK with no "alg" hint. */
	kt = mbedtls_pk_get_key_type(&pk);
	if (PSA_KEY_TYPE_IS_RSA(kt)) {
		out->kty = JWK_KEY_TYPE_RSA;
		ret = export_via_psa(&pk, is_priv, out);
	} else if (PSA_KEY_TYPE_IS_ECC(kt)) {
		out->kty = JWK_KEY_TYPE_EC;
		ret = export_via_psa(&pk, is_priv, out);
	} else {
		ret = 1; // LCOV_EXCL_LINE
	}

out:
	mbedtls_pk_free(&pk);
	jwt_scrub_and_free(copy, len + 1);

	return ret;
}
