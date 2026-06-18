/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <mbedtls/asn1write.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-mbedtls.h"

/* Allocate and zero a native key wrapper for provider_data. */
static mbedtls_jwk_t *jwk_new(jwk_key_type_t kty)
{
	mbedtls_jwk_t *k = jwt_malloc(sizeof(*k));

	if (k == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(k, 0, sizeof(*k));
	k->kty = kty;

	return k;
}

/* base64url-decode a JWK string member into a freshly allocated buffer. */
static unsigned char *decode_member(jwt_json_t *jwk, const char *name, int *len)
{
	jwt_json_t *val = jwt_json_obj_get(jwk, name);
	const char *str;

	*len = 0;

	if (val == NULL || !jwt_json_is_string(val))
		return NULL;

	str = jwt_json_str_val(val);
	if (str == NULL || !strlen(str))
		return NULL;

	return jwt_base64uri_decode(str, len);
}

/* Bit length of a big-endian unsigned integer held in @b[0..len). */
static size_t be_bitlen(const unsigned char *b, size_t len)
{
	size_t i = 0, bits;
	unsigned char top;

	while (i < len && b[i] == 0)
		i++; // LCOV_EXCL_LINE
	if (i == len)
		return 0; // LCOV_EXCL_LINE

	bits = (len - i - 1) * 8;
	for (top = b[i]; top; top >>= 1)
		bits++;

	return bits;
}

/* Map a NIST/secp JWK "crv" to a PSA ECC family + key size. Returns 0 and fills
 * @fam/@bits/@fieldlen on success, non-zero for an unknown curve. (Montgomery
 * X-curves are handled in mbedtls_process_eddsa, not here.) */
static int crv_to_psa(const char *crv, psa_ecc_family_t *fam, size_t *bits,
		      size_t *fieldlen)
{
	if (!strcmp(crv, "P-256")) {
		*fam = PSA_ECC_FAMILY_SECP_R1; *bits = 256;
	} else if (!strcmp(crv, "P-384")) {
		*fam = PSA_ECC_FAMILY_SECP_R1; *bits = 384;
	} else if (!strcmp(crv, "P-521")) {
		*fam = PSA_ECC_FAMILY_SECP_R1; *bits = 521;
	} else if (!strcmp(crv, "secp256k1")) {
		*fam = PSA_ECC_FAMILY_SECP_K1; *bits = 256;
	} else {
		return 1;
	}

	*fieldlen = (*bits + 7) / 8;

	return 0;
}

/* Import a short-lived PSA key from the stored JWK material with the given
 * policy. Public/private key form is selected by @want_private. See the header. */
JWT_NO_EXPORT
int mbedtls_jwk_to_psa(const mbedtls_jwk_t *key, int want_private,
	psa_algorithm_t alg, psa_key_usage_t usage, mbedtls_svc_key_id_t *kid)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_type_t type;
	const unsigned char *data;
	size_t data_len;
	psa_status_t st;

	*kid = MBEDTLS_SVC_KEY_ID_INIT;

	if (psa_crypto_init() != PSA_SUCCESS)
		return 1; // LCOV_EXCL_LINE

	if (want_private) {
		if (key->priv == NULL)
			return 1; // LCOV_EXCL_LINE
		data = key->priv;
		data_len = key->priv_len;
		type = (key->kty == JWK_KEY_TYPE_RSA)
			? PSA_KEY_TYPE_RSA_KEY_PAIR
			: PSA_KEY_TYPE_ECC_KEY_PAIR(key->ecc_family);
	} else {
		if (key->pub == NULL)
			return 1; // LCOV_EXCL_LINE
		data = key->pub;
		data_len = key->pub_len;
		type = (key->kty == JWK_KEY_TYPE_RSA)
			? PSA_KEY_TYPE_RSA_PUBLIC_KEY
			: PSA_KEY_TYPE_ECC_PUBLIC_KEY(key->ecc_family);
	}

	psa_set_key_type(&attr, type);
	psa_set_key_usage_flags(&attr, usage);
	psa_set_key_algorithm(&attr, alg);

	st = psa_import_key(&attr, data, data_len, kid);
	psa_reset_key_attributes(&attr);

	return st != PSA_SUCCESS;
}

/* Write one ASN.1 INTEGER from a raw big-endian magnitude (the mbedtls asn1
 * writers fill the buffer back-to-front from *p). Strips leading zero bytes and
 * prepends a 0x00 sign byte when the high bit is set. Returns the encoded length
 * or a negative error. */
static int asn1_write_int_raw(unsigned char **p, unsigned char *start,
			      const unsigned char *raw, size_t raw_len)
{
	const unsigned char *v = raw;
	size_t n = raw_len;
	int ret, len = 0;

	while (n > 1 && v[0] == 0) {
		v++; // LCOV_EXCL_LINE
		n--; // LCOV_EXCL_LINE
	}

	if ((ret = mbedtls_asn1_write_raw_buffer(p, start, v, n)) < 0)
		return ret; // LCOV_EXCL_LINE
	len += ret;

	if (v[0] & 0x80) {
		if (*p <= start)
			return -1; // LCOV_EXCL_LINE
		*--(*p) = 0x00;
		len += 1;
	}

	if ((ret = mbedtls_asn1_write_len(p, start, (size_t)len)) < 0)
		return ret; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_INTEGER)) < 0)
		return ret; // LCOV_EXCL_LINE
	len += ret;

	return len;
}

/* @rfc{8017} Build a DER PKCS#1 RSAPublicKey { n, e } from the raw components. */
static unsigned char *build_rsa_pub_der(const unsigned char *n, size_t n_l,
					const unsigned char *e, size_t e_l,
					size_t *out_len)
{
	size_t cap = n_l + e_l + 32;
	unsigned char *tmp, *p, *der;
	int len = 0, ret;

	tmp = jwt_malloc(cap);
	if (tmp == NULL)
		return NULL; // LCOV_EXCL_LINE
	p = tmp + cap;

	if ((ret = asn1_write_int_raw(&p, tmp, e, e_l)) < 0)
		goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, n, n_l)) < 0)
		goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = mbedtls_asn1_write_len(&p, tmp, (size_t)len)) < 0)
		goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = mbedtls_asn1_write_tag(&p, tmp,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) < 0)
		goto fail; // LCOV_EXCL_LINE
	len += ret;

	der = jwt_malloc((size_t)len);
	if (der == NULL)
		goto fail; // LCOV_EXCL_LINE
	memcpy(der, p, (size_t)len);
	*out_len = (size_t)len;
	jwt_freemem(tmp);
	return der;

fail:
	jwt_freemem(tmp); // LCOV_EXCL_LINE
	return NULL; // LCOV_EXCL_LINE
}

/* @rfc{8017} Build a DER PKCS#1 RSAPrivateKey { 0, n, e, d, p, q, dp, dq, qi }
 * from the raw components. The result is scrubbed/freed by the caller. */
static unsigned char *build_rsa_priv_der(
	const unsigned char *n, size_t n_l, const unsigned char *e, size_t e_l,
	const unsigned char *d, size_t d_l, const unsigned char *p_, size_t p_l,
	const unsigned char *q, size_t q_l, const unsigned char *dp, size_t dp_l,
	const unsigned char *dq, size_t dq_l, const unsigned char *qi, size_t qi_l,
	size_t *out_len)
{
	size_t cap = n_l + e_l + d_l + p_l + q_l + dp_l + dq_l + qi_l + 64;
	unsigned char *tmp, *p, *der;
	int len = 0, ret;

	tmp = jwt_malloc(cap);
	if (tmp == NULL)
		return NULL; // LCOV_EXCL_LINE
	p = tmp + cap;

	/* Written back-to-front, so emit fields in reverse order. */
	if ((ret = asn1_write_int_raw(&p, tmp, qi, qi_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, dq, dq_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, dp, dp_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, q, q_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, p_, p_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, d, d_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, e, e_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = asn1_write_int_raw(&p, tmp, n, n_l)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = mbedtls_asn1_write_int(&p, tmp, 0)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = mbedtls_asn1_write_len(&p, tmp, (size_t)len)) < 0) goto fail; // LCOV_EXCL_LINE
	len += ret;
	if ((ret = mbedtls_asn1_write_tag(&p, tmp,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) < 0)
		goto fail; // LCOV_EXCL_LINE
	len += ret;

	der = jwt_malloc((size_t)len);
	if (der == NULL)
		goto fail; // LCOV_EXCL_LINE
	memcpy(der, p, (size_t)len);
	*out_len = (size_t)len;
	mbedtls_platform_zeroize(tmp, cap);
	jwt_freemem(tmp);
	return der;

fail:
	// LCOV_EXCL_START
	mbedtls_platform_zeroize(tmp, cap);
	jwt_freemem(tmp);
	return NULL;
	// LCOV_EXCL_STOP
}

/* Best-effort PEM export into item->pem (a convenience surfaced by
 * jwks_item_pem and the jwk2key tool). PEM is optional and backend-dependent;
 * any failure simply leaves item->pem NULL. Only RSA and NIST EC keys are
 * exported (pk has no representation for OKP/Montgomery). */
static void set_pem_best_effort(jwk_item_t *item, const mbedtls_jwk_t *key)
{
	mbedtls_svc_key_id_t kid;
	mbedtls_pk_context pk;
	unsigned char buf[8192];
	psa_algorithm_t alg;
	psa_key_usage_t usage = PSA_KEY_USAGE_EXPORT;
	int priv = key->is_private, ret;

	if (key->kty == JWK_KEY_TYPE_RSA)
		alg = PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH);
	else if (key->kty == JWK_KEY_TYPE_EC)
		alg = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
	else
		return;	// LCOV_EXCL_LINE (OKP has no pk/PEM form; not called for OKP)

	usage |= priv ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_VERIFY_MESSAGE;

	if (mbedtls_jwk_to_psa(key, priv, alg, usage, &kid))
		return; // LCOV_EXCL_LINE

	mbedtls_pk_init(&pk);

	if (mbedtls_pk_copy_from_psa(kid, &pk) == 0) {
		ret = priv ? mbedtls_pk_write_key_pem(&pk, buf, sizeof(buf))
			   : mbedtls_pk_write_pubkey_pem(&pk, buf, sizeof(buf));
		if (ret == 0) {
			size_t len = strlen((char *)buf);
			char *dest = jwt_malloc(len + 1);
			if (dest != NULL) {
				memcpy(dest, buf, len + 1);
				item->pem = dest;
			}
		}
	}

	mbedtls_pk_free(&pk);
	psa_destroy_key(kid);
	mbedtls_platform_zeroize(buf, sizeof(buf));
}

/* @rfc{7518,6.3} Build the importable RSA material (DER PKCS#1) from the JWK
 * components. The same path serves RSA and RSA-PSS — the padding scheme is a
 * sign/verify-time choice, so we keep a single neutral RSA key. We deliberately
 * defer all key validation to first use (psa_import_key at sign/verify/encrypt
 * time): this matches the OpenSSL parser's loose fromdata for public keys, which
 * the RSA error-path tests rely on. */
JWT_NO_EXPORT
int mbedtls_process_rsa(jwt_json_t *jwk, jwk_item_t *item)
{
	unsigned char *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL,
		      *dp = NULL, *dq = NULL, *qi = NULL;
	int n_l, e_l, d_l, p_l, q_l, dp_l, dq_l, qi_l;
	jwt_json_t *jd, *jp, *jq, *jdp, *jdq, *jqi;
	mbedtls_jwk_t *key = NULL;
	int priv = 0, ret = -1;

	/* Presence of the JSON members first (matches the OpenSSL parser's
	 * "missing" vs "decode error" distinction the error-path tests rely on). */
	if (jwt_json_obj_get(jwk, "n") == NULL ||
	    jwt_json_obj_get(jwk, "e") == NULL) {
		jwt_write_error(item, "Missing required RSA component: n or e");
		goto cleanup;
	}

	jd = jwt_json_obj_get(jwk, "d");
	jp = jwt_json_obj_get(jwk, "p");
	jq = jwt_json_obj_get(jwk, "q");
	jdp = jwt_json_obj_get(jwk, "dp");
	jdq = jwt_json_obj_get(jwk, "dq");
	jqi = jwt_json_obj_get(jwk, "qi");

	if (jd && jp && jq && jdp && jdq && jqi) {
		priv = 1;
	} else if (jd || jp || jq || jdp || jdq || jqi) {
		jwt_write_error(item,
			"Some priv key components exist, but some are missing");
		goto cleanup;
	}

	n = decode_member(jwk, "n", &n_l);
	e = decode_member(jwk, "e", &e_l);
	if (n == NULL || e == NULL) {
		jwt_write_error(item, "Error decoding pub components");
		goto cleanup;
	}

	key = jwk_new(JWK_KEY_TYPE_RSA);
	if (key == NULL)
		goto cleanup; // LCOV_EXCL_LINE

	key->bits = be_bitlen(n, (size_t)n_l);
	item->bits = key->bits;

	/* PSA caps RSA at PSA_VENDOR_RSA_MAX_KEY_BITS (a property of the linked
	 * crypto build, 4096 by default). The classic API had no such limit, so a
	 * larger key would parse but fail at first use; reject it here with a clear
	 * message instead. */
	if (key->bits > PSA_VENDOR_RSA_MAX_KEY_BITS) {
		jwt_write_error(item,
			"RSA key size (%zu bits) exceeds the backend maximum "
			"of %u bits", key->bits,
			(unsigned int)PSA_VENDOR_RSA_MAX_KEY_BITS);
		goto cleanup;
	}

	key->pub = build_rsa_pub_der(n, (size_t)n_l, e, (size_t)e_l,
				     &key->pub_len);
	if (key->pub == NULL)
		goto cleanup; // LCOV_EXCL_LINE

	if (priv) {
		d = decode_member(jwk, "d", &d_l);
		p = decode_member(jwk, "p", &p_l);
		q = decode_member(jwk, "q", &q_l);
		dp = decode_member(jwk, "dp", &dp_l);
		dq = decode_member(jwk, "dq", &dq_l);
		qi = decode_member(jwk, "qi", &qi_l);
		if (!d || !p || !q || !dp || !dq || !qi) {
			jwt_write_error(item, "Error decoding priv components");
			goto cleanup;
		}
		key->priv = build_rsa_priv_der(n, n_l, e, e_l, d, d_l, p, p_l,
					       q, q_l, dp, dp_l, dq, dq_l,
					       qi, qi_l, &key->priv_len);
		if (key->priv == NULL)
			goto cleanup; // LCOV_EXCL_LINE
		item->is_private_key = key->is_private = 1;
	}

	item->provider = JWT_CRYPTO_OPS_MBEDTLS;
	item->provider_data = key;

	set_pem_best_effort(item, key);

	key = NULL;
	ret = 0;

cleanup: // LCOV_EXCL_LINE (gcov mis-counts the bare label)
	if (key != NULL) {
		// LCOV_EXCL_START
		jwt_freemem(key->pub);
		jwt_scrub_and_free(key->priv, key->priv_len);
		jwt_freemem(key);
		// LCOV_EXCL_STOP
	}
	jwt_freemem(n);
	jwt_freemem(e);
	jwt_scrub_and_free(d, d ? (size_t)d_l : 0);
	jwt_scrub_and_free(p, p ? (size_t)p_l : 0);
	jwt_scrub_and_free(q, q ? (size_t)q_l : 0);
	jwt_scrub_and_free(dp, dp ? (size_t)dp_l : 0);
	jwt_scrub_and_free(dq, dq ? (size_t)dq_l : 0);
	jwt_scrub_and_free(qi, qi ? (size_t)qi_l : 0);

	return ret;
}

/* @rfc{7518,6.2} Build the importable EC material from the JWK crv/x/y[/d]. The
 * public point (and private scalar, when present) is validated at parse via a
 * throwaway PSA import, so structurally-bad points are rejected here exactly as
 * the OpenSSL parser does. */
JWT_NO_EXPORT
int mbedtls_process_ec(jwt_json_t *jwk, jwk_item_t *item)
{
	unsigned char *x = NULL, *y = NULL, *d = NULL;
	int x_l, y_l, d_l = 0;
	jwt_json_t *jcrv, *jx, *jy, *jd;
	const char *crv;
	psa_ecc_family_t fam;
	size_t bits, fieldlen;
	mbedtls_jwk_t *key = NULL;
	mbedtls_svc_key_id_t kid;
	int priv = 0, ret = -1;

	jcrv = jwt_json_obj_get(jwk, "crv");
	jx = jwt_json_obj_get(jwk, "x");
	jy = jwt_json_obj_get(jwk, "y");
	jd = jwt_json_obj_get(jwk, "d");

	if (jcrv == NULL || jx == NULL || jy == NULL ||
	    !jwt_json_is_string(jcrv) || !jwt_json_is_string(jx) ||
	    !jwt_json_is_string(jy)) {
		jwt_write_error(item,
			"Missing or invalid type for one of crv, x, or y for pub key");
		goto cleanup;
	}

	crv = jwt_json_str_val(jcrv);
	strncpy(item->curve, crv, sizeof(item->curve) - 1);
	item->curve[sizeof(item->curve) - 1] = '\0';

	/* An unknown curve and bad x/y points are both pub-key construction
	 * failures, sharing one message to mirror the OpenSSL parser. */
	if (crv_to_psa(crv, &fam, &bits, &fieldlen)) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto cleanup;
	}

	key = jwk_new(JWK_KEY_TYPE_EC);
	if (key == NULL)
		goto cleanup; // LCOV_EXCL_LINE
	key->ecc_family = fam;
	key->bits = bits;
	item->bits = bits;

	x = decode_member(jwk, "x", &x_l);
	y = decode_member(jwk, "y", &y_l);
	if (x == NULL || y == NULL ||
	    (size_t)x_l > fieldlen || (size_t)y_l > fieldlen) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto cleanup;
	}

	/* Uncompressed point: 0x04 || X || Y, each left-padded to fieldlen. */
	key->pub_len = 1 + fieldlen * 2;
	key->pub = jwt_malloc(key->pub_len);
	if (key->pub == NULL)
		goto cleanup; // LCOV_EXCL_LINE
	memset(key->pub, 0, key->pub_len);
	key->pub[0] = 0x04;
	memcpy(key->pub + 1 + (fieldlen - (size_t)x_l), x, (size_t)x_l);
	memcpy(key->pub + 1 + fieldlen + (fieldlen - (size_t)y_l), y, (size_t)y_l);

	if (jd != NULL && jwt_json_is_string(jd)) {
		d = decode_member(jwk, "d", &d_l);
		if (d == NULL || (size_t)d_l > fieldlen) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing EC private key");
			goto cleanup;
			// LCOV_EXCL_STOP
		}
		/* Scalar left-padded to the field length for PSA import. */
		key->priv_len = fieldlen;
		key->priv = jwt_malloc(key->priv_len);
		if (key->priv == NULL)
			goto cleanup; // LCOV_EXCL_LINE
		memset(key->priv, 0, key->priv_len);
		memcpy(key->priv + (fieldlen - (size_t)d_l), d, (size_t)d_l);
		item->is_private_key = key->is_private = priv = 1;
	}

	/* Validate the public point (on-curve) via a throwaway PSA import. */
	if (mbedtls_jwk_to_psa(key, 0, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
			       PSA_KEY_USAGE_VERIFY_MESSAGE, &kid)) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto cleanup;
	}
	psa_destroy_key(kid);

	/* Validate the private scalar, when present, the same way. */
	if (priv &&
	    mbedtls_jwk_to_psa(key, 1, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
			       PSA_KEY_USAGE_SIGN_MESSAGE, &kid)) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error importing EC private key");
		goto cleanup;
		// LCOV_EXCL_STOP
	}
	if (priv)
		psa_destroy_key(kid);

	item->provider = JWT_CRYPTO_OPS_MBEDTLS;
	item->provider_data = key;

	set_pem_best_effort(item, key);

	key = NULL;
	ret = 0;

cleanup: // LCOV_EXCL_LINE (gcov mis-counts the bare label)
	if (key != NULL) {
		jwt_freemem(key->pub);
		jwt_scrub_and_free(key->priv, key->priv_len);
		jwt_freemem(key);
	}
	jwt_freemem(x);
	jwt_freemem(y);
	jwt_scrub_and_free(d, d ? (size_t)d_l : 0);

	return ret;
}

/* @rfc{8037} OKP keys. PSA (like MbedTLS classic) supports the X-curves
 * (X25519/X448) for ECDH but has no EdDSA. We keep the raw material for both:
 * X-curves as PSA-importable little-endian bytes, Ed-curves retained only so a
 * keyring still loads (any sign/verify/JWE on an Ed key fails with a clear
 * error). Montgomery keys need no on-curve check — any value of the right length
 * is a valid u-coordinate — so length is the only validation. */
JWT_NO_EXPORT
int mbedtls_process_eddsa(jwt_json_t *jwk, jwk_item_t *item)
{
	unsigned char *x = NULL, *d = NULL;
	int x_l = 0, d_l = 0;
	jwt_json_t *jcrv, *jx, *jd;
	const char *crv;
	mbedtls_jwk_t *key = NULL;
	size_t keylen = 0;
	int is_ed, ret = -1;

	jcrv = jwt_json_obj_get(jwk, "crv");
	jx = jwt_json_obj_get(jwk, "x");
	jd = jwt_json_obj_get(jwk, "d");

	if (jcrv == NULL || !jwt_json_is_string(jcrv)) {
		jwt_write_error(item, "No curve component found for OKP key");
		goto cleanup;
	}
	if (jx == NULL && jd == NULL) {
		jwt_write_error(item,
			"Need an 'x' or 'd' component and found neither");
		goto cleanup;
	}

	crv = jwt_json_str_val(jcrv);
	strncpy(item->curve, crv, sizeof(item->curve) - 1);
	item->curve[sizeof(item->curve) - 1] = '\0';

	is_ed = !strcmp(crv, "Ed25519") || !strcmp(crv, "Ed448");

	if (!is_ed && strcmp(crv, "X25519") && strcmp(crv, "X448")) {
		jwt_write_error(item, "Unknown curve [%s]", crv);
		goto cleanup;
	}

	/* Bit sizes (matches the JWS key-length validation in jwt.c). Ed448 is
	 * conventionally reported as 456. */
	if (!strcmp(crv, "Ed25519") || !strcmp(crv, "X25519"))
		item->bits = 256;
	else if (!strcmp(crv, "Ed448"))
		item->bits = 456;
	else
		item->bits = 448; /* X448 */

	key = jwk_new(JWK_KEY_TYPE_OKP);
	if (key == NULL)
		goto cleanup; // LCOV_EXCL_LINE
	key->okp_is_ed = is_ed;
	key->bits = item->bits;

	if (jd != NULL)
		item->is_private_key = key->is_private = 1;

	if (is_ed) {
		/* Ed-curves: store raw material only (no EdDSA support here). */
		if (jx != NULL && jwt_json_is_string(jx)) {
			key->pub = decode_member(jwk, "x", &x_l);
			key->pub_len = key->pub ? (size_t)x_l : 0;
		}
		if (jd != NULL && jwt_json_is_string(jd)) {
			key->priv = decode_member(jwk, "d", &d_l);
			key->priv_len = key->priv ? (size_t)d_l : 0;
		}
	} else {
		/* X-curves: PSA-importable little-endian material. The decoded
		 * "x"/"d" must be exactly the curve length (X25519 = 32, X448 =
		 * 56); without the check an over/undersized attacker value would
		 * be accepted where OpenSSL/GnuTLS reject it. */
		key->ecc_family = PSA_ECC_FAMILY_MONTGOMERY;
		keylen = !strcmp(crv, "X25519") ? 32 : 56;

		if (jx != NULL && jwt_json_is_string(jx)) {
			x = decode_member(jwk, "x", &x_l);
			if (x == NULL) {
				jwt_write_error(item, "Error decoding OKP x"); // LCOV_EXCL_LINE
				goto cleanup; // LCOV_EXCL_LINE
			}
			if ((size_t)x_l != keylen) {
				jwt_write_error(item, "Invalid OKP x length");
				goto cleanup;
			}
			key->pub = x;
			key->pub_len = (size_t)x_l;
			x = NULL;
		}
		if (jd != NULL && jwt_json_is_string(jd)) {
			d = decode_member(jwk, "d", &d_l);
			if (d == NULL) {
				jwt_write_error(item, "Error decoding OKP d"); // LCOV_EXCL_LINE
				goto cleanup; // LCOV_EXCL_LINE
			}
			if ((size_t)d_l != keylen) {
				jwt_write_error(item, "Invalid OKP d length");
				goto cleanup;
			}
			key->priv = d;
			key->priv_len = (size_t)d_l;
			d = NULL;
		}
	}

	item->provider = JWT_CRYPTO_OPS_MBEDTLS;
	item->provider_data = key;
	key = NULL;
	ret = 0;

cleanup:
	if (key != NULL) {
		jwt_freemem(key->pub);
		jwt_scrub_and_free(key->priv, key->priv_len);
		jwt_freemem(key);
	}
	jwt_freemem(x);
	jwt_scrub_and_free(d, d ? (size_t)d_l : 0);

	return ret;
}

JWT_NO_EXPORT
void mbedtls_process_item_free(jwk_item_t *item)
{
	mbedtls_jwk_t *key;

	if (item == NULL || item->provider != JWT_CRYPTO_OPS_MBEDTLS)
		return;

	key = item->provider_data;
	if (key != NULL) {
		jwt_freemem(key->pub);
		jwt_scrub_and_free(key->priv, key->priv_len);
		jwt_freemem(key);
	}

	if (item->pem) {
		mbedtls_platform_zeroize(item->pem, strlen(item->pem));
		jwt_freemem(item->pem);
	}

	item->pem = NULL;
	item->provider_data = NULL;
	item->provider = JWT_CRYPTO_OPS_NONE;
}

/* Generate a fresh EC or RSA key via PSA and emit it as a PKCS#8 private-key
 * PEM (via mbedtls_pk). MbedTLS has no EdDSA (OKP) or ML-DSA (AKP), so those
 * return non-zero -> a clean "not supported" error. */
int mbedtls_generate_pem(jwk_key_type_t kty, const char *param, jwt_alg_t alg,
			 char **pem_out, size_t *pem_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	mbedtls_pk_context pk;
	unsigned char buf[8192];
	psa_status_t st;
	int ret = 1;

	(void)alg;

	if (psa_crypto_init() != PSA_SUCCESS)
		return 1; // LCOV_EXCL_LINE

	switch (kty) {
	case JWK_KEY_TYPE_EC: {
		const char *crv = (param && param[0]) ? param : "P-256";
		psa_ecc_family_t fam = PSA_ECC_FAMILY_SECP_R1;
		size_t bits;

		if (!strcmp(crv, "P-256"))		bits = 256;
		else if (!strcmp(crv, "P-384"))		bits = 384;
		else if (!strcmp(crv, "P-521"))		bits = 521;
		else if (!strcmp(crv, "secp256k1")) {
			fam = PSA_ECC_FAMILY_SECP_K1;
			bits = 256;
		} else
			return 1;

		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(fam));
		psa_set_key_bits(&attr, bits);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
		break;
	}
	case JWK_KEY_TYPE_RSA: {
		long bits = (param && param[0]) ? strtol(param, NULL, 10) : 2048;

		if (bits < 2048)
			return 1;
		psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
		psa_set_key_bits(&attr, (size_t)bits);
		psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH));
		break;
	}
	default:
		return 1;
	}

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT |
				PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);

	st = psa_generate_key(&attr, &kid);
	psa_reset_key_attributes(&attr);
	if (st != PSA_SUCCESS)
		return 1;

	mbedtls_pk_init(&pk);
	if (mbedtls_pk_copy_from_psa(kid, &pk) == 0 &&
	    mbedtls_pk_write_key_pem(&pk, buf, sizeof(buf)) == 0) {
		size_t len = strlen((char *)buf);

		*pem_out = jwt_malloc(len + 1);
		if (*pem_out != NULL) {
			memcpy(*pem_out, buf, len + 1);
			*pem_len = len;
			ret = 0;
		}
	}

	/* The buffer held an unencrypted private key; scrub it (see the same
	 * convention in set_pem_best_effort()). */
	mbedtls_platform_zeroize(buf, sizeof(buf));
	mbedtls_pk_free(&pk);
	psa_destroy_key(kid);

	return ret;
}
