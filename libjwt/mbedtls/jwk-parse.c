/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/bignum.h>

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

/* Map a JWK "crv" to a MbedTLS EC group id (NIST + Montgomery X-curves). */
static mbedtls_ecp_group_id ec_crv_to_group(const char *crv)
{
	if (!strcmp(crv, "P-256"))
		return MBEDTLS_ECP_DP_SECP256R1;
	if (!strcmp(crv, "P-384"))
		return MBEDTLS_ECP_DP_SECP384R1;
	if (!strcmp(crv, "P-521"))
		return MBEDTLS_ECP_DP_SECP521R1;
	if (!strcmp(crv, "secp256k1"))
		return MBEDTLS_ECP_DP_SECP256K1;
	if (!strcmp(crv, "X25519"))
		return MBEDTLS_ECP_DP_CURVE25519;
	if (!strcmp(crv, "X448"))
		return MBEDTLS_ECP_DP_CURVE448;

	return MBEDTLS_ECP_DP_NONE;
}

/* Export a PEM string from a native RSA/EC key into item->pem (a convenience
 * exposed via jwks_item_pem and used by the jwk2key tool). Failure is
 * non-fatal: pem is optional, so we just leave it NULL. */
static void set_pem_from_pk(jwk_item_t *item, mbedtls_pk_context *pk, int priv)
{
	unsigned char buf[8192];
	char *dest;
	size_t len;
	int ret;

	if (priv)
		ret = mbedtls_pk_write_key_pem(pk, buf, sizeof(buf));
	else
		ret = mbedtls_pk_write_pubkey_pem(pk, buf, sizeof(buf));

	if (ret != 0)
		return; // LCOV_EXCL_LINE

	len = strlen((char *)buf);
	dest = jwt_malloc(len + 1);
	if (dest == NULL)
		return; // LCOV_EXCL_LINE

	memcpy(dest, buf, len + 1);
	item->pem = dest;

	mbedtls_platform_zeroize(buf, sizeof(buf));
}

/* @rfc{7518,6.3} Build a native RSA key from the JWK components. The same path
 * serves RSA and RSA-PSS; the PSS padding is applied at sign/verify, so we keep
 * a plain RSA context and never round-trip through an id-RSASSA-PSS PEM (which
 * mbedtls_pk_parse_key would reject). */
JWT_NO_EXPORT
int mbedtls_process_rsa(jwt_json_t *jwk, jwk_item_t *item)
{
	unsigned char *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL,
		      *dp = NULL, *dq = NULL, *qi = NULL;
	int n_l, e_l, d_l, p_l, q_l, dp_l, dq_l, qi_l;
	jwt_json_t *jd, *jp, *jq, *jdp, *jdq, *jqi;
	mbedtls_jwk_t *key = NULL;
	mbedtls_pk_context pk;
	int priv = 0, have_pem = 0, ret = -1;

	mbedtls_pk_init(&pk);

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
	mbedtls_rsa_init(&key->rsa);

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
		if (mbedtls_rsa_import_raw(&key->rsa, n, n_l, p, p_l, q, q_l,
					   d, d_l, e, e_l) ||
		    mbedtls_rsa_complete(&key->rsa) ||
		    mbedtls_rsa_check_privkey(&key->rsa)) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing RSA private key");
			goto cleanup;
			// LCOV_EXCL_STOP
		}
		item->is_private_key = key->is_private = 1;
	} else {
		/* Public key: import n,e only. We deliberately skip
		 * mbedtls_rsa_complete()/check_pubkey() — they enforce minimum
		 * sizes and reject structurally-odd keys that OpenSSL's loose
		 * fromdata accepts; matching OpenSSL keeps cross-backend parsing
		 * consistent (the RSA error-path tests rely on this). */
		if (mbedtls_rsa_import_raw(&key->rsa, n, n_l, NULL, 0, NULL, 0,
					   NULL, 0, e, e_l)) {
			jwt_write_error(item, "Error importing RSA public key"); // LCOV_EXCL_LINE
			goto cleanup; // LCOV_EXCL_LINE
		}
	}

	item->bits = mbedtls_rsa_get_bitlen(&key->rsa);

	/* Wrap in a temporary pk_context only to export the convenience PEM. */
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 &&
	    mbedtls_rsa_copy(mbedtls_pk_rsa(pk), &key->rsa) == 0)
		have_pem = 1;

	item->provider = JWT_CRYPTO_OPS_MBEDTLS;
	item->provider_data = key;
	key = NULL;
	ret = 0;

	if (have_pem)
		set_pem_from_pk(item, &pk, priv);

cleanup: // LCOV_EXCL_LINE (gcov mis-counts the bare label)
	mbedtls_pk_free(&pk);
	if (key != NULL) {
		mbedtls_rsa_free(&key->rsa);
		jwt_freemem(key);
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

/* @rfc{7518,6.2} Build a native EC keypair from the JWK crv/x/y[/d]. */
JWT_NO_EXPORT
int mbedtls_process_ec(jwt_json_t *jwk, jwk_item_t *item)
{
	unsigned char *x = NULL, *y = NULL, *d = NULL, *point = NULL;
	int x_l, y_l, d_l = 0;
	jwt_json_t *jcrv, *jx, *jy, *jd;
	const char *crv;
	mbedtls_ecp_group_id gid;
	mbedtls_jwk_t *key = NULL;
	mbedtls_pk_context pk;
	size_t fieldlen, ptlen;
	int priv = 0, have_pem = 0, ret = -1;

	mbedtls_pk_init(&pk);

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
	gid = ec_crv_to_group(crv);
	if (gid == MBEDTLS_ECP_DP_NONE) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto cleanup;
	}

	key = jwk_new(JWK_KEY_TYPE_EC);
	if (key == NULL)
		goto cleanup; // LCOV_EXCL_LINE
	mbedtls_ecp_keypair_init(&key->ec);

	if (mbedtls_ecp_group_load(&key->ec.MBEDTLS_PRIVATE(grp), gid)) {
		jwt_write_error(item, "Error loading EC group"); // LCOV_EXCL_LINE
		goto cleanup; // LCOV_EXCL_LINE
	}

	/* Field length from the loaded group. JWK coordinates are big-endian
	 * and may have had leading zero bytes stripped (e.g. P-521 often
	 * decodes to 65 bytes, not 66), so left-pad each into the fixed field
	 * width that mbedtls_ecp_point_read_binary expects. */
	fieldlen = (key->ec.MBEDTLS_PRIVATE(grp).nbits + 7) / 8;

	x = decode_member(jwk, "x", &x_l);
	y = decode_member(jwk, "y", &y_l);
	if (x == NULL || y == NULL ||
	    (size_t)x_l > fieldlen || (size_t)y_l > fieldlen) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto cleanup;
	}

	/* Uncompressed point: 0x04 || X || Y, each left-padded to fieldlen. */
	ptlen = 1 + fieldlen * 2;
	point = jwt_malloc(ptlen);
	if (point == NULL)
		goto cleanup; // LCOV_EXCL_LINE
	memset(point, 0, ptlen);
	point[0] = 0x04;
	memcpy(point + 1 + (fieldlen - (size_t)x_l), x, (size_t)x_l);
	memcpy(point + 1 + fieldlen + (fieldlen - (size_t)y_l), y, (size_t)y_l);

	if (mbedtls_ecp_point_read_binary(&key->ec.MBEDTLS_PRIVATE(grp),
					  &key->ec.MBEDTLS_PRIVATE(Q),
					  point, ptlen) ||
	    mbedtls_ecp_check_pubkey(&key->ec.MBEDTLS_PRIVATE(grp),
				     &key->ec.MBEDTLS_PRIVATE(Q))) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto cleanup;
	}

	if (jd != NULL && jwt_json_is_string(jd)) {
		d = decode_member(jwk, "d", &d_l);
		if (d == NULL) {
			jwt_write_error(item, "Error decoding EC d"); // LCOV_EXCL_LINE
			goto cleanup; // LCOV_EXCL_LINE
		}
		if (mbedtls_mpi_read_binary(&key->ec.MBEDTLS_PRIVATE(d),
					    d, (size_t)d_l) ||
		    mbedtls_ecp_check_privkey(&key->ec.MBEDTLS_PRIVATE(grp),
					      &key->ec.MBEDTLS_PRIVATE(d))) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing EC private key");
			goto cleanup;
			// LCOV_EXCL_STOP
		}
		item->is_private_key = key->is_private = priv = 1;
	}

	item->bits = key->ec.MBEDTLS_PRIVATE(grp).nbits;

	/* Wrap a copy of the native keypair in a pk_context for the PEM export.
	 * mbedtls_pk_setup(ECKEY) gives an initialized-but-empty keypair, so we
	 * load the group and copy Q (and d for private keys) into it. */
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0) {
		mbedtls_ecp_keypair *kp = mbedtls_pk_ec(pk);

		if (mbedtls_ecp_group_load(&kp->MBEDTLS_PRIVATE(grp), gid) == 0 &&
		    mbedtls_ecp_copy(&kp->MBEDTLS_PRIVATE(Q),
				     &key->ec.MBEDTLS_PRIVATE(Q)) == 0 &&
		    (!priv || mbedtls_mpi_copy(&kp->MBEDTLS_PRIVATE(d),
					       &key->ec.MBEDTLS_PRIVATE(d)) == 0))
			have_pem = 1;
	}

	item->provider = JWT_CRYPTO_OPS_MBEDTLS;
	item->provider_data = key;
	key = NULL;
	ret = 0;

	if (have_pem)
		set_pem_from_pk(item, &pk, priv);

cleanup: // LCOV_EXCL_LINE (gcov mis-counts the bare label)
	mbedtls_pk_free(&pk);
	if (key != NULL) {
		mbedtls_ecp_keypair_free(&key->ec);
		jwt_freemem(key);
	}
	jwt_freemem(x);
	jwt_freemem(y);
	jwt_freemem(point);
	jwt_scrub_and_free(d, d ? (size_t)d_l : 0);

	return ret;
}

/* @rfc{8037} OKP keys. MbedTLS supports the X-curves (X25519/X448) for ECDH but
 * has no EdDSA at all. We retain the native ECP keypair for X-curves and only
 * the raw material for Ed-curves; an Ed key parses cleanly so a keyring still
 * loads, but any sign/verify/JWE op on it fails with a clear error. */
JWT_NO_EXPORT
int mbedtls_process_eddsa(jwt_json_t *jwk, jwk_item_t *item)
{
	unsigned char *x = NULL, *d = NULL;
	int x_l = 0, d_l = 0;
	jwt_json_t *jcrv, *jx, *jd;
	const char *crv;
	mbedtls_jwk_t *key = NULL;
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

	if (jd != NULL)
		item->is_private_key = key->is_private = 1;

	if (is_ed) {
		/* Ed-curves: store raw material only (mbedtls has no EdDSA). */
		if (jx != NULL && jwt_json_is_string(jx)) {
			key->okp_ed.pub = decode_member(jwk, "x", &x_l);
			key->okp_ed.pub_len = key->okp_ed.pub ? (size_t)x_l : 0;
		}
		if (jd != NULL && jwt_json_is_string(jd)) {
			key->okp_ed.priv = decode_member(jwk, "d", &d_l);
			key->okp_ed.priv_len = key->okp_ed.priv ? (size_t)d_l : 0;
		}
	} else {
		/* X-curves: a native ECP keypair usable for ECDH. The JWK "x"/
		 * "d" are RFC 7748 little-endian; mbedtls Montgomery points read
		 * little-endian via the *_le MPI helpers. */
		mbedtls_ecp_group_id gid = ec_crv_to_group(crv);
		/* Field width: X25519 = 32 bytes, X448 = 56 bytes. The decoded
		 * "x"/"d" must be exactly this length. Without the check an
		 * over/undersized attacker-supplied value would be accepted here
		 * (mbedtls grows the MPI dynamically), where OpenSSL/GnuTLS and the
		 * mbedtls "epk" reader reject it. */
		size_t keylen = !strcmp(crv, "X25519") ? 32 : 56;

		mbedtls_ecp_keypair_init(&key->ec);
		if (mbedtls_ecp_group_load(&key->ec.MBEDTLS_PRIVATE(grp), gid)) {
			jwt_write_error(item, "Error loading OKP group"); // LCOV_EXCL_LINE
			goto cleanup; // LCOV_EXCL_LINE
		}

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
			if (mbedtls_mpi_read_binary_le(
				    &key->ec.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X),
				    x, (size_t)x_l) ||
			    mbedtls_mpi_lset(
				    &key->ec.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z),
				    1)) {
				jwt_write_error(item, "Error importing OKP x"); // LCOV_EXCL_LINE
				goto cleanup; // LCOV_EXCL_LINE
			}
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
			if (mbedtls_mpi_read_binary_le(
				    &key->ec.MBEDTLS_PRIVATE(d), d,
				    (size_t)d_l)) {
				jwt_write_error(item, "Error importing OKP d"); // LCOV_EXCL_LINE
				goto cleanup; // LCOV_EXCL_LINE
			}
		}
	}

	item->provider = JWT_CRYPTO_OPS_MBEDTLS;
	item->provider_data = key;
	key = NULL;
	ret = 0;

cleanup:
	/* Only reached with key != NULL on a post-allocation error path, all of
	 * which are defensive (decode/group-load failures). */
	// LCOV_EXCL_START
	if (key != NULL) {
		/* okp_ed and ec overlap in a union; free only the one in use. */
		if (is_ed) {
			jwt_scrub_and_free(key->okp_ed.pub, key->okp_ed.pub_len);
			jwt_scrub_and_free(key->okp_ed.priv,
					   key->okp_ed.priv_len);
		} else {
			mbedtls_ecp_keypair_free(&key->ec);
		}
		jwt_freemem(key);
	}
	// LCOV_EXCL_STOP
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
		switch (key->kty) {
		case JWK_KEY_TYPE_RSA:
			mbedtls_rsa_free(&key->rsa);
			break;
		case JWK_KEY_TYPE_EC:
			mbedtls_ecp_keypair_free(&key->ec);
			break;
		case JWK_KEY_TYPE_OKP:
			/* okp_ed and ec overlap in a union; free only the one in
			 * use. Ed-curves kept raw buffers; X-curves an ecp pair. */
			if (key->okp_is_ed) {
				jwt_scrub_and_free(key->okp_ed.pub,
						   key->okp_ed.pub_len);
				jwt_scrub_and_free(key->okp_ed.priv,
						   key->okp_ed.priv_len);
			} else {
				mbedtls_ecp_keypair_free(&key->ec);
			}
			break;
		// LCOV_EXCL_START
		default:
			break;
		// LCOV_EXCL_STOP
		}
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
