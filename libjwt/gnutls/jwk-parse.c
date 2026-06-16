/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-gnutls.h"

/* base64url-decode a JWK string member into a gnutls_datum_t. The datum's
 * data is a jwt_malloc'd buffer the caller frees with jwt_freemem(d->data). */
static int decode_member(jwt_json_t *jwk, const char *name, gnutls_datum_t *d)
{
	jwt_json_t *val = jwt_json_obj_get(jwk, name);
	const char *str;
	int len = 0;

	d->data = NULL;
	d->size = 0;

	if (val == NULL || !jwt_json_is_string(val))
		return 1;

	str = jwt_json_str_val(val);
	if (str == NULL || !strlen(str))
		return 1;

	d->data = jwt_base64uri_decode(str, &len);
	if (d->data == NULL || len <= 0) {
		jwt_freemem(d->data);
		d->data = NULL;
		return 1;
	}
	d->size = (unsigned int)len;

	return 0;
}

/* Map a JWK "crv" to a GnuTLS ECC curve id (NIST + OKP). */
static gnutls_ecc_curve_t ec_crv_to_curve(const char *crv)
{
	if (!strcmp(crv, "P-256"))
		return GNUTLS_ECC_CURVE_SECP256R1;
	if (!strcmp(crv, "P-384"))
		return GNUTLS_ECC_CURVE_SECP384R1;
	if (!strcmp(crv, "P-521"))
		return GNUTLS_ECC_CURVE_SECP521R1;
	/* GnuTLS does not support secp256k1 (ES256K). */
	if (!strcmp(crv, "X25519"))
		return GNUTLS_ECC_CURVE_X25519;
	if (!strcmp(crv, "X448"))
		return GNUTLS_ECC_CURVE_X448;
	if (!strcmp(crv, "Ed25519"))
		return GNUTLS_ECC_CURVE_ED25519;
	if (!strcmp(crv, "Ed448"))
		return GNUTLS_ECC_CURVE_ED448;

	return GNUTLS_ECC_CURVE_INVALID;
}

/* Attach the RSA-OAEP-256 (SHA-256) SPKI to a private key. Done once at parse
 * time so the native RSA-OAEP-256 decrypt op can use the key without mutating
 * it per call (avoiding a data race when one key decrypts concurrently). The
 * SPKI is idempotent and does not affect JWS, which re-imports from item->pem.
 * Best effort: a failure here just leaves decrypt to surface the error. */
static void set_rsa_oaep_spki(gnutls_privkey_t priv)
{
	gnutls_x509_spki_t spki = NULL;

	if (gnutls_x509_spki_init(&spki))
		return; // LCOV_EXCL_LINE
	if (!gnutls_x509_spki_set_rsa_oaep_params(spki, GNUTLS_DIG_SHA256, NULL))
		gnutls_privkey_set_spki(priv, spki, 0);
	gnutls_x509_spki_deinit(spki);
}

/* Export item->pem from the parsed key (public PEM for public keys, private
 * PEM otherwise). Failure is non-fatal: pem is an optional convenience exposed
 * via jwks_item_pem() and used by the jwk2key tool. */
static void set_pem(jwk_item_t *item, gnutls_jwk_t *key, int priv)
{
	gnutls_datum_t out = { NULL, 0 };
	char *dest;

	if (priv) {
		gnutls_x509_privkey_t x509 = NULL;

		if (gnutls_privkey_export_x509(key->priv, &x509))
			return; // LCOV_EXCL_LINE
		/* PKCS#8 ("BEGIN PRIVATE KEY") round-trips for every key type,
		 * including EdDSA/OKP — the plain PKCS#1/SEC1 export emits a
		 * "BEGIN UNKNOWN" blob for OKP that cannot be re-imported. */
		if (gnutls_x509_privkey_export2_pkcs8(x509, GNUTLS_X509_FMT_PEM,
						      NULL, 0, &out)) {
			gnutls_x509_privkey_deinit(x509); // LCOV_EXCL_LINE
			return; // LCOV_EXCL_LINE
		}
		gnutls_x509_privkey_deinit(x509);
	} else {
		if (gnutls_pubkey_export2(key->pub, GNUTLS_X509_FMT_PEM, &out))
			return; // LCOV_EXCL_LINE
	}

	dest = jwt_malloc(out.size + 1);
	if (dest != NULL) {
		memcpy(dest, out.data, out.size);
		dest[out.size] = '\0';
		item->pem = dest;
	}

	gnutls_free(out.data);
}

/* Canonical key bit length. EC/OKP curves report their defined size (e.g.
 * P-521 is 521, not the 528 GnuTLS rounds to); RSA uses the modulus size.
 * jwt.c validates these exact values for the EC/EdDSA signing algs. */
static unsigned int key_bits(jwk_item_t *item, gnutls_jwk_t *key)
{
	unsigned int bits = 0;

	if (key->kty == JWK_KEY_TYPE_EC || key->kty == JWK_KEY_TYPE_OKP) {
		const char *crv = item->curve;

		if (!strcmp(crv, "P-256"))
			return 256;
		if (!strcmp(crv, "P-384"))
			return 384;
		if (!strcmp(crv, "P-521"))
			return 521;
		if (!strcmp(crv, "Ed25519") || !strcmp(crv, "X25519"))
			return 256;
		if (!strcmp(crv, "Ed448"))
			return 456;
		if (!strcmp(crv, "X448"))
			return 448;
	}

	gnutls_pubkey_get_pk_algorithm(key->pub, &bits);

	return bits;
}

/* Validate, then finalize a parsed key onto the item: set the bit length and
 * (best effort) the convenience PEM. Returns 0 on success. The validation step
 * (gnutls_pubkey_verify_params) rejects, e.g., an EC point not on the curve or
 * a malformed coordinate that GnuTLS's import accepts but OpenSSL rejects. */
static int finalize(jwk_item_t *item, gnutls_jwk_t *key, int priv)
{
	/* Validate EC/RSA public params (rejects an off-curve EC point or a
	 * malformed coordinate that import accepts but OpenSSL would reject). OKP
	 * keys (both Ed and X curves) are skipped: gnutls_pubkey_verify_params
	 * does not support the X-curve ECDH keys, and the OKP import itself
	 * already validates the key structure. */
	if (key->kty != JWK_KEY_TYPE_OKP && key->kty != JWK_KEY_TYPE_AKP &&
	    gnutls_pubkey_verify_params(key->pub))
		return 1;

	item->bits = key_bits(item, key);

	item->provider = JWT_CRYPTO_OPS_GNUTLS;
	item->provider_data = key;

	set_pem(item, key, priv);

	return 0;
}

/* @rfc{7518,6.3} Native GnuTLS RSA JWK. */
JWT_NO_EXPORT
int gnutls_process_rsa(jwt_json_t *jwk, jwk_item_t *item)
{
	gnutls_datum_t m = {0}, e = {0}, d = {0}, p = {0}, q = {0},
		       u = {0}, e1 = {0}, e2 = {0};
	gnutls_jwk_t *key = NULL;
	jwt_json_t *jd, *jp, *jq, *jdp, *jdq, *jqi;
	int priv = 0, ret = -1;

	if (jwt_json_obj_get(jwk, "n") == NULL ||
	    jwt_json_obj_get(jwk, "e") == NULL) {
		jwt_write_error(item, "Missing required RSA component: n or e");
		goto out;
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
		goto out;
	}

	if (decode_member(jwk, "n", &m) || decode_member(jwk, "e", &e)) {
		jwt_write_error(item, "Error decoding pub components");
		goto out;
	}

	key = jwt_malloc(sizeof(*key));
	if (key == NULL)
		goto out; // LCOV_EXCL_LINE
	memset(key, 0, sizeof(*key));
	key->kty = JWK_KEY_TYPE_RSA;

	if (gnutls_pubkey_init(&key->pub)) {
		jwt_write_error(item, "Error initializing pubkey"); // LCOV_EXCL_LINE
		goto out; // LCOV_EXCL_LINE
	}

	if (priv) {
		/* GnuTLS RSA priv order: m, e, d, p, q, u, e1, e2 — where
		 * u = JWK qi, e1 = JWK dp, e2 = JWK dq. */
		if (decode_member(jwk, "d", &d) || decode_member(jwk, "p", &p) ||
		    decode_member(jwk, "q", &q) || decode_member(jwk, "qi", &u) ||
		    decode_member(jwk, "dp", &e1) ||
		    decode_member(jwk, "dq", &e2)) {
			jwt_write_error(item, "Error decoding priv components");
			goto out;
		}
		if (gnutls_privkey_init(&key->priv) ||
		    gnutls_privkey_import_rsa_raw(key->priv, &m, &e, &d, &p, &q,
						  &u, &e1, &e2)) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing RSA private key");
			goto out;
			// LCOV_EXCL_STOP
		}
		if (gnutls_pubkey_import_privkey(key->pub, key->priv, 0, 0)) {
			jwt_write_error(item, "Error deriving RSA public key"); // LCOV_EXCL_LINE
			goto out; // LCOV_EXCL_LINE
		}
		item->is_private_key = 1;
	} else {
		if (gnutls_pubkey_import_rsa_raw(key->pub, &m, &e)) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing RSA public key");
			goto out;
			// LCOV_EXCL_STOP
		}
	}

	/* finalize()'s gnutls_pubkey_verify_params accepts any RSA key that
	 * imports above, so this never fails for RSA: a defensive guard. */
	if (finalize(item, key, priv)) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error generating pub key from components");
		goto out;
		// LCOV_EXCL_STOP
	}

	/* Attach the RSA-OAEP-256 SPKI to the private key AFTER finalize() has
	 * exported the (unrestricted) item->pem, so JWS sign/verify and the
	 * SHA-1 RSA-OAEP OpenSSL fallback still get a plain RSA PEM. Doing it
	 * once here keeps the native RSA-OAEP-256 decrypt from mutating the
	 * shared key per call (race-free concurrent decrypts). */
	if (priv)
		set_rsa_oaep_spki(key->priv);

	key = NULL;
	ret = 0;

out:
	if (key != NULL) {
		// LCOV_EXCL_START
		if (key->priv)
			gnutls_privkey_deinit(key->priv);
		if (key->pub)
			gnutls_pubkey_deinit(key->pub);
		jwt_freemem(key);
		// LCOV_EXCL_STOP
	}
	jwt_freemem(m.data);
	jwt_freemem(e.data);
	jwt_scrub_and_free(d.data, d.size);
	jwt_scrub_and_free(p.data, p.size);
	jwt_scrub_and_free(q.data, q.size);
	jwt_scrub_and_free(u.data, u.size);
	jwt_scrub_and_free(e1.data, e1.size);
	jwt_scrub_and_free(e2.data, e2.size);

	return ret;
}

/* @rfc{7518,6.2} Native GnuTLS EC JWK (P-256/384/521, secp256k1). */
JWT_NO_EXPORT
int gnutls_process_ec(jwt_json_t *jwk, jwk_item_t *item)
{
	gnutls_datum_t x = {0}, y = {0}, k = {0};
	gnutls_jwk_t *key = NULL;
	jwt_json_t *jcrv, *jx, *jy, *jd;
	const char *crv;
	gnutls_ecc_curve_t curve;
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
		goto out;
	}

	crv = jwt_json_str_val(jcrv);
	strncpy(item->curve, crv, sizeof(item->curve) - 1);
	item->curve[sizeof(item->curve) - 1] = '\0';

	curve = ec_crv_to_curve(crv);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto out;
	}

	if (decode_member(jwk, "x", &x) || decode_member(jwk, "y", &y)) {
		jwt_write_error(item,
			"Error generating pub key from components");
		goto out;
	}

	key = jwt_malloc(sizeof(*key));
	if (key == NULL)
		goto out; // LCOV_EXCL_LINE
	memset(key, 0, sizeof(*key));
	key->kty = JWK_KEY_TYPE_EC;

	if (gnutls_pubkey_init(&key->pub)) {
		jwt_write_error(item, "Error initializing pubkey"); // LCOV_EXCL_LINE
		goto out; // LCOV_EXCL_LINE
	}

	if (jd != NULL && jwt_json_is_string(jd)) {
		if (decode_member(jwk, "d", &k)) {
			jwt_write_error(item, "Error decoding priv component"); // LCOV_EXCL_LINE
			goto out; // LCOV_EXCL_LINE
		}
		if (gnutls_privkey_init(&key->priv) ||
		    gnutls_privkey_import_ecc_raw(key->priv, curve, &x, &y,
						  &k)) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing EC private key");
			goto out;
			// LCOV_EXCL_STOP
		}
		if (gnutls_pubkey_import_privkey(key->pub, key->priv, 0, 0)) {
			jwt_write_error(item, "Error deriving EC public key"); // LCOV_EXCL_LINE
			goto out; // LCOV_EXCL_LINE
		}
		item->is_private_key = priv = 1;
	} else {
		if (gnutls_pubkey_import_ecc_raw(key->pub, curve, &x, &y)) {
			jwt_write_error(item,
				"Error generating pub key from components");
			goto out;
		}
	}

	if (finalize(item, key, priv)) {
		jwt_write_error(item, "Error generating pub key from components");
		goto out;
	}
	key = NULL;
	ret = 0;

out:
	if (key != NULL) {
		if (key->priv)
			gnutls_privkey_deinit(key->priv); // LCOV_EXCL_LINE
		if (key->pub)
			gnutls_pubkey_deinit(key->pub);
		jwt_freemem(key);
	}
	jwt_freemem(x.data);
	jwt_freemem(y.data);
	jwt_scrub_and_free(k.data, k.size);

	return ret;
}

/* @rfc{8037} Native GnuTLS OKP JWK (Ed25519/Ed448 for signing; X25519/X448 for
 * ECDH). GnuTLS imports these via import_ecc_raw with y = NULL and x = the raw
 * native key. */
JWT_NO_EXPORT
int gnutls_process_eddsa(jwt_json_t *jwk, jwk_item_t *item)
{
	gnutls_datum_t x = {0}, k = {0};
	gnutls_jwk_t *key = NULL;
	jwt_json_t *jcrv, *jx, *jd;
	const char *crv;
	gnutls_ecc_curve_t curve;
	int priv = 0, ret = -1;

	jcrv = jwt_json_obj_get(jwk, "crv");
	jx = jwt_json_obj_get(jwk, "x");
	jd = jwt_json_obj_get(jwk, "d");

	if (jcrv == NULL || !jwt_json_is_string(jcrv)) {
		jwt_write_error(item, "No curve component found for OKP key");
		goto out;
	}
	if (jx == NULL && jd == NULL) {
		jwt_write_error(item,
			"Need an 'x' or 'd' component and found neither");
		goto out;
	}

	crv = jwt_json_str_val(jcrv);
	strncpy(item->curve, crv, sizeof(item->curve) - 1);
	item->curve[sizeof(item->curve) - 1] = '\0';

	curve = ec_crv_to_curve(crv);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		jwt_write_error(item, "Unknown curve [%s]", crv);
		goto out;
	}

	if (jx != NULL && jwt_json_is_string(jx) && decode_member(jwk, "x", &x)) {
		jwt_write_error(item, "Error decoding OKP x"); // LCOV_EXCL_LINE
		goto out; // LCOV_EXCL_LINE
	}

	key = jwt_malloc(sizeof(*key));
	if (key == NULL)
		goto out; // LCOV_EXCL_LINE
	memset(key, 0, sizeof(*key));
	key->kty = JWK_KEY_TYPE_OKP;

	if (gnutls_pubkey_init(&key->pub)) {
		jwt_write_error(item, "Error initializing pubkey"); // LCOV_EXCL_LINE
		goto out; // LCOV_EXCL_LINE
	}

	if (jd != NULL && jwt_json_is_string(jd)) {
		if (decode_member(jwk, "d", &k)) {
			jwt_write_error(item, "Error decoding OKP d"); // LCOV_EXCL_LINE
			goto out; // LCOV_EXCL_LINE
		}
		/* OKP: y is NULL; x is the raw public key (may be absent). */
		if (gnutls_privkey_init(&key->priv) ||
		    gnutls_privkey_import_ecc_raw(key->priv, curve,
						  x.data ? &x : NULL, NULL,
						  &k)) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing OKP private key");
			goto out;
			// LCOV_EXCL_STOP
		}
		if (gnutls_pubkey_import_privkey(key->pub, key->priv, 0, 0)) {
			jwt_write_error(item, "Error deriving OKP public key"); // LCOV_EXCL_LINE
			goto out; // LCOV_EXCL_LINE
		}
		item->is_private_key = priv = 1;
	} else {
		if (gnutls_pubkey_import_ecc_raw(key->pub, curve, &x, NULL)) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error importing OKP public key");
			goto out;
			// LCOV_EXCL_STOP
		}
	}

	/* finalize() skips gnutls_pubkey_verify_params for OKP (X-curve keys are
	 * ECDH-only and rejected by it), so it always succeeds here. */
	if (finalize(item, key, priv)) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error generating pub key from components");
		goto out;
		// LCOV_EXCL_STOP
	}
	key = NULL;
	ret = 0;

out:
	/* Reached with key != NULL only on a post-allocation error path, all of
	 * which are defensive (init/import failures). */
	if (key != NULL) {
		// LCOV_EXCL_START
		if (key->priv)
			gnutls_privkey_deinit(key->priv);
		if (key->pub)
			gnutls_pubkey_deinit(key->pub);
		jwt_freemem(key);
		// LCOV_EXCL_STOP
	}
	jwt_freemem(x.data);
	jwt_scrub_and_free(k.data, k.size);

	return ret;
}

#if defined(LIBJWT_HAVE_ML_DSA) && GNUTLS_VERSION_NUMBER >= 0x03080a
/* The three ML-DSA variants: the last byte of the id-ml-dsa-NN OID and the
 * raw public-key length. */
static const struct {
	const char *alg;
	unsigned char oid;
	size_t publen;
} mldsa_variants[] = {
	{ "ML-DSA-44", 0x11, 1312 },
	{ "ML-DSA-65", 0x12, 1952 },
	{ "ML-DSA-87", 0x13, 2592 },
};

/* ML-DSA (FIPS 204 / RFC 9964), @rfc{9964}. GnuTLS has no raw ML-DSA import,
 * so build the encoded key from the JWK's raw "pub" (a SubjectPublicKeyInfo)
 * or 32-byte "priv" seed (a seed-form PKCS#8 using the [0] seed CHOICE) and
 * import that. The DER is a fixed template per variant. */
JWT_NO_EXPORT
int gnutls_process_mldsa(jwt_json_t *jwk, jwk_item_t *item)
{
	gnutls_datum_t pub = { NULL, 0 }, seed = { NULL, 0 };
	gnutls_datum_t spki = { NULL, 0 };
	gnutls_jwk_t *key = NULL;
	jwt_json_t *jalg, *jpub, *jpriv;
	const char *alg;
	int idx = -1, priv = 0, ret = -1;
	size_t i;

	jalg = jwt_json_obj_get(jwk, "alg");
	jpub = jwt_json_obj_get(jwk, "pub");
	jpriv = jwt_json_obj_get(jwk, "priv");

	/* RFC 9964: "alg" is REQUIRED on AKP keys and selects the variant. */
	if (jalg == NULL || !jwt_json_is_string(jalg)) {
		jwt_write_error(item, "ML-DSA (AKP) key missing required 'alg'");
		goto out;
	}
	alg = jwt_json_str_val(jalg);
	for (i = 0; i < sizeof(mldsa_variants) / sizeof(mldsa_variants[0]); i++) {
		if (!strcmp(alg, mldsa_variants[i].alg)) {
			idx = (int)i;
			break;
		}
	}
	if (idx < 0) {
		jwt_write_error(item, "Unsupported AKP alg [%s]", alg);
		goto out;
	}

	if (jpub == NULL && jpriv == NULL) {
		jwt_write_error(item,
			"Need a 'pub' or 'priv' component and found neither");
		goto out;
	}

	key = jwt_malloc(sizeof(*key));
	if (key == NULL)
		goto out; // LCOV_EXCL_LINE
	memset(key, 0, sizeof(*key));
	key->kty = JWK_KEY_TYPE_AKP;

	if (gnutls_pubkey_init(&key->pub)) {
		jwt_write_error(item, "Error initializing pubkey"); // LCOV_EXCL_LINE
		goto out; // LCOV_EXCL_LINE
	}

	if (jpriv != NULL && jwt_json_is_string(jpriv)) {
		/* Private: seed-form PKCS#8 (22-byte template + 32-byte seed). */
		static const unsigned char tmpl[22] = {
			0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06,
			0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
			0x03, 0x00, 0x04, 0x22, 0x80, 0x20
		};
		unsigned char p8[sizeof(tmpl) + 32];
		gnutls_datum_t der;

		if (decode_member(jwk, "priv", &seed)) {
			jwt_write_error(item, "Error decoding ML-DSA priv (seed)");
			goto out;
		}
		if (seed.size != 32) {
			jwt_write_error(item, "ML-DSA priv (seed) must be 32 bytes");
			goto out;
		}
		memcpy(p8, tmpl, sizeof(tmpl));
		p8[17] = mldsa_variants[idx].oid;
		memcpy(p8 + sizeof(tmpl), seed.data, 32);
		der.data = p8;
		der.size = sizeof(p8);

		if (gnutls_privkey_init(&key->priv) ||
		    gnutls_privkey_import_x509_raw(key->priv, &der,
						   GNUTLS_X509_FMT_DER, NULL, 0)) {
			// LCOV_EXCL_START — any 32-byte seed imports
			jwt_cleanse(p8, sizeof(p8));
			jwt_write_error(item, "Error importing ML-DSA private key");
			goto out;
			// LCOV_EXCL_STOP
		}
		/* The seed now lives in key->priv; wipe the stack copy. */
		jwt_cleanse(p8, sizeof(p8));
		if (gnutls_pubkey_import_privkey(key->pub, key->priv, 0, 0)) {
			jwt_write_error(item, "Error deriving ML-DSA public key"); // LCOV_EXCL_LINE
			goto out; // LCOV_EXCL_LINE
		}
		item->is_private_key = priv = 1;
	} else {
		/* Public: SubjectPublicKeyInfo from the raw public key. */
		size_t publen, bclen, oclen, n;
		unsigned char *b;

		if (jpub == NULL || !jwt_json_is_string(jpub) ||
		    decode_member(jwk, "pub", &pub)) {
			jwt_write_error(item, "Error decoding ML-DSA pub");
			goto out;
		}
		publen = mldsa_variants[idx].publen;
		if (pub.size != publen) {
			jwt_write_error(item, "ML-DSA pub has wrong size");
			goto out;
		}
		bclen = publen + 1;		/* BIT STRING content (unused + key) */
		oclen = 13 + 4 + 1 + publen;	/* algid + bitstr hdr + unused + key */

		spki.data = b = jwt_malloc(4 + oclen);
		if (b == NULL)
			goto out; // LCOV_EXCL_LINE
		n = 0;
		b[n++] = 0x30; b[n++] = 0x82;
		b[n++] = (oclen >> 8) & 0xff; b[n++] = oclen & 0xff;
		b[n++] = 0x30; b[n++] = 0x0b; b[n++] = 0x06; b[n++] = 0x09;
		b[n++] = 0x60; b[n++] = 0x86; b[n++] = 0x48; b[n++] = 0x01;
		b[n++] = 0x65; b[n++] = 0x03; b[n++] = 0x04; b[n++] = 0x03;
		b[n++] = mldsa_variants[idx].oid;
		b[n++] = 0x03; b[n++] = 0x82;
		b[n++] = (bclen >> 8) & 0xff; b[n++] = bclen & 0xff;
		b[n++] = 0x00;
		memcpy(b + n, pub.data, publen);
		spki.size = n + publen;

		if (gnutls_pubkey_import(key->pub, &spki, GNUTLS_X509_FMT_DER)) {
			// LCOV_EXCL_START — a correct-length pub always imports
			jwt_write_error(item, "Error importing ML-DSA public key");
			goto out;
			// LCOV_EXCL_STOP
		}
	}

	if (finalize(item, key, priv)) {
		jwt_write_error(item, "Error finalizing ML-DSA key"); // LCOV_EXCL_LINE
		goto out; // LCOV_EXCL_LINE
	}
	key = NULL;
	ret = 0;

out:
	if (key != NULL) {
		/* key->priv is only set on the (unreachable) private-import
		 * failure; reachable errors leave it NULL. */
		if (key->priv)
			gnutls_privkey_deinit(key->priv); // LCOV_EXCL_LINE
		if (key->pub)
			gnutls_pubkey_deinit(key->pub);
		jwt_freemem(key);
	}
	jwt_freemem(spki.data);
	jwt_freemem(pub.data);
	jwt_scrub_and_free(seed.data, seed.size);

	return ret;
}
#endif /* LIBJWT_HAVE_ML_DSA && GNUTLS >= 3.8.10 */

JWT_NO_EXPORT
void gnutls_process_item_free(jwk_item_t *item)
{
	gnutls_jwk_t *key;

	if (item == NULL || item->provider != JWT_CRYPTO_OPS_GNUTLS)
		return;

	key = item->provider_data;
	if (key != NULL) {
		if (key->priv)
			gnutls_privkey_deinit(key->priv);
		if (key->pub)
			gnutls_pubkey_deinit(key->pub);
		jwt_freemem(key);
	}

	if (item->pem) {
		jwt_cleanse(item->pem, strlen(item->pem));
		jwt_freemem(item->pem);
	}

	item->pem = NULL;
	item->provider_data = NULL;
	item->provider = JWT_CRYPTO_OPS_NONE;
}
