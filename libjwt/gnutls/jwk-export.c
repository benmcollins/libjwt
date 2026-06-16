/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* GnuTLS implementation of the key2jwk_params op: parse a native key (PEM or
 * DER) and extract its raw components into the neutral jwk_export_t. The common
 * jwt_key2jwk() (jwk-export.c) base64url-encodes those into a JWK. This is the
 * inverse of this backend's jwk-parse.c (RSA u=qi, e1=dp, e2=dq; OKP via
 * import_ecc_raw with y=NULL and x=the raw key). */

#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-gnutls.h"

/* Copy @len bytes into a fresh jwt_malloc buffer and add it as JWK member
 * @name (taking ownership for the common code to scrub/free). */
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

/* Add a big-endian integer with leading zero bytes stripped (the minimal
 * encoding JWK uses for RSA integer members). */
static void add_int(jwk_export_t *out, const char *name, const gnutls_datum_t *d)
{
	const unsigned char *p = d->data;
	size_t len = d->size;

	while (len > 1 && p[0] == 0x00) {
		p++;
		len--;
	}

	add_raw(out, name, p, len);
}

/* Add an EC field element, left-padded with zeros to @field bytes per
 * @rfc{7518,6.2.1.2} (a fixed-length octet string, not a minimal integer). */
static void add_fixed(jwk_export_t *out, const char *name,
		      const gnutls_datum_t *d, size_t field)
{
	const unsigned char *p = d->data;
	size_t len = d->size;
	unsigned char *buf;

	while (len > 0 && p[0] == 0x00) {
		p++;
		len--;
	}

	if (len > field)
		return; // LCOV_EXCL_LINE

	buf = jwt_malloc(field);
	if (buf == NULL)
		return; // LCOV_EXCL_LINE

	memset(buf, 0, field);
	if (len)
		memcpy(buf + (field - len), p, len);

	jwk_export_add(out, name, buf, field);
}

/* Load a private key from a PEM or DER blob. Returns 0 and sets *out on
 * success. */
static int load_privkey(const gnutls_datum_t *data, gnutls_privkey_t *out)
{
	gnutls_privkey_t p = NULL;

	if (gnutls_privkey_init(&p) == 0 &&
	    gnutls_privkey_import_x509_raw(p, data, GNUTLS_X509_FMT_PEM,
					   NULL, 0) == 0) {
		*out = p;
		return 0;
	}
	if (p)
		gnutls_privkey_deinit(p);

	p = NULL;
	if (gnutls_privkey_init(&p) == 0 &&
	    gnutls_privkey_import_x509_raw(p, data, GNUTLS_X509_FMT_DER,
					   NULL, 0) == 0) {
		*out = p;
		return 0;
	}
	if (p)
		gnutls_privkey_deinit(p);

	return 1;
}

/* Load a public key from a PEM or DER blob. Returns 0 and sets *out on
 * success. */
static int load_pubkey(const gnutls_datum_t *data, gnutls_pubkey_t *out)
{
	gnutls_pubkey_t p = NULL;

	if (gnutls_pubkey_init(&p) == 0 &&
	    gnutls_pubkey_import(p, data, GNUTLS_X509_FMT_PEM) == 0) {
		*out = p;
		return 0;
	}
	if (p)
		gnutls_pubkey_deinit(p);

	p = NULL;
	if (gnutls_pubkey_init(&p) == 0 &&
	    gnutls_pubkey_import(p, data, GNUTLS_X509_FMT_DER) == 0) {
		*out = p;
		return 0;
	}
	if (p)
		gnutls_pubkey_deinit(p);

	return 1;
}

/* Map a GnuTLS EC curve to its JWK crv/alg and field length. Returns 0 on a
 * supported NIST curve. */
static int ec_curve_info(gnutls_ecc_curve_t curve, char *crv, char *alg,
			 size_t *field)
{
	switch (curve) {
	case GNUTLS_ECC_CURVE_SECP256R1:
		strcpy(crv, "P-256");
		strcpy(alg, "ES256");
		*field = 32;
		return 0;
	case GNUTLS_ECC_CURVE_SECP384R1:
		strcpy(crv, "P-384");
		strcpy(alg, "ES384");
		*field = 48;
		return 0;
	case GNUTLS_ECC_CURVE_SECP521R1:
		strcpy(crv, "P-521");
		strcpy(alg, "ES512");
		*field = 66;
		return 0;
	default:
		/* GnuTLS has no secp256k1 (ES256K). */
		return 1; // LCOV_EXCL_LINE
	}
}

static int export_rsa(gnutls_privkey_t priv, gnutls_pubkey_t pub, int is_priv,
		      jwk_export_t *out)
{
	gnutls_datum_t m = {0}, e = {0}, d = {0}, p = {0}, q = {0},
		       u = {0}, e1 = {0}, e2 = {0};
	int ret = 1;

	if (is_priv) {
		if (gnutls_privkey_export_rsa_raw2(priv, &m, &e, &d, &p, &q,
						   &u, &e1, &e2, 0))
			goto out; // LCOV_EXCL_LINE
	} else {
		if (gnutls_pubkey_export_rsa_raw2(pub, &m, &e, 0))
			goto out; // LCOV_EXCL_LINE
	}

	add_int(out, "n", &m);
	add_int(out, "e", &e);

	if (is_priv) {
		/* GnuTLS u = JWK qi, e1 = JWK dp, e2 = JWK dq (see jwk-parse.c). */
		add_int(out, "d", &d);
		add_int(out, "p", &p);
		add_int(out, "q", &q);
		add_int(out, "dp", &e1);
		add_int(out, "dq", &e2);
		add_int(out, "qi", &u);
	}

	ret = 0;

out:
	gnutls_free(m.data);
	gnutls_free(e.data);
	jwt_cleanse(d.data, d.size);
	gnutls_free(d.data);
	jwt_cleanse(p.data, p.size);
	gnutls_free(p.data);
	jwt_cleanse(q.data, q.size);
	gnutls_free(q.data);
	jwt_cleanse(u.data, u.size);
	gnutls_free(u.data);
	jwt_cleanse(e1.data, e1.size);
	gnutls_free(e1.data);
	jwt_cleanse(e2.data, e2.size);
	gnutls_free(e2.data);

	return ret;
}

static int export_ec(gnutls_privkey_t priv, gnutls_pubkey_t pub, int is_priv,
		     jwk_export_t *out)
{
	gnutls_datum_t x = {0}, y = {0}, k = {0};
	gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_INVALID;
	size_t field = 0;
	int ret = 1;

	if (is_priv) {
		if (gnutls_privkey_export_ecc_raw(priv, &curve, &x, &y, &k))
			goto out; // LCOV_EXCL_LINE
	} else {
		if (gnutls_pubkey_export_ecc_raw(pub, &curve, &x, &y))
			goto out; // LCOV_EXCL_LINE
	}

	if (ec_curve_info(curve, out->crv, out->alg, &field))
		goto out; // LCOV_EXCL_LINE

	add_fixed(out, "x", &x, field);
	add_fixed(out, "y", &y, field);
	if (is_priv)
		add_fixed(out, "d", &k, field);

	ret = 0;

out:
	gnutls_free(x.data);
	gnutls_free(y.data);
	jwt_cleanse(k.data, k.size);
	gnutls_free(k.data);

	return ret;
}

static int export_okp(gnutls_privkey_t priv, gnutls_pubkey_t pub, int is_priv,
		      jwk_export_t *out)
{
	gnutls_datum_t x = {0}, y = {0}, k = {0};
	gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_INVALID;
	int ret = 1;

	if (is_priv) {
		if (gnutls_privkey_export_ecc_raw(priv, &curve, &x, &y, &k))
			goto out; // LCOV_EXCL_LINE

		/* @rfc{8037,2}: an OKP private key carries x (public) and d
		 * (private), both raw octet strings (no leading-zero stripping). */
		add_raw(out, "x", x.data, x.size);
		add_raw(out, "d", k.data, k.size);
	} else {
		if (gnutls_pubkey_export_ecc_raw(pub, &curve, &x, &y))
			goto out; // LCOV_EXCL_LINE

		add_raw(out, "x", x.data, x.size);
	}

	ret = 0;

out:
	gnutls_free(x.data);
	gnutls_free(y.data);
	jwt_cleanse(k.data, k.size);
	gnutls_free(k.data);

	return ret;
}

#if defined(LIBJWT_HAVE_ML_DSA) && GNUTLS_VERSION_NUMBER >= 0x03080a
/* ML-DSA (AKP), @rfc{9964}. GnuTLS has no raw ML-DSA export, so recover the
 * raw public key from the SubjectPublicKeyInfo and the 32-byte seed from a
 * seed-form PKCS#8. Both share the fixed 22-byte ASN.1 prefix that jwk-parse.c
 * builds when importing. */
#define MLDSA_DER_PREFIX 22
static int export_mldsa(gnutls_privkey_t priv, gnutls_pubkey_t pub,
			const gnutls_datum_t *raw, int is_priv,
			jwk_export_t *out)
{
	gnutls_pubkey_t tmp_pub = NULL;
	gnutls_x509_privkey_t x509 = NULL;
	gnutls_datum_t spki = { NULL, 0 }, p8 = { NULL, 0 };
	int ret = 1;

	/* For a private key, derive the pubkey to obtain its SPKI. */
	if (pub == NULL) {
		if (gnutls_pubkey_init(&tmp_pub) ||
		    gnutls_pubkey_import_privkey(tmp_pub, priv, 0, 0))
			goto out; // LCOV_EXCL_LINE
		pub = tmp_pub;
	}

	if (gnutls_pubkey_export2(pub, GNUTLS_X509_FMT_DER, &spki))
		goto out; // LCOV_EXCL_LINE
	if (spki.size <= MLDSA_DER_PREFIX)
		goto out; // LCOV_EXCL_LINE
	add_raw(out, "pub", spki.data + MLDSA_DER_PREFIX,
		spki.size - MLDSA_DER_PREFIX);

	if (is_priv) {
		gnutls_datum_t plain = { NULL, 0 };
		int has_seed;

		/* Recover the 32-byte seed via a seed-form PKCS#8 export (a
		 * 22-byte prefix + the seed). Re-import the original key bytes
		 * directly as an x509: exporting via gnutls_privkey_export_x509()
		 * and then a seed PKCS#8 crashes some GnuTLS/leancrypto builds. */
		if (gnutls_x509_privkey_init(&x509))
			goto out; // LCOV_EXCL_LINE
		if (gnutls_x509_privkey_import(x509, raw, GNUTLS_X509_FMT_PEM) &&
		    gnutls_x509_privkey_import(x509, raw, GNUTLS_X509_FMT_DER))
			goto out; // LCOV_EXCL_LINE

		/* The seed-form export below null-derefs inside GnuTLS on an
		 * expanded-only private key (one carrying no FIPS-204 seed), so
		 * first probe for the seed with a plain PKCS#8 export, which never
		 * crashes. In the "30 82 .. 02 01 00 <algid:13> 04 82 .. <priv>"
		 * structure the private-key content (offset 24) is a SEQUENCE/[0]
		 * (0x30/0x80) when a seed is present, but an OCTET STRING (0x04)
		 * for an expanded-only key. */
		if (gnutls_x509_privkey_export2_pkcs8(x509, GNUTLS_X509_FMT_DER,
						      NULL, GNUTLS_PKCS_PLAIN,
						      &plain))
			goto out; // LCOV_EXCL_LINE
		has_seed = (plain.size > 24 && plain.data[20] == 0x04 &&
			    plain.data[21] == 0x82 &&
			    (plain.data[24] == 0x30 || plain.data[24] == 0x80));
		gnutls_free(plain.data);

		if (!has_seed) {
			/* An expanded-only private key cannot be a private AKP
			 * JWK, so downgrade to a public-only export (matching the
			 * OpenSSL backend) rather than emit a private JWK with no
			 * "priv" — or crash trying. */
			out->is_private = 0;
			ret = 0;
			goto out;
		}

		if (gnutls_x509_privkey_export2_pkcs8(x509, GNUTLS_X509_FMT_DER,
						      NULL, GNUTLS_PKCS_PLAIN |
						      GNUTLS_PKCS_MLDSA_SEED,
						      &p8))
			goto out; // LCOV_EXCL_LINE
		if (p8.size != MLDSA_DER_PREFIX + 32)
			goto out; // LCOV_EXCL_LINE
		add_raw(out, "priv", p8.data + MLDSA_DER_PREFIX, 32);
	}

	ret = 0;

out:
	if (tmp_pub)
		gnutls_pubkey_deinit(tmp_pub);
	if (x509)
		gnutls_x509_privkey_deinit(x509);
	gnutls_free(spki.data);
	jwt_cleanse(p8.data, p8.size);
	gnutls_free(p8.data);

	return ret;
}
#endif /* LIBJWT_HAVE_ML_DSA && GNUTLS >= 3.8.10 */

JWT_NO_EXPORT
int gnutls_key2jwk_params(const char *key, size_t len, jwk_export_t *out)
{
	gnutls_datum_t data;
	gnutls_privkey_t priv = NULL;
	gnutls_pubkey_t pub = NULL;
	unsigned int bits = 0;
	int gpk, is_priv = 0, ret = 1;

	data.data = (unsigned char *)key;
	data.size = (unsigned int)len;

	/* Try a private key first, then a public key (each PEM then DER). */
	if (load_privkey(&data, &priv) == 0) {
		is_priv = 1;
		gpk = gnutls_privkey_get_pk_algorithm(priv, &bits);
	} else if (load_pubkey(&data, &pub) == 0) {
		gpk = gnutls_pubkey_get_pk_algorithm(pub, &bits);
	} else {
		/* Not a parseable key; the common code may try the HMAC fallback. */
		return 1;
	}

	out->is_private = is_priv;

	switch (gpk) {
	case GNUTLS_PK_RSA:
		out->kty = JWK_KEY_TYPE_RSA;
		ret = export_rsa(priv, pub, is_priv, out);
		break;

	case GNUTLS_PK_RSA_PSS:
		/* RSA-PSS is only valid for PS*; default to PS256 like OpenSSL. */
		out->kty = JWK_KEY_TYPE_RSA;
		strcpy(out->alg, "PS256");
		ret = export_rsa(priv, pub, is_priv, out);
		break;

	case GNUTLS_PK_ECDSA:
		out->kty = JWK_KEY_TYPE_EC;
		ret = export_ec(priv, pub, is_priv, out);
		break;

	case GNUTLS_PK_EDDSA_ED25519:
		out->kty = JWK_KEY_TYPE_OKP;
		strcpy(out->crv, "Ed25519");
		strcpy(out->alg, "EdDSA");
		ret = export_okp(priv, pub, is_priv, out);
		break;

	case GNUTLS_PK_EDDSA_ED448:
		out->kty = JWK_KEY_TYPE_OKP;
		strcpy(out->crv, "Ed448");
		strcpy(out->alg, "EdDSA");
		ret = export_okp(priv, pub, is_priv, out);
		break;

#if defined(LIBJWT_HAVE_ML_DSA) && GNUTLS_VERSION_NUMBER >= 0x03080a
	case GNUTLS_PK_MLDSA44:
		out->kty = JWK_KEY_TYPE_AKP;
		strcpy(out->alg, "ML-DSA-44");
		ret = export_mldsa(priv, pub, &data, is_priv, out);
		break;
	case GNUTLS_PK_MLDSA65:
		out->kty = JWK_KEY_TYPE_AKP;
		strcpy(out->alg, "ML-DSA-65");
		ret = export_mldsa(priv, pub, &data, is_priv, out);
		break;
	case GNUTLS_PK_MLDSA87:
		out->kty = JWK_KEY_TYPE_AKP;
		strcpy(out->alg, "ML-DSA-87");
		ret = export_mldsa(priv, pub, &data, is_priv, out);
		break;
#endif

	// LCOV_EXCL_START
	default:
		ret = 1;
		break;
	// LCOV_EXCL_STOP
	}

	if (priv)
		gnutls_privkey_deinit(priv);
	if (pub)
		gnutls_pubkey_deinit(pub);

	return ret;
}
