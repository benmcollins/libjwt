/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>
#include "jwt-private.h"

/* RFC-7517 4.3 */
static jwk_key_op_t jwk_key_op_j(jwt_json_t *j_op)
{
	const char *op;

	if (!j_op || !jwt_json_is_string(j_op))
		return JWK_KEY_OP_NONE;

	op = jwt_json_str_val(j_op);

	/* Should not be possible for this to happen. */
	if (op == NULL)
		return JWK_KEY_OP_NONE; // LCOV_EXCL_LINE

	if (!strcmp(op, "sign"))
		return JWK_KEY_OP_SIGN;
	else if (!strcmp(op, "verify"))
		return JWK_KEY_OP_VERIFY;
	else if (!strcmp(op, "encrypt"))
		return JWK_KEY_OP_ENCRYPT;
	else if (!strcmp(op, "decrypt"))
		return JWK_KEY_OP_DECRYPT;
	else if (!strcmp(op, "wrapKey"))
		return JWK_KEY_OP_WRAP;
	else if (!strcmp(op, "unwrapKey"))
		return JWK_KEY_OP_UNWRAP;
	else if (!strcmp(op, "deriveKey"))
		return JWK_KEY_OP_DERIVE_KEY;
	else if (!strcmp(op, "deriveBits"))
		return JWK_KEY_OP_DERIVE_BITS;

	/* Ignore all others as the spec says other values may be used. */
	return JWK_KEY_OP_NONE;
}

/* @rfc{7517,4.9} base64url(SHA-256(@der)) — the "x5t#S256" thumbprint of a
 * certificate. Returns a malloc'd string the caller frees, or NULL on error. */
static char *cert_x5t_s256(const unsigned char *der, size_t der_len)
{
	unsigned char hash[32];
	unsigned int hlen = 0;
	char *b64 = NULL;

	if (jwt_ops->sha == NULL ||
	    jwt_ops->sha(256, der, der_len, hash, &hlen) || hlen != sizeof(hash))
		return NULL; // LCOV_EXCL_LINE

	if (jwt_base64uri_encode(&b64, (char *)hash, (int)hlen) <= 0)
		return NULL; // LCOV_EXCL_LINE

	return b64;
}

/* A view of DER octets that are still to be read: @p[0] to @p[@len - 1]. */
struct der {
	const unsigned char *p;
	size_t len;
};

/* Take the element at the front of @in, which must have the single-octet tag
 * @tag and a definite length in its shortest form (DER) that fits in @in. On
 * success @out is its contents and @in is what follows it; otherwise neither
 * is changed. Returns 0 on success. */
static int der_get(struct der *in, unsigned char tag, struct der *out)
{
	const unsigned char *p = in->p;
	size_t left = in->len, len, n, i;

	if (left < 2 || p[0] != tag)
		return 1;

	len = p[1];
	p += 2;
	left -= 2;

	if (len & 0x80) {
		/* Long form: 1 to 3 more octets hold the length (0 would be
		 * the indefinite form), which must need that many: no leading
		 * zero octet, and 128 or more. */
		n = len & 0x7f;
		if (n < 1 || n > 3 || n > left || p[0] == 0)
			return 1;

		for (len = 0, i = 0; i < n; i++)
			len = (len << 8) | p[i];
		if (len < 0x80)
			return 1;

		p += n;
		left -= n;
	}

	if (len > left)
		return 1;

	out->p = p;
	out->len = len;
	in->p = p + len;
	in->len = left - len;

	return 0;
}

/* Take an INTEGER that is not negative from the front of @in: as der_get(),
 * and the first octet has its top bit clear and is zero only where the value
 * needs that as its sign octet. Returns 0 on success. */
static int der_get_uint(struct der *in, struct der *out)
{
	return der_get(in, 0x02, out) || out->len == 0 || (out->p[0] & 0x80) ||
	       (out->len > 1 && out->p[0] == 0 && !(out->p[1] & 0x80));
}

/* @rfc{5280,4.1} Walk the certificate @cert to its SubjectPublicKeyInfo. On
 * success @alg is the contents of its AlgorithmIdentifier (the algorithm OID,
 * then any parameters) and @key is the subjectPublicKey. The other fields are
 * stepped over by tag and length, and what follows the key inside the
 * tbsCertificate is not read. No name, date, extension or signature is looked
 * at: validating the certificate and its chain is left to the caller of
 * jwks_item_x5c(). Returns 0 on success. */
static int x5c_cert_spki(struct der cert, struct der *alg, struct der *key)
{
	/* serialNumber, signature, issuer, validity, subject */
	static const unsigned char tags[] = { 0x02, 0x30, 0x30, 0x30, 0x30 };
	struct der body, tbs, spki, skip;
	size_t i;

	/* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
	 * signatureValue }, and nothing after it. */
	if (der_get(&cert, 0x30, &body) || cert.len ||
	    der_get(&body, 0x30, &tbs) || der_get(&body, 0x30, &skip) ||
	    der_get(&body, 0x03, &skip) || body.len)
		return 1;

	/* A version 1 certificate has no version [0]. If this fails, the
	 * serialNumber is looked for in the same place. */
	(void)der_get(&tbs, 0xa0, &skip);

	for (i = 0; i < ARRAY_SIZE(tags); i++) {
		if (der_get(&tbs, tags[i], &skip))
			return 1;
	}

	/* SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
	 * subjectPublicKey BIT STRING }. A BIT STRING starts with its count
	 * of unused bits, which is 0 for every kind of key. */
	if (der_get(&tbs, 0x30, &spki) || der_get(&spki, 0x30, alg) ||
	    der_get(&spki, 0x03, key) || spki.len ||
	    key->len < 1 || key->p[0] != 0)
		return 1;

	key->p++;
	key->len--;

	return 0;
}

/* What a SubjectPublicKeyInfo has to be for each "crv" (EC, OKP) and "alg"
 * (AKP): the contents of its AlgorithmIdentifier, which DER can write in one
 * way only (the algorithm OID and, for EC, the OID of the named curve), and
 * the length of the key. */
static const struct {
	jwk_key_type_t kty;
	const char *name;
	size_t key_len;
	size_t alg_len;
	unsigned char alg[19];
} x5c_spkis[] = {
	/* @rfc{5480,2} id-ecPublicKey and a named curve; 04 || X || Y. */
	{ JWK_KEY_TYPE_EC, "P-256", 65, 19,
	  { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
	    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 } },
	{ JWK_KEY_TYPE_EC, "P-384", 97, 16,
	  { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
	    0x2b, 0x81, 0x04, 0x00, 0x22 } },
	{ JWK_KEY_TYPE_EC, "P-521", 133, 16,
	  { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
	    0x2b, 0x81, 0x04, 0x00, 0x23 } },
	{ JWK_KEY_TYPE_EC, "secp256k1", 65, 16,
	  { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
	    0x2b, 0x81, 0x04, 0x00, 0x0a } },
	/* @rfc{8410,3} No parameters; the key as it is. */
	{ JWK_KEY_TYPE_OKP, "X25519", 32, 5, { 0x06, 0x03, 0x2b, 0x65, 0x6e } },
	{ JWK_KEY_TYPE_OKP, "X448", 56, 5, { 0x06, 0x03, 0x2b, 0x65, 0x6f } },
	{ JWK_KEY_TYPE_OKP, "Ed25519", 32, 5,
	  { 0x06, 0x03, 0x2b, 0x65, 0x70 } },
	{ JWK_KEY_TYPE_OKP, "Ed448", 57, 5, { 0x06, 0x03, 0x2b, 0x65, 0x71 } },
	/* id-ml-dsa-44, -65 and -87 (2.16.840.1.101.3.4.3.17 to 19): no
	 * parameters; the key as it is. */
	{ JWK_KEY_TYPE_AKP, "ML-DSA-44", 1312, 11,
	  { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
	    0x11 } },
	{ JWK_KEY_TYPE_AKP, "ML-DSA-65", 1952, 11,
	  { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
	    0x12 } },
	{ JWK_KEY_TYPE_AKP, "ML-DSA-87", 2592, 11,
	  { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
	    0x13 } },
};

/* The string member @name of @jwk, or "" if it has none. */
static const char *x5c_member(jwt_json_t *jwk, const char *name)
{
	jwt_json_t *val = jwt_json_obj_get(jwk, name);

	if (val == NULL || !jwt_json_is_string(val))
		return "";

	return jwt_json_str_val(val);
}

/* An unsigned big-endian integer without its leading zero octets. */
static struct der x5c_uint(struct der val)
{
	while (val.len && val.p[0] == 0) {
		val.p++;
		val.len--;
	}

	return val;
}

/* Non-zero if the base64url member @name of @jwk decodes to the octets @want
 * or, with @is_uint, to the same unsigned integer: every backend reads "n",
 * "e" and the EC "x" and "y" as numbers, and not every producer pads them.
 * The values are public, so the compare need not be constant-time. */
static int x5c_member_eq(jwt_json_t *jwk, const char *name, struct der want,
			 int is_uint)
{
	unsigned char *bin;
	struct der have;
	int len = 0, ret;

	bin = jwt_base64uri_decode(x5c_member(jwk, name), &len);
	if (bin == NULL)
		return 0;

	have.p = bin;
	have.len = (size_t)len;
	if (is_uint) {
		have = x5c_uint(have);
		want = x5c_uint(want);
	}

	ret = have.len == want.len && !memcmp(have.p, want.p, want.len);
	jwt_freemem(bin);

	return ret;
}

/* Non-zero if the SubjectPublicKeyInfo (@alg, @key) holds the public key that
 * the members of @jwk represent. */
static int x5c_spki_matches(jwt_json_t *jwk, const jwk_item_t *item,
			    struct der alg, struct der key)
{
	int akp = item->kty == JWK_KEY_TYPE_AKP;
	const char *name;
	size_t i;

	if (item->kty == JWK_KEY_TYPE_RSA) {
		/* @rfc{4055,1.2} rsaEncryption (1.2.840.113549.1.1.1) or
		 * id-RSASSA-PSS (1.2.840.113549.1.1.10), whose parameters
		 * do not change the key: RSAPublicKey ::= SEQUENCE {
		 * modulus INTEGER, publicExponent INTEGER } */
		static const unsigned char oid[] = { 0x06, 0x09, 0x2a, 0x86,
			0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01 };
		struct der seq, n, e;

		if (alg.len <= sizeof(oid) || memcmp(alg.p, oid, sizeof(oid)) ||
		    (alg.p[sizeof(oid)] != 0x01 && alg.p[sizeof(oid)] != 0x0a))
			return 0;

		if (der_get(&key, 0x30, &seq) || key.len ||
		    der_get_uint(&seq, &n) || der_get_uint(&seq, &e) || seq.len)
			return 0;

		return x5c_member_eq(jwk, "n", n, 1) &&
		       x5c_member_eq(jwk, "e", e, 1);
	}

	/* The others are told apart by "crv", or for AKP (ML-DSA) by "alg". */
	name = x5c_member(jwk, akp ? "alg" : "crv");
	for (i = 0; i < ARRAY_SIZE(x5c_spkis); i++) {
		if (x5c_spkis[i].kty == item->kty &&
		    !strcmp(x5c_spkis[i].name, name))
			break;
	}

	if (i == ARRAY_SIZE(x5c_spkis) || key.len != x5c_spkis[i].key_len ||
	    alg.len != x5c_spkis[i].alg_len ||
	    memcmp(alg.p, x5c_spkis[i].alg, alg.len))
		return 0;

	if (item->kty == JWK_KEY_TYPE_EC) {
		/* @rfc{5480,2.2} The uncompressed point only: 04, then X and
		 * Y, which are each half of what is left. */
		struct der x = { key.p + 1, key.len / 2 };
		struct der y = { x.p + x.len, x.len };

		return key.p[0] == 0x04 && x5c_member_eq(jwk, "x", x, 1) &&
		       x5c_member_eq(jwk, "y", y, 1);
	}

	return x5c_member_eq(jwk, akp ? "pub" : "x", key, 0);
}

/* @rfc{7517,4.7} "The key in the first certificate MUST match the public key
 * represented by other members of the JWK." Otherwise anyone can put another
 * party's certificate chain, which is public, on a key of their own. Compare
 * the SubjectPublicKeyInfo of the leaf with the members of the JWK, and mark
 * the item in error if they differ or cannot be compared. */
static void jwk_check_x5c_leaf(jwt_json_t *jwk, jwk_item_t *item)
{
	struct der cert = { item->x5c[0].der, item->x5c[0].len };
	struct der alg, key;

	/* A certificate holds a public key, never a shared secret. */
	if (item->kty == JWK_KEY_TYPE_OCT) {
		jwt_write_error(item,
			"Invalid JWK: \"x5c\" is not valid for an \"oct\" key");
		return;
	}

	if (x5c_cert_spki(cert, &alg, &key)) {
		jwt_write_error(item,
			"Invalid JWK: \"x5c\" leaf is not a valid certificate");
		return;
	}

	if (!x5c_spki_matches(jwk, item, alg, key))
		jwt_write_error(item,
			"\"x5c\" leaf certificate does not match the JWK's key");
}

/* @rfc{7517,4.7} Decode the "x5c" certificate chain (standard base64 DER) into
 * item->x5c. If "x5t#S256" is also present it MUST match the leaf cert's SHA-256
 * thumbprint (@rfc{7517,4.9}), and the leaf MUST hold the JWK's own public key;
 * a mismatch of either marks the item in error. */
static void jwk_process_x5c(jwt_json_t *jwk, jwk_item_t *item)
{
	jwt_json_t *j_x5c, *j_cert, *j_x5t256;
	size_t i, count;

	j_x5c = jwt_json_obj_get(jwk, "x5c");
	/* A JSON null member is treated as absent, the same on both JSON
	 * backends: json-c already hands out a null as NULL, while Jansson
	 * would otherwise see json_null() here and flag the key "not an array",
	 * a cross-backend divergence (an in-error key is never used). */
	if (j_x5c == NULL || jwt_json_is_null(j_x5c))
		return;
	if (!jwt_json_is_array(j_x5c)) {
		jwt_write_error(item, "Invalid JWK: \"x5c\" is not an array");
		return;
	}

	count = jwt_json_arr_size(j_x5c);
	if (count == 0)
		return;

	item->x5c = jwt_malloc(count * sizeof(struct jwk_cert));
	if (item->x5c == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error allocating memory for x5c");
		return;
		// LCOV_EXCL_STOP
	}
	memset(item->x5c, 0, count * sizeof(struct jwk_cert));

	jwt_json_arr_foreach(j_x5c, i, j_cert) {
		const char *b64;
		size_t blen;

		if (!jwt_json_is_string(j_cert)) {
			jwt_write_error(item,
				"Invalid JWK: \"x5c\" entry is not a string");
			return;
		}

		b64 = jwt_json_str_val(j_cert);
		blen = strlen(b64);
		/* Decoded DER is at most 3/4 of the base64 length. */
		item->x5c[i].der = jwt_malloc(blen ? blen : 1);
		if (item->x5c[i].der == NULL) {
			// LCOV_EXCL_START
			jwt_write_error(item,
				"Error allocating memory for x5c");
			return;
			// LCOV_EXCL_STOP
		}
		item->x5c_count = i + 1;
		item->x5c[i].len = base64_decode(b64, (unsigned int)blen,
						 item->x5c[i].der);
		if (item->x5c[i].len == 0) {
			jwt_write_error(item,
				"Invalid JWK: \"x5c\" entry is not valid base64");
			return;
		}
	}

	j_x5t256 = jwt_json_obj_get(jwk, "x5t#S256");
	if (j_x5t256 != NULL && jwt_json_is_string(j_x5t256)) {
		char_auto *computed =
			cert_x5t_s256(item->x5c[0].der, item->x5c[0].len);
		const char *stated = jwt_json_str_val(j_x5t256);

		if (computed == NULL || strcmp(computed, stated))
			jwt_write_error(item,
				"\"x5t#S256\" does not match the \"x5c\" leaf certificate");
	}

	/* A key already in error stays as it is, with its first message. */
	if (!item->error)
		jwk_check_x5c_leaf(jwk, item);
}

static void jwk_process_values(jwt_json_t *jwk, jwk_item_t *item)
{
	jwt_json_t *j_use, *j_ops_a, *j_kid, *j_alg;

	/* Start with the ALG (4.4). A JSON null "alg" is treated as absent, the
	 * same on both JSON backends (see jwk_process_x5c()): Jansson would
	 * otherwise flag "Invalid alg type" where json-c reads it as absent. */
	j_alg = jwt_json_obj_get(jwk, "alg");
	if (j_alg && !jwt_json_is_null(j_alg)) {
		if (!jwt_json_is_string(j_alg)) {
			 jwt_write_error(item, "Invalid alg type");
			 return;
		}
		item->alg = jwt_str_alg(jwt_json_str_val(j_alg));
	}

	/* Check for use (4.2). */
	j_use = jwt_json_obj_get(jwk, "use");
	if (j_use && jwt_json_is_string(j_use)) {
		const char *use = jwt_json_str_val(j_use);
		if (!strcmp(use, "sig"))
			item->use = JWK_PUB_KEY_USE_SIG;
		else if (!strcmp(use, "enc"))
			item->use = JWK_PUB_KEY_USE_ENC;
	}

	/* Check for key_ops (4.3). */
	j_ops_a = jwt_json_obj_get(jwk, "key_ops");
	if (j_ops_a && jwt_json_is_array(j_ops_a)) {
		jwt_json_t *j_op;
		size_t i;

		jwt_json_arr_foreach(j_ops_a, i, j_op)
			item->key_ops |= jwk_key_op_j(j_op);;
	}

	/* Key ID (4.5). */
	j_kid = jwt_json_obj_get(jwk, "kid");
	if (j_kid && jwt_json_is_string(j_kid)) {
		const char *kid = jwt_json_str_val(j_kid);
		size_t len = strlen(kid);

		if (len) {
			item->kid = jwt_malloc(len + 1);
			if (item->kid == NULL) {
				// LCOV_EXCL_START
				jwt_write_error(item,
					"Error allocating memory for kid");
				// LCOV_EXCL_STOP
			} else { // LCOV_EXCL_LINE
				memcpy(item->kid, kid, len + 1);
			}
		}
	}

	/* @rfc{7517,4.7,4.9} X.509 certificate chain + thumbprint check. */
	jwk_process_x5c(jwk, item);
}

static int process_octet(jwt_json_t *jwk, jwk_item_t *item)
{
	unsigned char *bin_k = NULL;
	const char *str_k;
	jwt_json_t *k;
	int len_k = 0;

	k = jwt_json_obj_get(jwk, "k");
	if (k == NULL || !jwt_json_is_string(k)) {
		jwt_write_error(item, "Invalid JWK: missing `k`");
		return -1;
	}

	str_k = jwt_json_str_val(k);
	if (str_k == NULL || !strlen(str_k)) {
		jwt_write_error(item, "Invalid JWK: invalid `k`");
		return -1;
	}

	bin_k = jwt_base64uri_decode(str_k, &len_k);
	if (bin_k == NULL) {
		/* Reachable: jwt_base64uri_decode returns NULL for a non-base64url
		 * "k" (exercised by test_jwks_oct_invalid_base64). */
		jwt_write_error(item, "Invalid JWK: failed to decode `k`");
		return -1;
	}

	item->is_private_key = 1;
	item->provider = JWT_CRYPTO_OPS_ANY;
	item->oct.key = bin_k;
	item->oct.len = len_k;
	/* Compute in size_t: len_k * 8 in int overflows (UB) for a decoded key
	 * larger than INT_MAX/8, yielding a bogus bit count. len_k > 0 here. */
	item->bits = (size_t)len_k * 8;

	return 0;
}

static jwk_item_t *jwk_process_one(jwk_set_t *jwk_set, jwt_json_t *jwk)
{
	const char *kty;
	jwt_json_t *val;
	jwk_item_t *item;

	item = jwt_malloc(sizeof(*item));
	if (item == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(jwk_set,
			"Error allocating memory for jwk_item_t");
		return NULL;
		// LCOV_EXCL_STOP
	}

	memset(item, 0, sizeof(*item));
	/* json-c hands out a JSON null array element as NULL: make it an
	 * empty object, which fails below as Jansson's null does. */
	item->json = jwk ? jwt_json_clone(jwk) : jwt_json_create();
	if (item->json == NULL) {
		// LCOV_EXCL_START
		/* Only free what this function owns: the jwk_item_t allocated
		 * above. "jwk" is a borrowed reference into the caller-owned
		 * parsed JSON tree (j_all or an array element) and must not be
		 * freed here; doing so with jwt_freemem() (a raw free of a live,
		 * refcounted json object) would corrupt that tree and double-free
		 * it when the caller releases it. item->json is NULL here. */
		jwt_freemem(item);
		jwt_write_error(jwk_set,
			"Error allocating memory for jwk_item_t");
		return NULL;
		// LCOV_EXCL_STOP
	}

	val = jwt_json_obj_get(item->json, "kty");
	if (val == NULL || !jwt_json_is_string(val)) {
		jwt_write_error(item, "Invalid JWK: missing kty value");
		return item;
	}

	kty = jwt_json_str_val(val);

	if (!strcmp(kty, "EC")) {
		item->kty = JWK_KEY_TYPE_EC;
		jwt_ops->process_ec(item->json, item);
	} else if (!strcmp(kty, "RSA")) {
		item->kty = JWK_KEY_TYPE_RSA;
		jwt_ops->process_rsa(item->json, item);
	} else if (!strcmp(kty, "OKP")) {
		item->kty = JWK_KEY_TYPE_OKP;
		jwt_ops->process_eddsa(item->json, item);
	} else if (!strcmp(kty, "AKP")) {
		/* "AKP" is recognised in every build, so a public AKP key keeps
		 * its type and its public form (jwks_export() minus "priv")
		 * rather than falling to the unknown-type branch below, which
		 * would strip nothing and leak the seed. Only a build with an
		 * ML-DSA backend can load it; otherwise it stays in error. */
		item->kty = JWK_KEY_TYPE_AKP;
#ifdef LIBJWT_HAVE_ML_DSA
		/* Unlike the other process_* ops, process_mldsa may be NULL:
		 * only backends with ML-DSA support set it. Fail cleanly
		 * rather than dereferencing a NULL pointer. */
		if (jwt_ops->process_mldsa == NULL) {
			jwt_write_error(item, "ML-DSA (AKP) keys are not "
					"supported by the %s backend",
					jwt_ops->name);
			return item;
		}
		jwt_ops->process_mldsa(item->json, item);
#else
		jwt_write_error(item, "ML-DSA (AKP) keys are not "
				"supported in this build");
		return item;
#endif
	} else if (!strcmp(kty, "oct")) {
		item->kty = JWK_KEY_TYPE_OCT;
		process_octet(item->json, item);
	} else {
		jwt_write_error(item, "Unknown or unsupported kty type '%s'", kty);
		return item;
	}

	/* No backend bound a key to the item, so it failed to load, whether
	 * or not the parser said why. Flag it, and leave nothing on it that a
	 * later check could take for a usable key. */
	if (item->provider == JWT_CRYPTO_OPS_NONE) {
		jwt_write_error(item, "Failed to load key");
		item->bits = 0;
		item->is_private_key = 0;
	}

	jwk_process_values(item->json, item);

	return item;
}

const jwk_item_t *jwks_item_get(const jwk_set_t *jwk_set, size_t index)
{
	jwk_item_t *item = NULL;
	size_t i = 0;

	if (jwk_set == NULL)
		return NULL;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (i == index)
			return item;
		i++;
	}

	return NULL;
}

int jwks_error_any(const jwk_set_t *jwk_set)
{
	jwk_item_t *item = NULL;
	int count;

	if (jwk_set == NULL)
		return 1;

	count = jwk_set->error;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (item->error)
			count++;
	}

	return count;
}

int jwks_item_is_private(const jwk_item_t *item)
{
	return item->is_private_key ? 1 : 0;
}

int jwks_item_error(const jwk_item_t *item)
{
	return item->error;
}

const char *jwks_item_error_msg(const jwk_item_t *item)
{
	return item->error_msg;
}

const char *jwks_item_curve(const jwk_item_t *item)
{
	return item->curve[0] ? item->curve : NULL;
}

const char *jwks_item_kid(const jwk_item_t *item)
{
	return item->kid;
}

jwt_alg_t jwks_item_alg(const jwk_item_t *item)
{
	return item->alg;
}

jwk_key_type_t jwks_item_kty(const jwk_item_t *item)
{
	return item->kty;
}

jwk_pub_key_use_t jwks_item_use(const jwk_item_t *item)
{
	return item->use;
}

jwk_key_op_t jwks_item_key_ops(const jwk_item_t *item)
{
	return item->key_ops;
}

const char *jwks_item_pem(const jwk_item_t *item)
{
	return item->pem;
}

/* A key in error vouches for nothing: its chain may be cut short or not be
 * this key's at all, and its certificate thumbprints were not, or could not
 * be, checked against it. All of these read as absent. */
size_t jwks_item_x5c_count(const jwk_item_t *item)
{
	return item->error ? 0 : item->x5c_count;
}

const unsigned char *jwks_item_x5c(const jwk_item_t *item, size_t index,
				   size_t *len)
{
	if (item->error || item->x5c == NULL || index >= item->x5c_count)
		return NULL;

	if (len != NULL)
		*len = item->x5c[index].len;

	return item->x5c[index].der;
}

const char *jwks_item_x5t(const jwk_item_t *item)
{
	jwt_json_t *j = (item->json && !item->error) ?
		jwt_json_obj_get(item->json, "x5t") : NULL;

	return (j != NULL && jwt_json_is_string(j)) ? jwt_json_str_val(j) : NULL;
}

const char *jwks_item_x5t_s256(const jwk_item_t *item)
{
	jwt_json_t *j = (item->json && !item->error) ?
		jwt_json_obj_get(item->json, "x5t#S256") : NULL;

	return (j != NULL && jwt_json_is_string(j)) ? jwt_json_str_val(j) : NULL;
}

int jwks_item_key_bits(const jwk_item_t *item)
{
	return item->bits;
}

int jwks_item_key_oct(const jwk_item_t *item, const unsigned char **buf,
		      size_t *len)
{
	if (!item->oct.key || !item->oct.len)
		return 1;

	*buf = item->oct.key;
	*len = item->oct.len;

	return 0;
}

int jwks_error(const jwk_set_t *jwk_set)
{
	if (jwk_set == NULL)
		return 1;

	return jwk_set->error ? 1 : 0;
}

const char *jwks_error_msg(const jwk_set_t *jwk_set)
{
	if (jwk_set == NULL)
		return NULL;

	return jwk_set->error_msg;
}

void jwks_error_clear(jwk_set_t *jwk_set)
{
	if (jwk_set == NULL)
		return;

	jwk_set->error = 0;
	memset(jwk_set->error_msg, 0, sizeof(jwk_set->error_msg));
}

static int jwks_item_add(jwk_set_t *jwk_set, jwk_item_t *item)
{
	list_add_tail(&item->node, &jwk_set->head);

	return 0;
}

jwk_item_t *jwks_find_bykid(jwk_set_t *jwk_set, const char *kid)
{
	jwk_item_t *item = NULL;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (item->kid == NULL || strcmp(item->kid, kid))
			continue;
		return item;
        }

	return NULL;
}

static void __item_free(jwk_item_t *todel)
{
	if (todel->provider == JWT_CRYPTO_OPS_ANY) {
		jwt_scrub_and_free(todel->oct.key, todel->oct.len);
	} else {
		/* Free the provider_data via the backend that PARSED the key, not
		 * the active ops (#327, completing #320): a key parsed under one
		 * backend may be freed while another is active, and only its origin
		 * backend can release its EVP_PKEY / GnuTLS key / PSA handle. */
		struct jwt_crypto_ops *ops = jwt_item_ops(todel);

		if (ops != NULL)
			ops->process_item_free(todel);
	}

	/* A few non-crypto specific things. */
	jwt_freemem(todel->kid);
	if (todel->x5c != NULL) {
		size_t i;

		for (i = 0; i < todel->x5c_count; i++)
			jwt_freemem(todel->x5c[i].der);
		jwt_freemem(todel->x5c);
	}
	jwt_json_releasep(&todel->json);
	list_del(&todel->node);

	/* Free the container and the item itself. */
	jwt_freemem(todel);
}

int jwks_item_free(jwk_set_t *jwk_set, const size_t index)
{
	jwk_item_t *item = NULL, *todel = NULL;
	size_t i = 0;

	if (jwk_set == NULL)
		return 0;

	list_for_each_entry(item, &jwk_set->head, node) {
		if (i == index) {
			todel = item;
			break;
		}
		i++;
	}

	if (todel == NULL)
		return 0;

	__item_free(todel);

	return 1;
}

size_t jwks_item_count(const jwk_set_t *jwk_set)
{
	size_t count = 0;
	jwk_item_t *item = NULL;

	list_for_each_entry(item, &jwk_set->head, node)
		count++;

	return count;
}

int jwks_item_free_bad(jwk_set_t *jwk_set)
{
	jwk_item_t *item, *pos;
	int count = 0;

	list_for_each_entry_safe(item, pos, &jwk_set->head, node) {
		if (!item->error)
			continue;
		__item_free(item);
		count++;
	}

	return count;
}

int jwks_item_free_all(jwk_set_t *jwk_set)
{
	int i;

	if (jwk_set == NULL)
		return 0;

	for (i = 0; jwks_item_free(jwk_set, 0); i++)
		/* do nothing */;

	return i;
}

void jwks_free(jwk_set_t *jwk_set)
{
	if (jwk_set == NULL)
		return;

	jwks_item_free_all(jwk_set);
	if (jwk_set->cache != NULL) {
		jwt_freemem(jwk_set->cache->url);
		jwt_freemem(jwk_set->cache->etag);
		jwt_freemem(jwk_set->cache);
	}
	jwt_freemem(jwk_set);
}

static jwk_set_t *jwks_new(void)
{
	jwk_set_t *jwk_set;

	jwk_set = jwt_malloc(sizeof *jwk_set);
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	memset(jwk_set, 0, sizeof(*jwk_set));
	INIT_LIST_HEAD(&jwk_set->head);

	return jwk_set;
}

static jwk_set_t *jwks_process(jwk_set_t *jwk_set, jwt_json_t *j_all, jwt_json_error_t *error)
{
	jwt_json_t *j_array = NULL, *j_item = NULL;
	jwk_item_t *jwk_item;
	size_t i;

	if (j_all == NULL) {
		jwt_write_error(jwk_set, "%s: %s", error->source, error->text);
		return jwk_set;
	}

        /* Check for "keys" as in a JWKS */
        j_array = jwt_json_obj_get(j_all, "keys");

        if (j_array == NULL) {
                /* Assume a single JSON Object for one JWK */
                jwk_item = jwk_process_one(jwk_set, j_all);
                if (jwk_item != NULL)
                        jwks_item_add(jwk_set, jwk_item);
        } else {
                /* We have a list, so parse them all. */
                jwt_json_arr_foreach(j_array, i, j_item) {
                        jwk_item = jwk_process_one(jwk_set, j_item);
                        if (jwk_item != NULL)
                                jwks_item_add(jwk_set, jwk_item);
                }
        }

        return jwk_set;
}

static jwk_set_t *__jwks_load_strn(jwk_set_t *jwk_set, const char *jwk_json_str,
				   const size_t len, int empty_allowed)
{
	jwt_json_auto_t *j_all = NULL;
	jwt_json_error_t error;

	if (jwk_json_str == NULL && !empty_allowed)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Just an empty set */
	if (jwk_json_str == NULL)
		return jwk_set;

	/* Parse the JSON string. */
	j_all = jwt_json_parse_buf(jwk_json_str, len, JWT_JSON_DECODE_ANY, &error);

	return jwks_process(jwk_set, j_all, &error);
}

jwk_set_t *jwks_load_strn(jwk_set_t *jwk_set, const char *jwk_json_str,
			  const size_t len)
{
	return __jwks_load_strn(jwk_set, jwk_json_str, len, 0);
}

jwk_set_t *jwks_load(jwk_set_t *jwk_set, const char *jwk_json_str)
{
	size_t len;

	if (jwk_json_str == NULL)
		return NULL;

	len = strlen(jwk_json_str);

	return __jwks_load_strn(jwk_set, jwk_json_str, len, 0);
}

jwk_set_t *jwks_load_fromfile(jwk_set_t *jwk_set, const char *file_name)
{
	jwt_json_auto_t *j_all = NULL;
	jwt_json_error_t error;

	if (file_name == NULL)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Parse the JSON string. */
	j_all = jwt_json_parse_file(file_name, JWT_JSON_DECODE_ANY, &error);

	return jwks_process(jwk_set, j_all, &error);
}

jwk_set_t *jwks_load_fromfp(jwk_set_t *jwk_set, FILE *input)
{
	jwt_json_auto_t *j_all = NULL;
	jwt_json_error_t error;

	if (input == NULL)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Parse the JSON string. */
	j_all = jwt_json_parse_fp(input, JWT_JSON_DECODE_ANY, &error);

	return jwks_process(jwk_set, j_all, &error);
}

jwk_set_t *jwks_create(const char *jwk_json_str)
{
	int len = 0;

	if (jwk_json_str != NULL)
		len = strlen(jwk_json_str);

	return __jwks_load_strn(NULL, jwk_json_str, len, 1);
}

jwk_set_t *jwks_create_strn(const char *jwk_json_str, const size_t len)
{
	return jwks_load_strn(NULL, jwk_json_str, len);
}

jwk_set_t *jwks_create_fromfile(const char *file_name)
{
	return jwks_load_fromfile(NULL, file_name);
}

jwk_set_t *jwks_create_fromfp(FILE *input)
{
	return jwks_load_fromfp(NULL, input);
}

/* Run each JWK JSON object produced by the key2jwk backend op through the same
 * per-item path used for a parsed JWKS, so the resulting jwk_item_t is built
 * identically. */
static void jwks_process_array(jwk_set_t *jwk_set, jwt_json_t *j_array)
{
	jwk_item_t *jwk_item;
	jwt_json_t *j_item;
	size_t i;

	jwt_json_arr_foreach(j_array, i, j_item) {
		jwk_item = jwk_process_one(jwk_set, j_item);
		if (jwk_item != NULL)
			jwks_item_add(jwk_set, jwk_item);
	}
}

jwk_set_t *jwks_load_fromkey(jwk_set_t *jwk_set, const char *key,
			     const size_t len, unsigned int flags)
{
	jwt_json_auto_t *j_array = NULL;

	if (key == NULL || len == 0)
		return NULL;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	j_array = jwt_json_create_arr();
	if (j_array == NULL)
		return jwk_set; // LCOV_EXCL_LINE

	if (jwt_key2jwk(key, len, flags, j_array)) {
		jwt_write_error(jwk_set, "Could not parse key as PEM, DER, "
				"or HMAC");
		return jwk_set;
	}

	jwks_process_array(jwk_set, j_array);

	return jwk_set;
}

jwk_set_t *jwks_load_fromkey_file(jwk_set_t *jwk_set, const char *file_name,
				  unsigned int flags)
{
	jwk_set_t *ret;
	char *buf;
	size_t len;
	long size;
	FILE *fp;

	if (file_name == NULL)
		return NULL;

	fp = fopen(file_name, "rb");
	if (fp == NULL)
		return NULL;

	if (fseek(fp, 0, SEEK_END) || (size = ftell(fp)) < 0) {
		// LCOV_EXCL_START
		fclose(fp);
		return NULL;
		// LCOV_EXCL_STOP
	}
	rewind(fp);

	buf = jwt_malloc(size);
	if (buf == NULL) {
		// LCOV_EXCL_START
		fclose(fp);
		return NULL;
		// LCOV_EXCL_STOP
	}

	len = fread(buf, 1, size, fp);
	fclose(fp);

	if (len != (size_t)size) {
		// LCOV_EXCL_START
		jwt_freemem(buf);
		return NULL;
		// LCOV_EXCL_STOP
	}

	ret = jwks_load_fromkey(jwk_set, buf, len, flags);

	jwt_freemem(buf);

	return ret;
}

jwk_set_t *jwks_create_fromkey(const char *key, const size_t len,
			       unsigned int flags)
{
	return jwks_load_fromkey(NULL, key, len, flags);
}

jwk_set_t *jwks_create_fromkey_file(const char *file_name, unsigned int flags)
{
	return jwks_load_fromkey_file(NULL, file_name, flags);
}

/* Set a string member (helper for the generated-oct JWK). 0 on success. */
static int jwk_set_str(jwt_json_t *obj, const char *key, const char *val)
{
	jwt_json_t *v = jwt_json_create_str(val);

	if (v == NULL || jwt_json_obj_set(obj, key, v))
		return 1; // LCOV_EXCL_LINE

	return 0;
}

/* Generate a symmetric "oct" key: CSPRNG bytes -> {kty:oct, k, [alg]} -> the
 * normal load path (process_octet, provider=ANY). Bits from @param or @alg. */
static void jwks_generate_oct(jwk_set_t *jwk_set, const char *param,
			      jwt_alg_t alg, unsigned int flags)
{
	jwt_json_auto_t *arr = NULL;
	jwt_json_t *jwk;
	unsigned char *buf = NULL;
	char_auto *b64 = NULL;
	long bits;
	int blen;

	if (param != NULL && param[0] != '\0') {
		char *end;

		bits = strtol(param, &end, 10);
		if (*end != '\0') {
			jwt_write_error(jwk_set, "Invalid oct key size [%s]", param);
			return;
		}
	} else {
		bits = (alg == JWT_ALG_HS384) ? 384 :
		       (alg == JWT_ALG_HS512) ? 512 : 256;
	}

	if (bits < 112 || bits % 8) {
		jwt_write_error(jwk_set,
			"oct key size must be a multiple of 8 and >= 112");
		return;
	}

	buf = jwt_malloc((size_t)bits / 8);
	if (buf == NULL)
		return; // LCOV_EXCL_LINE
	if (jwt_ops->rng == NULL || jwt_ops->rng(buf, (size_t)bits / 8)) {
		// LCOV_EXCL_START
		jwt_scrub_and_free(buf, (size_t)bits / 8);
		jwt_write_error(jwk_set, "Random generation failed");
		return;
		// LCOV_EXCL_STOP
	}

	blen = jwt_base64uri_encode(&b64, (char *)buf, (int)(bits / 8));
	jwt_scrub_and_free(buf, (size_t)bits / 8);
	if (blen <= 0)
		return; // LCOV_EXCL_LINE

	arr = jwt_json_create_arr();
	jwk = jwt_json_create();
	if (arr == NULL || jwk == NULL || jwt_json_arr_append(arr, jwk))
		return; // LCOV_EXCL_LINE

	if (jwk_set_str(jwk, "kty", "oct") || jwk_set_str(jwk, "k", b64) ||
	    (alg != JWT_ALG_NONE && jwk_set_str(jwk, "alg", jwt_alg_str(alg))))
		return; // LCOV_EXCL_LINE

	jwt_gen_kid(jwk, JWK_KEY_TYPE_OCT, flags);
	jwks_process_array(jwk_set, arr);
}

jwk_set_t *jwks_generate(jwk_set_t *jwk_set, jwk_key_type_t kty,
			 const char *param, jwt_alg_t alg, unsigned int flags)
{
	jwt_json_auto_t *arr = NULL;
	char *pem = NULL;
	size_t pem_len = 0;

	if (jwk_set == NULL)
		jwk_set = jwks_new();
	if (jwk_set == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Anti-confusion: a stated alg must match the key type (GHSA-q843...). */
	if (alg != JWT_ALG_NONE && jwt_alg_required_kty(alg) != kty) {
		jwt_write_error(jwk_set,
			"Algorithm does not match the requested key type");
		return jwk_set;
	}

	if (kty == JWK_KEY_TYPE_OCT) {
		jwks_generate_oct(jwk_set, param, alg, flags);
		return jwk_set;
	}

	/* Asymmetric: generate a native key (PEM) via the active backend, then
	 * run the existing key2jwk -> load pipeline (binds provider_data). */
	if (jwt_ops->generate_pem == NULL) {
		jwt_write_error(jwk_set,
			"Key generation is not supported by the %s backend",
			jwt_ops->name);
		return jwk_set;
	}

	if (jwt_ops->generate_pem(kty, param, alg, &pem, &pem_len) || pem == NULL) {
		jwt_write_error(jwk_set,
			"Could not generate a key for the requested type");
		jwt_scrub_and_free(pem, pem_len);
		return jwk_set;
	}

	arr = jwt_json_create_arr();
	if (arr == NULL) {
		jwt_scrub_and_free(pem, pem_len); // LCOV_EXCL_LINE
		return jwk_set; // LCOV_EXCL_LINE
	}

	if (jwt_key2jwk(pem, pem_len, flags, arr)) {
		jwt_write_error(jwk_set, "Could not export the generated key");
		jwt_scrub_and_free(pem, pem_len);
		return jwk_set;
	}
	jwt_scrub_and_free(pem, pem_len);

	/* Record the caller's alg (the in-key PEM cannot encode PS384/PS512 vs
	 * PS256, and pins the ML-DSA variant) before parsing it into an item. */
	if (alg != JWT_ALG_NONE) {
		jwt_json_t *jwk0 = jwt_json_arr_get(arr, 0);

		if (jwk0 != NULL && jwk_set_str(jwk0, "alg", jwt_alg_str(alg)))
			return jwk_set; // LCOV_EXCL_LINE
	}

	jwks_process_array(jwk_set, arr);

	return jwk_set;
}

jwk_set_t *jwks_create_generate(jwk_key_type_t kty, const char *param,
				jwt_alg_t alg, unsigned int flags)
{
	return jwks_generate(NULL, kty, param, alg, flags);
}

/* Every member that is private in some key type: RSA (@rfc{7518,6.3.2}, "oth"
 * too), EC and OKP ("d"), oct ("k") and AKP ("priv"). None of them is a public
 * member of another type. */
static const char *const jwk_priv_names[] = { "d", "p", "q", "dp", "dq", "qi",
					      "oth", "k", "priv", NULL };

/* Whether a JWK JSON object has a member that is private in some key type,
 * whatever its value (a JSON null too): what a public export strips. Such a
 * JWK is not the public form of a key, even one that a backend also loaded as
 * a public key by leaving a private member it could not read aside. */
int jwk_json_has_private(const jwt_json_t *jwk)
{
	size_t i;

	for (i = 0; jwk_priv_names[i] != NULL; i++) {
		if (jwt_json_obj_has(jwk, jwk_priv_names[i]))
			return 1;
	}

	return 0;
}

/* Strip the JWK JSON object @jwk (a clone of @item's) down to @item's public
 * form, in place. Returns non-zero, with nothing stripped, for a key that has
 * no public form. */
static int jwk_strip_private(jwt_json_t *jwk, const jwk_item_t *item)
{
	/* All of jwk_priv_names go, whatever @kty is: a key in error need not
	 * be what its "kty" says, and an RSA private key labelled "EC" must not
	 * keep its primes. */
	const char *const *members = jwk_priv_names;
	size_t i;

	/* What is private in a key is known for these types only. A key of
	 * any other type has no public form: that is a key whose "kty" was
	 * missing, not a string, or not known to this build. A known type
	 * also means that @jwk is an object, which the deletes below rely on
	 * (json-c crashes on anything else). */
	switch (item->kty) {
	case JWK_KEY_TYPE_EC:
	case JWK_KEY_TYPE_RSA:
	case JWK_KEY_TYPE_OKP:
	case JWK_KEY_TYPE_OCT:
	case JWK_KEY_TYPE_AKP:
		break;
	default:
		return 1;
	}

	for (i = 0; members[i] != NULL; i++)
		jwt_json_obj_del(jwk, members[i]);

	/* A key in error (a foreign "x5c", an "x5t#S256" that is not its leaf's)
	 * must not hand out in its public form the X.509 binding it was flagged
	 * for: the accessors already read as absent for such a key, so a relay
	 * cannot republish the rejected binding from it either. */
	if (item->error) {
		static const char *const certs[] = { "x5c", "x5t", "x5t#S256",
						     "x5u", NULL };

		for (i = 0; certs[i] != NULL; i++)
			jwt_json_obj_del(jwk, certs[i]);
	}

	return 0;
}

char *jwks_item_export(const jwk_item_t *item, int priv)
{
	jwt_json_auto_t *clone = NULL;

	if (item == NULL || item->json == NULL)
		return NULL;

	clone = jwt_json_clone(item->json);
	if (clone == NULL)
		return NULL; // LCOV_EXCL_LINE

	if (!priv && jwk_strip_private(clone, item))
		return NULL;

	return jwt_json_serialize(clone, JWT_JSON_INDENT(2));
}

char *jwks_export(const jwk_set_t *jwk_set, int priv)
{
	jwt_json_auto_t *root = NULL;
	jwt_json_t *keys;
	jwk_item_t *item;

	if (jwk_set == NULL)
		return NULL;

	root = jwt_json_create();
	if (root == NULL)
		return NULL; // LCOV_EXCL_LINE

	keys = jwt_json_create_arr();
	if (keys == NULL)
		return NULL; // LCOV_EXCL_LINE
	jwt_json_obj_set(root, "keys", keys);

	list_for_each_entry(item, &jwk_set->head, node) {
		jwt_json_t *clone;

		if (item->json == NULL)
			continue; // LCOV_EXCL_LINE

		clone = jwt_json_clone(item->json);
		if (clone == NULL)
			continue; // LCOV_EXCL_LINE

		/* A key with no public form is left out of a public set. */
		if (!priv && jwk_strip_private(clone, item)) {
			jwt_json_release(clone);
			continue;
		}

		jwt_json_arr_append(keys, clone);
	}

	return jwt_json_serialize(root, JWT_JSON_INDENT(2));
}

/* @rfc{7638,3} The required members for the JWK thumbprint, per key type. The
 * thumbprint is the hash of a JSON object containing ONLY these members, with
 * no whitespace and the member names in lexicographic order. The array is
 * NULL-terminated; an unknown kty returns an empty list (a hard error). */
static const char **jwk_thumbprint_members(jwk_key_type_t kty)
{
	static const char *ec[]  = { "crv", "kty", "x", "y", NULL };
	static const char *rsa[] = { "e", "kty", "n", NULL };
	static const char *okp[] = { "crv", "kty", "x", NULL };
	static const char *oct[] = { "k", "kty", NULL };
	static const char *none[] = { NULL };
#ifdef LIBJWT_HAVE_ML_DSA
	static const char *akp[] = { "alg", "kty", "pub", NULL };
#endif

	switch (kty) {
	case JWK_KEY_TYPE_EC:
		return ec;
	case JWK_KEY_TYPE_RSA:
		return rsa;
	case JWK_KEY_TYPE_OKP:
		return okp;
	case JWK_KEY_TYPE_OCT:
		return oct;
#ifdef LIBJWT_HAVE_ML_DSA
	case JWK_KEY_TYPE_AKP:
		return akp;
#endif
	default:
		return none; // LCOV_EXCL_LINE
	}
}

char *jwt_jwk_thumbprint(const jwt_json_t *jwk, jwk_key_type_t kty, int bits)
{
	jwt_json_auto_t *canon = NULL;
	char_auto *json = NULL;
	const char **members;
	unsigned char dig[64];
	unsigned int dig_len = 0;
	char *out = NULL;
	size_t i;

	if (jwk == NULL)
		return NULL;

	/* A valid key always has a supported kty, so the member list is never
	 * empty here; guard defensively anyway. */
	members = jwk_thumbprint_members(kty);
	if (members[0] == NULL)
		return NULL; // LCOV_EXCL_LINE

	/* Build a fresh object with ONLY the required members, cloned from the
	 * key, then serialize it sorted + compact. This reuses the exact
	 * canonicalization the library already trusts for signing (and is
	 * identical across the Jansson and json-c backends), so we neither
	 * hand-order keys nor hand-escape values. */
	canon = jwt_json_create();
	if (canon == NULL)
		return NULL; // LCOV_EXCL_LINE

	for (i = 0; members[i] != NULL; i++) {
		jwt_json_t *val = jwt_json_obj_get(jwk, members[i]);
		jwt_json_t *cval;

		if (val == NULL || !jwt_json_is_string(val))
			return NULL;

		cval = jwt_json_clone(val);
		if (cval == NULL)
			return NULL; // LCOV_EXCL_LINE

		/* obj_set steals the reference to cval. */
		jwt_json_obj_set(canon, members[i], cval);
	}

	json = jwt_json_serialize(canon, JWT_JSON_SORT_KEYS | JWT_JSON_COMPACT);
	if (json == NULL)
		return NULL; // LCOV_EXCL_LINE

	if (jwt_ops->sha == NULL ||
	    jwt_ops->sha(bits, (const unsigned char *)json, strlen(json),
			 dig, &dig_len))
		return NULL; // LCOV_EXCL_LINE

	if (jwt_base64uri_encode(&out, (const char *)dig, (int)dig_len) <= 0)
		return NULL; // LCOV_EXCL_LINE

	return out;
}

char *jwks_item_thumbprint(const jwk_item_t *item, jwk_thumbprint_alg_t alg)
{
	int bits;

	if (item == NULL || item->error || item->json == NULL)
		return NULL;

	switch (alg) {
	case JWK_THUMBPRINT_SHA256:
		bits = 256;
		break;
	case JWK_THUMBPRINT_SHA384:
		bits = 384;
		break;
	case JWK_THUMBPRINT_SHA512:
		bits = 512;
		break;
	default:
		return NULL;
	}

	return jwt_jwk_thumbprint(item->json, item->kty, bits);
}

char *jwks_item_thumbprint_uri(const jwk_item_t *item, jwk_thumbprint_alg_t alg)
{
	char_auto *tp = NULL;
	const char *label;
	char *out = NULL;
	size_t len;

	/* @rfc{9278} maps the hash to a "sha-NNN" name from the RFC 6920
	 * Named Information Hash Algorithm registry. */
	switch (alg) {
	case JWK_THUMBPRINT_SHA256:
		label = "sha-256";
		break;
	case JWK_THUMBPRINT_SHA384:
		label = "sha-384";
		break;
	case JWK_THUMBPRINT_SHA512:
		label = "sha-512";
		break;
	default:
		return NULL;
	}

	tp = jwks_item_thumbprint(item, alg);
	if (tp == NULL)
		return NULL;

	len = strlen("urn:ietf:params:oauth:jwk-thumbprint:") + strlen(label)
	      + 1 + strlen(tp) + 1;
	out = jwt_malloc(len);
	if (out == NULL)
		return NULL; // LCOV_EXCL_LINE

	snprintf(out, len, "urn:ietf:params:oauth:jwk-thumbprint:%s:%s",
		 label, tp);

	return out;
}

jwk_item_t *jwks_find_bythumbprint(jwk_set_t *jwk_set, jwk_thumbprint_alg_t alg,
				   const char *thumbprint)
{
	jwk_item_t *item;

	if (jwk_set == NULL || thumbprint == NULL)
		return NULL;

	list_for_each_entry(item, &jwk_set->head, node) {
		char_auto *tp = jwks_item_thumbprint(item, alg);

		if (tp != NULL && !strcmp(tp, thumbprint))
			return item;
	}

	return NULL;
}

jwk_item_t *jwks_find_bythumbprint_uri(jwk_set_t *jwk_set, const char *uri)
{
	static const char prefix[] = "urn:ietf:params:oauth:jwk-thumbprint:";
	jwk_thumbprint_alg_t alg;

	if (jwk_set == NULL || uri == NULL)
		return NULL;

	/* @rfc{9278}: urn:ietf:params:oauth:jwk-thumbprint:sha-NNN:<thumbprint> */
	if (strncmp(uri, prefix, strlen(prefix)))
		return NULL;
	uri += strlen(prefix);

	if (!strncmp(uri, "sha-256:", 8))
		alg = JWK_THUMBPRINT_SHA256;
	else if (!strncmp(uri, "sha-384:", 8))
		alg = JWK_THUMBPRINT_SHA384;
	else if (!strncmp(uri, "sha-512:", 8))
		alg = JWK_THUMBPRINT_SHA512;
	else
		return NULL;
	uri += 8;

	return jwks_find_bythumbprint(jwk_set, alg, uri);
}
