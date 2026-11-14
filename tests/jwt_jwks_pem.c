/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "jwt_tests.h"

/* Tests for the native-key import API: jwks_load_fromkey(),
 * jwks_load_fromkey_file(), jwks_create_fromkey(), jwks_create_fromkey_file()
 * and the JWK-JSON exporters jwks_item_export() / jwks_export(). These convert
 * a PEM, DER, or raw HMAC key into a JWK and back. */

/* A representative key fixture. */
struct keyspec {
	const char *file;	/* file under tests/keys/pem-files/	*/
	jwk_key_type_t kty;	/* expected key type			*/
	jwt_alg_t alg;		/* expected alg (JWT_ALG_NONE if unset)	*/
	const char *curve;	/* expected curve, or NULL		*/
	int is_private;		/* 1 if a private key			*/
	int es256k;		/* 1 if secp256k1 (skipped on native gnutls) */
};

static const struct keyspec keys[] = {
	{ "rsa_key_2048.pem",       JWK_KEY_TYPE_RSA, JWT_ALG_NONE,  NULL,        1, 0 },
	{ "rsa_key_2048_pub.pem",   JWK_KEY_TYPE_RSA, JWT_ALG_NONE,  NULL,        0, 0 },
	{ "rsa_key_4096.pem",       JWK_KEY_TYPE_RSA, JWT_ALG_NONE,  NULL,        1, 0 },
	{ "rsa_pss_key_2048.pem",   JWK_KEY_TYPE_RSA, JWT_ALG_PS256, NULL,        1, 0 },
	{ "ec_key_prime256v1.pem",  JWK_KEY_TYPE_EC,  JWT_ALG_ES256, "P-256",     1, 0 },
	{ "ec_key_prime256v1_pub.pem", JWK_KEY_TYPE_EC, JWT_ALG_ES256, "P-256",   0, 0 },
	{ "ec_key_secp384r1.pem",   JWK_KEY_TYPE_EC,  JWT_ALG_ES384, "P-384",     1, 0 },
	{ "ec_key_secp521r1.pem",   JWK_KEY_TYPE_EC,  JWT_ALG_ES512, "P-521",     1, 0 },
	{ "ec_key_secp256k1.pem",   JWK_KEY_TYPE_EC,  JWT_ALG_ES256K,"secp256k1", 1, 1 },
	{ "eddsa_key_ed25519.pem",  JWK_KEY_TYPE_OKP, JWT_ALG_EDDSA, "Ed25519",   1, 0 },
	{ "eddsa_key_ed25519_pub.pem", JWK_KEY_TYPE_OKP, JWT_ALG_EDDSA, "Ed25519", 0, 0 },
	{ "eddsa_key_ed448.pem",    JWK_KEY_TYPE_OKP, JWT_ALG_EDDSA, "Ed448",     1, 0 },
};

/* Whether @file (a tests/keys/pem-files fixture) cannot be converted to a JWK
 * by the given backend, so the round-trip test must skip it:
 *  - The GnuTLS backend has no secp256k1 (ES256K) in its native key2jwk, in
 *    any GnuTLS version.
 *  - MbedTLS has no EdDSA, and mbedtls_pk has no OKP representation, so Ed
 *    keys do not parse. It also treats RSA-PSS as plain RSA (no PS256 "alg"
 *    hint), so the rsa_pss fixture's expected alg cannot be reproduced. */
static int skip_key(const char *file, jwt_crypto_provider_t type)
{
	if (strstr(file, "secp256k1") && type == JWT_CRYPTO_OPS_GNUTLS)
		return 1;

	if (type == JWT_CRYPTO_OPS_MBEDTLS &&
	    (strstr(file, "eddsa") || strstr(file, "rsa_pss")))
		return 1;

	return 0;
}

static char *read_file(const char *file, size_t *len_out)
{
	char *path, *buf;
	size_t len;
	long size;
	FILE *fp;
	int ret;

	ret = asprintf(&path, KEYDIR "/pem-files/%s", file);
	ck_assert_int_gt(ret, 0);

	fp = fopen(path, "rb");
	ck_assert_ptr_nonnull(fp);
	free(path);

	ck_assert_int_eq(fseek(fp, 0, SEEK_END), 0);
	size = ftell(fp);
	ck_assert_int_gt(size, 0);
	rewind(fp);

	buf = malloc(size);
	ck_assert_ptr_nonnull(buf);

	len = fread(buf, 1, size, fp);
	ck_assert_int_eq(len, (size_t)size);
	fclose(fp);

	*len_out = len;
	return buf;
}

/* Assert the item matches the expectations in the keyspec. */
static void check_item(const jwk_item_t *item, const struct keyspec *k)
{
	ck_assert_ptr_nonnull(item);
	if (jwks_item_error(item))
		fprintf(stderr, "item error: %s\n", jwks_item_error_msg(item));
	ck_assert_int_eq(jwks_item_error(item), 0);

	ck_assert_int_eq(jwks_item_kty(item), k->kty);
	ck_assert_int_eq(jwks_item_alg(item), k->alg);
	ck_assert_int_eq(jwks_item_is_private(item), k->is_private);

	if (k->curve) {
		ck_assert_ptr_nonnull(jwks_item_curve(item));
		ck_assert_str_eq(jwks_item_curve(item), k->curve);
	}

	/* A PEM string is an optional, backend-dependent courtesy field (the
	 * OpenSSL backend always provides one; MbedTLS may not), so we don't
	 * require it. The bit count, however, must always be set. */
	ck_assert_int_gt(jwks_item_key_bits(item), 0);
}

/* Round-trip every key fixture through jwks_create_fromkey_file(). */
START_TEST(test_fromkey_file)
{
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		jwk_set_auto_t *set = NULL;
		const jwk_item_t *item;
		char *path;
		int ret;

		if (skip_key(keys[i].file, jwt_test_ops[_i].type))
			continue;

		ret = asprintf(&path, KEYDIR "/pem-files/%s", keys[i].file);
		ck_assert_int_gt(ret, 0);

		set = jwks_create_fromkey_file(path, JWK_KEY_NONE);
		free(path);

		ck_assert_ptr_nonnull(set);
		ck_assert_int_eq(jwks_error(set), 0);

		/* Exactly one key per file. */
		ck_assert_int_eq(jwks_item_count(set), 1);

		item = jwks_item_get(set, 0);
		check_item(item, &keys[i]);
	}
}
END_TEST

/* The buffer loader (jwks_load_fromkey) must produce the same result as the
 * file loader. */
START_TEST(test_fromkey_buf)
{
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		jwk_set_auto_t *set = NULL;
		const jwk_item_t *item;
		char *buf;
		size_t len;

		if (skip_key(keys[i].file, jwt_test_ops[_i].type))
			continue;

		buf = read_file(keys[i].file, &len);

		/* Use the create-style wrapper here for coverage. */
		set = jwks_create_fromkey(buf, len, JWK_KEY_NONE);
		free(buf);

		ck_assert_ptr_nonnull(set);
		ck_assert_int_eq(jwks_error(set), 0);
		ck_assert_int_eq(jwks_item_count(set), 1);

		item = jwks_item_get(set, 0);
		check_item(item, &keys[i]);
	}
}
END_TEST

/* DER input must yield the same JWK (same exported JSON) as the matching PEM. */
START_TEST(test_der_matches_pem)
{
	static const char *pairs[][2] = {
		{ "rsa_key_2048.pem",          "rsa_key_2048.der" },
		{ "rsa_key_2048_pub.pem",      "rsa_key_2048_pub.der" },
		{ "ec_key_prime256v1.pem",     "ec_key_prime256v1.der" },
		{ "ec_key_prime256v1_pub.pem", "ec_key_prime256v1_pub.der" },
		{ "eddsa_key_ed25519.pem",     "eddsa_key_ed25519.der" },
		{ "eddsa_key_ed25519_pub.pem", "eddsa_key_ed25519_pub.der" },
	};
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(pairs); i++) {
		jwk_set_auto_t *pset = NULL, *dset = NULL;
		char_auto *pjson = NULL, *djson = NULL;
		char *pbuf, *dbuf;
		size_t plen, dlen;

		if (skip_key(pairs[i][0], jwt_test_ops[_i].type))
			continue;

		pbuf = read_file(pairs[i][0], &plen);
		dbuf = read_file(pairs[i][1], &dlen);

		pset = jwks_load_fromkey(NULL, pbuf, plen, JWK_KEY_NONE);
		dset = jwks_load_fromkey(NULL, dbuf, dlen, JWK_KEY_NONE);
		free(pbuf);
		free(dbuf);

		ck_assert_ptr_nonnull(pset);
		ck_assert_ptr_nonnull(dset);
		ck_assert_int_eq(jwks_error(pset), 0);
		ck_assert_int_eq(jwks_error(dset), 0);

		pjson = jwks_export(pset, 1);
		djson = jwks_export(dset, 1);
		ck_assert_ptr_nonnull(pjson);
		ck_assert_ptr_nonnull(djson);

		/* Same key, same conversion => identical JWK JSON. */
		ck_assert_str_eq(pjson, djson);
	}
}
END_TEST

/* @rfc{7517,3} JWK member values are unpadded base64url, so an exported JWK
 * must never contain the standard-base64 characters '+' or '/' or any padding
 * '='. Export a range of key types (RSA/EC/EdDSA, public and private) and check
 * the whole JSON document is clean. */
START_TEST(test_export_is_base64url)
{
	static const char *keys[] = {
		"rsa_key_2048.pem",
		"rsa_key_2048_pub.pem",
		"ec_key_prime256v1.pem",
		"ec_key_prime256v1_pub.pem",
		"eddsa_key_ed25519.pem",
		"eddsa_key_ed25519_pub.pem",
	};
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		jwk_set_auto_t *set = NULL;
		char_auto *json = NULL;
		char *buf;
		size_t len;

		if (skip_key(keys[i], jwt_test_ops[_i].type))
			continue;

		buf = read_file(keys[i], &len);
		set = jwks_load_fromkey(NULL, buf, len, JWK_KEY_NONE);
		free(buf);

		ck_assert_ptr_nonnull(set);
		ck_assert_int_eq(jwks_error(set), 0);

		json = jwks_export(set, 1);
		ck_assert_ptr_nonnull(json);

		/* No JSON syntax uses '+'/'='; '/' appears only inside member
		 * values, so any occurrence means a non-base64url field. */
		ck_assert_ptr_null(strchr(json, '+'));
		ck_assert_ptr_null(strchr(json, '/'));
		ck_assert_ptr_null(strchr(json, '='));
	}
}
END_TEST

/* JWK_KEY_GEN_KID adds a kid; without it there is none. */
START_TEST(test_gen_kid)
{
	jwk_set_auto_t *with = NULL, *without = NULL;
	const jwk_item_t *item;
	const char *kid;
	char *buf;
	size_t len;

	SET_OPS();

	buf = read_file("rsa_key_2048.pem", &len);

	without = jwks_load_fromkey(NULL, buf, len, JWK_KEY_NONE);
	ck_assert_ptr_nonnull(without);
	ck_assert_int_eq(jwks_error(without), 0);
	item = jwks_item_get(without, 0);
	ck_assert_ptr_null(jwks_item_kid(item));

	with = jwks_load_fromkey(NULL, buf, len, JWK_KEY_GEN_KID);
	free(buf);
	ck_assert_ptr_nonnull(with);
	ck_assert_int_eq(jwks_error(with), 0);
	item = jwks_item_get(with, 0);
	kid = jwks_item_kid(item);
	ck_assert_ptr_nonnull(kid);

	/* The generated kid is the deterministic RFC 7638 SHA-256 thumbprint:
	 * base64url of a 32-byte digest, i.e. 43 chars, and equal to what
	 * jwks_item_thumbprint() computes for the same key. */
	{
		char_auto *tp = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);

		ck_assert_int_eq((int)strlen(kid), 43);
		ck_assert_ptr_nonnull(tp);
		ck_assert_str_eq(kid, tp);
	}
}
END_TEST

/* JWK_KEY_TRY_HMAC turns raw bytes into an oct key; without it they fail. */
START_TEST(test_hmac_fallback)
{
	static const struct {
		const char *file;
		jwt_alg_t alg;
	} octs[] = {
		{ "oct_key_hs256.bin", JWT_ALG_HS256 },
		{ "oct_key_hs384.bin", JWT_ALG_HS384 },
		{ "oct_key_hs512.bin", JWT_ALG_HS512 },
	};
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(octs); i++) {
		jwk_set_auto_t *yes = NULL, *no = NULL;
		const jwk_item_t *item;
		const unsigned char *kbuf;
		size_t klen;
		char *buf;
		size_t len;

		buf = read_file(octs[i].file, &len);

		/* Without the flag, an unparseable key fails. */
		no = jwks_load_fromkey(NULL, buf, len, JWK_KEY_NONE);
		ck_assert_ptr_nonnull(no);
		ck_assert_int_ne(jwks_error(no), 0);

		/* With the flag, it becomes an oct key. */
		yes = jwks_load_fromkey(NULL, buf, len, JWK_KEY_TRY_HMAC);
		free(buf);
		ck_assert_ptr_nonnull(yes);
		ck_assert_int_eq(jwks_error(yes), 0);

		item = jwks_item_get(yes, 0);
		ck_assert_ptr_nonnull(item);
		ck_assert_int_eq(jwks_item_error(item), 0);
		ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_OCT);
		ck_assert_int_eq(jwks_item_alg(item), octs[i].alg);

		/* The octet data must round-trip to the original bytes. */
		ck_assert_int_eq(jwks_item_key_oct(item, &kbuf, &klen), 0);
		ck_assert_int_eq(klen, len);

		/* Exporting an oct key public-only strips the "k" material. */
		{
			char_auto *priv_json = jwks_item_export(item, 1);
			char_auto *pub_json = jwks_item_export(item, 0);

			ck_assert_ptr_nonnull(priv_json);
			ck_assert_ptr_nonnull(pub_json);
			ck_assert_ptr_nonnull(strstr(priv_json, "\"k\""));
			ck_assert_ptr_null(strstr(pub_json, "\"k\""));
		}
	}
}
END_TEST

/* Appending to an existing set keeps prior keys. */
START_TEST(test_append_to_set)
{
	jwk_set_auto_t *set = NULL;
	char *rsa, *ec;
	size_t rsa_len, ec_len;

	SET_OPS();

	rsa = read_file("rsa_key_2048.pem", &rsa_len);
	ec = read_file("ec_key_prime256v1.pem", &ec_len);

	set = jwks_load_fromkey(NULL, rsa, rsa_len, JWK_KEY_NONE);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_item_count(set), 1);

	/* Same set passed back in - should now hold two keys. */
	set = jwks_load_fromkey(set, ec, ec_len, JWK_KEY_NONE);
	free(rsa);
	free(ec);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);
	ck_assert_int_eq(jwks_item_count(set), 2);

	ck_assert_int_eq(jwks_item_kty(jwks_item_get(set, 0)), JWK_KEY_TYPE_RSA);
	ck_assert_int_eq(jwks_item_kty(jwks_item_get(set, 1)), JWK_KEY_TYPE_EC);
}
END_TEST

/* Export then re-import must yield an equivalent, usable key. */
START_TEST(test_export_reimport)
{
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		jwk_set_auto_t *orig = NULL, *round = NULL;
		char_auto *json = NULL;
		const jwk_item_t *item;
		char *buf;
		size_t len;

		if (skip_key(keys[i].file, jwt_test_ops[_i].type))
			continue;

		buf = read_file(keys[i].file, &len);
		orig = jwks_load_fromkey(NULL, buf, len, JWK_KEY_NONE);
		free(buf);
		ck_assert_ptr_nonnull(orig);
		ck_assert_int_eq(jwks_error(orig), 0);

		/* Export a single item, then load it as a normal JWK. */
		json = jwks_item_export(jwks_item_get(orig, 0), keys[i].is_private);
		ck_assert_ptr_nonnull(json);

		round = jwks_create(json);
		ck_assert_ptr_nonnull(round);
		ck_assert_int_eq(jwks_error(round), 0);

		item = jwks_item_get(round, 0);
		check_item(item, &keys[i]);
	}
}
END_TEST

/* jwks_item_export(priv=0) must strip private members. */
START_TEST(test_export_public_only)
{
	jwk_set_auto_t *set = NULL;
	jwk_set_auto_t *pub = NULL;
	char_auto *priv_json = NULL, *pub_json = NULL;
	char *buf;
	size_t len;

	SET_OPS();

	buf = read_file("ec_key_prime256v1.pem", &len);
	set = jwks_load_fromkey(NULL, buf, len, JWK_KEY_NONE);
	free(buf);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);

	/* Private export contains "d"; public export does not. */
	priv_json = jwks_item_export(jwks_item_get(set, 0), 1);
	pub_json = jwks_item_export(jwks_item_get(set, 0), 0);
	ck_assert_ptr_nonnull(priv_json);
	ck_assert_ptr_nonnull(pub_json);

	ck_assert_ptr_nonnull(strstr(priv_json, "\"d\""));
	ck_assert_ptr_null(strstr(pub_json, "\"d\""));

	/* The public-only export must load as a public key. */
	pub = jwks_create(pub_json);
	ck_assert_ptr_nonnull(pub);
	ck_assert_int_eq(jwks_error(pub), 0);
	ck_assert_int_eq(jwks_item_is_private(jwks_item_get(pub, 0)), 0);
}
END_TEST

/* jwks_export() produces a JWKS ("keys" array) that re-parses. */
START_TEST(test_export_set)
{
	jwk_set_auto_t *set = NULL, *round = NULL;
	char_auto *json = NULL;
	char *rsa, *ec;
	size_t rsa_len, ec_len;

	SET_OPS();

	rsa = read_file("rsa_key_2048.pem", &rsa_len);
	ec = read_file("ec_key_prime256v1.pem", &ec_len);
	set = jwks_load_fromkey(NULL, rsa, rsa_len, JWK_KEY_NONE);
	set = jwks_load_fromkey(set, ec, ec_len, JWK_KEY_NONE);
	free(rsa);
	free(ec);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_item_count(set), 2);

	json = jwks_export(set, 1);
	ck_assert_ptr_nonnull(json);
	ck_assert_ptr_nonnull(strstr(json, "\"keys\""));

	round = jwks_create(json);
	ck_assert_ptr_nonnull(round);
	ck_assert_int_eq(jwks_error(round), 0);
	ck_assert_int_eq(jwks_item_count(round), 2);

	/* Public-only set export must strip private members. */
	{
		char_auto *pub_json = jwks_export(set, 0);

		ck_assert_ptr_nonnull(pub_json);
		ck_assert_ptr_null(strstr(pub_json, "\"d\""));
	}
}
END_TEST

/* The value of every private member in the hand-written keys below (it is
 * base64url for "SECRET"). It must never be found in a public form. */
#define SECRET "U0VDUkVU"

/* How many times @needle is found in @hay. */
static int count_str(const char *hay, const char *needle)
{
	int n = 0;

	while ((hay = strstr(hay, needle)) != NULL) {
		hay += strlen(needle);
		n++;
	}

	return n;
}

/* A public form holds no member that is private in some key type, whatever
 * the type of the key it was made from. */
static void check_public_form(const char *json)
{
	static const char *names[] = { "\"d\"", "\"p\"", "\"q\"", "\"dp\"",
		"\"dq\"", "\"qi\"", "\"oth\"", "\"k\"", "\"priv\"" };
	size_t i;

	ck_assert_ptr_nonnull(json);

	for (i = 0; i < ARRAY_SIZE(names); i++)
		ck_assert_msg(strstr(json, names[i]) == NULL,
			      "%s is in a public form: %s", names[i], json);

	ck_assert_msg(strstr(json, SECRET) == NULL,
		      "A private value is in a public form: %s", json);
}

/* Keys whose "kty" LibJWT does not take for a key type: an unknown name, a
 * known one in the wrong case, a "kty" that is not a string, none at all, and
 * a "keys" entry that is not even an object. Each holds SECRET once. */
static const char unknown_keys[] = "{\"keys\":["
	"{\"kty\":\"XYZ\",\"d\":\"" SECRET "\"},"
	"{\"kty\":\"ec\",\"crv\":\"P-256\","
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
	"\"d\":\"" SECRET "\"},"
	"{\"kty\":true,\"k\":\"" SECRET "\"},"
	"{\"k\":\"" SECRET "\"},"
	"[\"" SECRET "\"]]}";
#define UNKNOWN_KEYS 5

/* What is private in a JWK is known only for the key types LibJWT knows, so
 * a key of any other type has no public form: nothing of it comes out of a
 * public export, where the whole JWK used to. It stays in the keyring, in
 * error, and a private export still gives it as it was loaded. */
START_TEST(test_export_unknown_kty)
{
	static const char known_key[] = "{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"}";
	jwk_set_auto_t *set = NULL, *round = NULL, *mixed = NULL;
	char_auto *pub_json = NULL, *priv_json = NULL, *mixed_json = NULL;
	size_t i;

	SET_OPS();

	set = jwks_create(unknown_keys);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);
	ck_assert_int_eq(jwks_item_count(set), UNKNOWN_KEYS);
	ck_assert_int_eq(jwks_error_any(set), UNKNOWN_KEYS);

	for (i = 0; i < UNKNOWN_KEYS; i++) {
		const jwk_item_t *item = jwks_item_get(set, i);
		char_auto *as_loaded = NULL;

		ck_assert_ptr_nonnull(item);
		ck_assert_int_ne(jwks_item_error(item), 0);
		ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_NONE);

		ck_assert_ptr_null(jwks_item_export(item, 0));

		as_loaded = jwks_item_export(item, 1);
		ck_assert_ptr_nonnull(as_loaded);
		ck_assert_int_eq(count_str(as_loaded, SECRET), 1);
	}

	/* The public set leaves them all out, and is still a JWKS. */
	pub_json = jwks_export(set, 0);
	ck_assert_ptr_nonnull(pub_json);
	ck_assert_ptr_null(strstr(pub_json, SECRET));
	ck_assert_ptr_nonnull(strstr(pub_json, "\"keys\""));
	round = jwks_create(pub_json);
	ck_assert_ptr_nonnull(round);
	ck_assert_int_eq(jwks_error(round), 0);
	ck_assert_int_eq(jwks_item_count(round), 0);

	/* The private set has them all. */
	priv_json = jwks_export(set, 1);
	ck_assert_ptr_nonnull(priv_json);
	ck_assert_int_eq(count_str(priv_json, SECRET), UNKNOWN_KEYS);

	/* A key of a known type next to them is alone in the public set. */
	ck_assert_ptr_eq(jwks_load(set, known_key), set);
	ck_assert_int_eq(jwks_item_count(set), UNKNOWN_KEYS + 1);
	mixed_json = jwks_export(set, 0);
	check_public_form(mixed_json);
	mixed = jwks_create(mixed_json);
	ck_assert_ptr_nonnull(mixed);
	ck_assert_int_eq(jwks_error(mixed), 0);
	ck_assert_int_eq(jwks_item_count(mixed), 1);
	ck_assert_int_eq(jwks_item_kty(jwks_item_get(mixed, 0)),
			 JWK_KEY_TYPE_EC);
}
END_TEST

/* jwt_builder_setcnf_jwk() embeds the public form of a key. A key of unknown
 * type has none, and it is in error besides, which is refused before its
 * public form is asked for. Either way nothing of it gets into the "cnf" claim,
 * where such a key used to go whole. An earlier "cnf" is left as it was. */
START_TEST(test_setcnf_jwk_unknown_kty)
{
	jwk_set_auto_t *set = NULL;
	jwt_builder_auto_t *builder = NULL;
	jwt_value_t jval;
	size_t i;

	SET_OPS();

	set = jwks_create(unknown_keys);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_item_count(set), UNKNOWN_KEYS);

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setcnf(builder, "kid", "kept"), 0);

	for (i = 0; i < UNKNOWN_KEYS; i++) {
		const jwk_item_t *item = jwks_item_get(set, i);

		ck_assert_ptr_nonnull(item);
		ck_assert_int_ne(jwt_builder_setcnf_jwk(builder, item), 0);
	}

	jwt_set_GET_JSON(&jval, "cnf");
	ck_assert_int_eq(jwt_builder_claim_get(builder, &jval),
			 JWT_VALUE_ERR_NONE);
	ck_assert_ptr_nonnull(jval.json_val);
	ck_assert_str_eq(jval.json_val, "{\"kid\":\"kept\"}");
	free(jval.json_val);
}
END_TEST

/* A public key of a known type that also carries members private in ANOTHER
 * type (an EC key with "k", "p" and "priv") loads with no error and is embedded
 * by jwt_builder_setcnf_jwk(); the public form it embeds holds none of them, so
 * a foreign private member cannot ride into the "cnf" claim. (This fails on
 * 3.6.2, which stripped only the members of the key's own type.) */
START_TEST(test_setcnf_jwk_strips_foreign)
{
	jwk_set_auto_t *set = NULL;
	jwt_builder_auto_t *builder = NULL;
	const jwk_item_t *item;
	jwt_value_t jval;

	SET_OPS();

	set = jwks_create("{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"k\":\"" SECRET "\",\"p\":\"" SECRET "\","
		"\"priv\":\"" SECRET "\"}");
	ck_assert_ptr_nonnull(set);
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setcnf_jwk(builder, item), 0);

	jwt_set_GET_JSON(&jval, "cnf");
	ck_assert_int_eq(jwt_builder_claim_get(builder, &jval),
			 JWT_VALUE_ERR_NONE);
	ck_assert_ptr_nonnull(jval.json_val);
	ck_assert_ptr_null(strstr(jval.json_val, "\"k\""));
	ck_assert_ptr_null(strstr(jval.json_val, "\"p\""));
	ck_assert_ptr_null(strstr(jval.json_val, "\"priv\""));
	ck_assert_ptr_null(strstr(jval.json_val, SECRET));
	free(jval.json_val);
}
END_TEST

/* An ML-DSA key has the "kty" "AKP", which is recognised in every build (so a
 * public AKP key keeps its type and its public form, the JWK minus the "priv"
 * seed), whether or not the active backend can load it. A build without ML-DSA
 * recognises the type but can load no such key, so it is in error -- its public
 * form is still available. */
START_TEST(test_export_akp)
{
	jwk_set_auto_t *set = NULL;
	const jwk_item_t *item;
	char_auto *one_pub = NULL, *one_priv = NULL, *all_pub = NULL;

	SET_OPS();

	set = jwks_create_fromfile(KEYDIR "/mldsa_key_44.json");
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);
	ck_assert_int_eq(jwks_item_count(set), 1);
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);

	one_priv = jwks_item_export(item, 1);
	ck_assert_ptr_nonnull(one_priv);
	ck_assert_ptr_nonnull(strstr(one_priv, "\"pub\""));
	ck_assert_ptr_nonnull(strstr(one_priv, "\"priv\""));

	/* The public form is the JWK minus "priv", with "pub" kept, in every
	 * build and under every backend (the key need not be usable). */
	one_pub = jwks_item_export(item, 0);
	all_pub = jwks_export(set, 0);
	ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_AKP);
	check_public_form(one_pub);
	ck_assert_ptr_nonnull(strstr(one_pub, "\"pub\""));
	ck_assert_ptr_nonnull(all_pub);
	ck_assert_ptr_null(strstr(all_pub, "\"priv\""));
	ck_assert_ptr_nonnull(strstr(all_pub, "\"pub\""));

#ifndef LIBJWT_HAVE_ML_DSA
	/* No backend in this build can load it, so it is in error. */
	ck_assert_int_ne(jwks_item_error(item), 0);
#endif
}
END_TEST

/* A key in error whose "kty" is a known one keeps a public form, and that
 * form holds none of its private members: not those of its own type, and not
 * those of another type either, since a key in error need not be what its
 * "kty" says. */
START_TEST(test_export_key_in_error)
{
	static const struct {
		const char *jwk;
		jwk_key_type_t kty;
		int secrets;		/* times the JWK holds SECRET */
		const char *keeps;	/* part of a member that is public */
		int by_libjwt;		/* LibJWT itself finds the fault */
	} bad[] = {
		/* An EC private key whose point is not on its curve. That
		 * is for the crypto library to find, so it is not checked
		 * here that it did. */
		{ "{\"kty\":\"EC\",\"crv\":\"P-256\","
		  "\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		  "\"y\":\"795Zo2s891l9E7Jb57g9CEvRVGk_LJ7Hy0ixzGcV8UE\","
		  "\"d\":\"" SECRET "\"}", JWK_KEY_TYPE_EC, 1,
		  "795Zo2s891l9E7Jb57g9CEvRVGk_LJ7Hy0ixzGcV8UE", 0 },
		/* An EC private key with no "y". */
		{ "{\"kty\":\"EC\",\"crv\":\"P-256\","
		  "\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		  "\"d\":\"" SECRET "\"}", JWK_KEY_TYPE_EC, 1,
		  "Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM", 1 },
		/* An RSA private key with no "n", other primes included. */
		{ "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"d\":\"" SECRET "\","
		  "\"p\":\"" SECRET "\",\"q\":\"" SECRET "\","
		  "\"dp\":\"" SECRET "\",\"dq\":\"" SECRET "\","
		  "\"qi\":\"" SECRET "\",\"oth\":[{\"r\":\"" SECRET "\","
		  "\"d\":\"" SECRET "\",\"t\":\"" SECRET "\"}]}",
		  JWK_KEY_TYPE_RSA, 9, "AQAB", 1 },
		/* An OKP private key with no "crv". */
		{ "{\"kty\":\"OKP\","
		  "\"x\":\"HUj-14kN6N4i5qNVkfEhwKiCf-tSrvRHstQdtV8a5QM\","
		  "\"d\":\"" SECRET "\"}", JWK_KEY_TYPE_OKP, 1,
		  "HUj-14kN6N4i5qNVkfEhwKiCf-tSrvRHstQdtV8a5QM", 1 },
		/* A symmetric key that loaded and was then flagged for its
		 * "alg". */
		{ "{\"kty\":\"oct\",\"alg\":8384,\"k\":\"" SECRET "\"}",
		  JWK_KEY_TYPE_OCT, 1, "8384", 1 },
		/* Keys under the wrong "kty": an RSA private key as "EC", */
		{ "{\"kty\":\"EC\",\"n\":\"bW9kdWx1cw\",\"e\":\"AQAB\","
		  "\"d\":\"" SECRET "\",\"p\":\"" SECRET "\","
		  "\"q\":\"" SECRET "\",\"dp\":\"" SECRET "\","
		  "\"dq\":\"" SECRET "\",\"qi\":\"" SECRET "\","
		  "\"oth\":[{\"r\":\"" SECRET "\"}]}", JWK_KEY_TYPE_EC, 7,
		  "bW9kdWx1cw", 1 },
		/* a symmetric key as "RSA", */
		{ "{\"kty\":\"RSA\",\"k\":\"" SECRET "\"}",
		  JWK_KEY_TYPE_RSA, 1, "\"RSA\"", 1 },
		/* an EC or ML-DSA private key as "oct", */
		{ "{\"kty\":\"oct\",\"d\":\"" SECRET "\","
		  "\"priv\":\"" SECRET "\"}", JWK_KEY_TYPE_OCT, 2,
		  "\"oct\"", 1 },
		/* and a symmetric or ML-DSA private key as "OKP". */
		{ "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"k\":\"" SECRET "\","
		  "\"priv\":\"" SECRET "\"}", JWK_KEY_TYPE_OKP, 2,
		  "Ed25519", 1 },
	};
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		jwk_set_auto_t *set = NULL, *round = NULL;
		char_auto *one_pub = NULL, *one_priv = NULL;
		char_auto *all_pub = NULL, *all_priv = NULL;
		const jwk_item_t *item;

		set = jwks_create(bad[i].jwk);
		ck_assert_ptr_nonnull(set);
		ck_assert_int_eq(jwks_error(set), 0);
		item = jwks_item_get(set, 0);
		ck_assert_ptr_nonnull(item);
		ck_assert_int_eq(jwks_item_kty(item), bad[i].kty);
		if (bad[i].by_libjwt)
			ck_assert_msg(jwks_item_error(item) != 0,
				      "Not in error: %s", bad[i].jwk);

		/* As loaded, it is all there. */
		one_priv = jwks_item_export(item, 1);
		ck_assert_ptr_nonnull(one_priv);
		ck_assert_int_eq(count_str(one_priv, SECRET), bad[i].secrets);
		all_priv = jwks_export(set, 1);
		ck_assert_ptr_nonnull(all_priv);
		ck_assert_int_eq(count_str(all_priv, SECRET), bad[i].secrets);

		/* The public form is the same, less what is private. */
		one_pub = jwks_item_export(item, 0);
		check_public_form(one_pub);
		ck_assert_ptr_nonnull(strstr(one_pub, "\"kty\""));
		ck_assert_ptr_nonnull(strstr(one_pub, bad[i].keeps));

		/* The public set keeps the key, in that form. */
		all_pub = jwks_export(set, 0);
		check_public_form(all_pub);
		ck_assert_ptr_nonnull(strstr(all_pub, bad[i].keeps));
		round = jwks_create(all_pub);
		ck_assert_ptr_nonnull(round);
		ck_assert_int_eq(jwks_error(round), 0);
		ck_assert_int_eq(jwks_item_count(round), 1);
		ck_assert_int_eq(jwks_item_kty(jwks_item_get(round, 0)),
				 bad[i].kty);
	}
}
END_TEST

/* The public form of a key in error drops the X.509 binding it was flagged for
 * (a foreign or malformed "x5c", and the "x5t"/"x5t#S256"/"x5u" beside it), so
 * a relay cannot republish a rejected binding from it; the accessors already
 * hide these for such a key. A key not in error keeps its "x5c". */
START_TEST(test_export_key_in_error_x5c)
{
	jwk_set_auto_t *set = NULL;
	const jwk_item_t *item;
	char_auto *one_pub = NULL, *all_pub = NULL;

	SET_OPS();

	set = jwks_create("{\"kty\":\"EC\",\"crv\":\"P-256\","
		"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\","
		"\"x5c\":\"bogus\",\"x5t\":\"AA\",\"x5t#S256\":\"BB\","
		"\"x5u\":\"https://example/cert\"}");
	ck_assert_ptr_nonnull(set);
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);

	one_pub = jwks_item_export(item, 0);
	all_pub = jwks_export(set, 0);
	ck_assert_ptr_nonnull(one_pub);
	ck_assert_ptr_nonnull(all_pub);
	/* The key itself is still there; its X.509 binding is not ("x5t" also
	 * covers "x5t#S256"). */
	ck_assert_ptr_nonnull(strstr(one_pub, "\"kty\""));
	ck_assert_ptr_null(strstr(one_pub, "x5c"));
	ck_assert_ptr_null(strstr(one_pub, "x5t"));
	ck_assert_ptr_null(strstr(one_pub, "x5u"));
	ck_assert_ptr_null(strstr(all_pub, "x5c"));
	ck_assert_ptr_null(strstr(all_pub, "x5t"));
	ck_assert_ptr_null(strstr(all_pub, "x5u"));
}
END_TEST

/* "oth", the other primes of a multi-prime RSA key (RFC 7518 section
 * 6.3.2.7), is as private as "p" and "q": it is left out of the public form
 * of an RSA key like them. */
START_TEST(test_export_rsa_oth)
{
	static const char oth[] = "\"oth\":[{\"r\":\"" SECRET "\","
		"\"d\":\"" SECRET "\",\"t\":\"" SECRET "\"}],";
	jwk_set_auto_t *orig = NULL, *set = NULL, *round = NULL;
	char_auto *json = NULL, *with_oth = NULL;
	char_auto *one_pub = NULL, *one_priv = NULL, *all_pub = NULL;
	const jwk_item_t *item;
	char *buf;
	size_t len;

	SET_OPS();

	/* The RSA test key as a JWK, with "oth" put in front of its other
	 * members. No backend reads "oth", so the key loads as before. */
	buf = read_file("rsa_key_2048.pem", &len);
	orig = jwks_load_fromkey(NULL, buf, len, JWK_KEY_NONE);
	free(buf);
	ck_assert_ptr_nonnull(orig);
	ck_assert_int_eq(jwks_error(orig), 0);
	json = jwks_item_export(jwks_item_get(orig, 0), 1);
	ck_assert_ptr_nonnull(json);
	ck_assert_int_eq(json[0], '{');
	ck_assert_int_gt(asprintf(&with_oth, "{%s%s", oth, json + 1), 0);

	set = jwks_create(with_oth);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_RSA);

	/* As loaded, it is all there. */
	one_priv = jwks_item_export(item, 1);
	ck_assert_ptr_nonnull(one_priv);
	ck_assert_ptr_nonnull(strstr(one_priv, "\"oth\""));
	ck_assert_ptr_nonnull(strstr(one_priv, "\"qi\""));
	ck_assert_int_eq(count_str(one_priv, SECRET), 3);

	one_pub = jwks_item_export(item, 0);
	check_public_form(one_pub);
	all_pub = jwks_export(set, 0);
	check_public_form(all_pub);

	/* What is left is the public key. */
	round = jwks_create(one_pub);
	ck_assert_ptr_nonnull(round);
	ck_assert_int_eq(jwks_error(round), 0);
	item = jwks_item_get(round, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);
	ck_assert_int_eq(jwks_item_kty(item), JWK_KEY_TYPE_RSA);
	ck_assert_int_eq(jwks_item_is_private(item), 0);
}
END_TEST

/* The whole test keyring: RSA, EC, OKP and symmetric keys, private and public.
 * Some backends cannot load some of them, which changes nothing in what is
 * private in a key: no public form holds a private member, and the public set
 * leaves no key out, as every "kty" in there is a known one. */
START_TEST(test_export_keyring)
{
	jwk_set_auto_t *set = NULL, *round = NULL;
	char_auto *pub_json = NULL, *priv_json = NULL;
	const jwk_item_t *item;
	size_t i, count;

	SET_OPS();

	set = jwks_create_fromfile(KEYDIR "/jwks_keyring.json");
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);
	count = jwks_item_count(set);
	ck_assert_int_gt(count, 0);

	/* It does hold private keys of each kind. */
	priv_json = jwks_export(set, 1);
	ck_assert_ptr_nonnull(priv_json);
	ck_assert_ptr_nonnull(strstr(priv_json, "\"qi\""));
	ck_assert_ptr_nonnull(strstr(priv_json, "\"d\""));
	ck_assert_ptr_nonnull(strstr(priv_json, "\"k\""));

	pub_json = jwks_export(set, 0);
	check_public_form(pub_json);
	round = jwks_create(pub_json);
	ck_assert_ptr_nonnull(round);
	ck_assert_int_eq(jwks_error(round), 0);
	ck_assert_int_eq(jwks_item_count(round), count);

	for (i = 0; (item = jwks_item_get(set, i)) != NULL; i++) {
		char_auto *one_pub = jwks_item_export(item, 0);

		ck_assert_int_ne(jwks_item_kty(item), JWK_KEY_TYPE_NONE);
		check_public_form(one_pub);
		ck_assert_int_eq(jwks_item_kty(jwks_item_get(round, i)),
				 jwks_item_kty(item));
	}
}
END_TEST

/* Bad / edge-case inputs. */
START_TEST(test_errors)
{
	jwk_set_auto_t *set = NULL;
	const char junk[] = "this is not a key at all, no PEM, no DER";

	SET_OPS();

	/* NULL / zero-length buffers return NULL. */
	ck_assert_ptr_null(jwks_load_fromkey(NULL, NULL, 0, JWK_KEY_NONE));
	ck_assert_ptr_null(jwks_load_fromkey(NULL, junk, 0, JWK_KEY_NONE));
	ck_assert_ptr_null(jwks_load_fromkey_file(NULL, NULL, JWK_KEY_NONE));

	/* A nonexistent file returns NULL. */
	ck_assert_ptr_null(jwks_load_fromkey_file(NULL,
		KEYDIR "/pem-files/does_not_exist.pem", JWK_KEY_NONE));

	/* Junk bytes without the HMAC flag set the set error. */
	set = jwks_load_fromkey(NULL, junk, sizeof(junk) - 1, JWK_KEY_NONE);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
	ck_assert_ptr_nonnull(jwks_error_msg(set));

	/* Exporters tolerate NULL. */
	ck_assert_ptr_null(jwks_item_export(NULL, 1));
	ck_assert_ptr_null(jwks_export(NULL, 1));
}
END_TEST

/* An invalid PEM file should not parse as a key. */
START_TEST(test_invalid_key)
{
	jwk_set_auto_t *set = NULL;
	char *buf;
	size_t len;

	SET_OPS();

	buf = read_file("rsa_key_invalid.pem", &len);

	/* Not a valid PEM/DER key, and HMAC fallback disabled => error. */
	set = jwks_load_fromkey(NULL, buf, len, JWK_KEY_NONE);
	free(buf);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks_pem");

	tcase_add_loop_test(tc_core, test_fromkey_file, 0, i);
	tcase_add_loop_test(tc_core, test_fromkey_buf, 0, i);
	tcase_add_loop_test(tc_core, test_der_matches_pem, 0, i);
	tcase_add_loop_test(tc_core, test_export_is_base64url, 0, i);
	tcase_add_loop_test(tc_core, test_gen_kid, 0, i);
	tcase_add_loop_test(tc_core, test_hmac_fallback, 0, i);
	tcase_add_loop_test(tc_core, test_append_to_set, 0, i);
	tcase_add_loop_test(tc_core, test_export_reimport, 0, i);
	tcase_add_loop_test(tc_core, test_export_public_only, 0, i);
	tcase_add_loop_test(tc_core, test_export_set, 0, i);
	tcase_add_loop_test(tc_core, test_export_unknown_kty, 0, i);
	tcase_add_loop_test(tc_core, test_setcnf_jwk_unknown_kty, 0, i);
	tcase_add_loop_test(tc_core, test_setcnf_jwk_strips_foreign, 0, i);
	tcase_add_loop_test(tc_core, test_export_akp, 0, i);
	tcase_add_loop_test(tc_core, test_export_key_in_error, 0, i);
	tcase_add_loop_test(tc_core, test_export_key_in_error_x5c, 0, i);
	tcase_add_loop_test(tc_core, test_export_rsa_oth, 0, i);
	tcase_add_loop_test(tc_core, test_export_keyring, 0, i);
	tcase_add_loop_test(tc_core, test_errors, 0, i);
	tcase_add_loop_test(tc_core, test_invalid_key, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS PEM/DER Import");
}
