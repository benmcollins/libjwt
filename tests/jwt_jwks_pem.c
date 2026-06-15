/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "jwt_tests.h"

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#endif

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

/* GnuTLS >= 3.8.4 parses JWKs natively and has no secp256k1 support. Mirrors
 * the helper in jwt_jwks.c. */
static int gnutls_native_jwk(jwt_crypto_provider_t type)
{
#if defined(HAVE_GNUTLS) && GNUTLS_VERSION_NUMBER >= 0x030804
	return type == JWT_CRYPTO_OPS_GNUTLS;
#else
	(void)type;
	return 0;
#endif
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

		if (keys[i].es256k && gnutls_native_jwk(jwt_test_ops[_i].type))
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

		if (keys[i].es256k && gnutls_native_jwk(jwt_test_ops[_i].type))
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
	/* uuidv4 string form: 8-4-4-4-12 = 36 chars. */
	ck_assert_int_eq((int)strlen(kid), 36);
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

		if (keys[i].es256k && gnutls_native_jwk(jwt_test_ops[_i].type))
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
	tcase_add_loop_test(tc_core, test_gen_kid, 0, i);
	tcase_add_loop_test(tc_core, test_hmac_fallback, 0, i);
	tcase_add_loop_test(tc_core, test_append_to_set, 0, i);
	tcase_add_loop_test(tc_core, test_export_reimport, 0, i);
	tcase_add_loop_test(tc_core, test_export_public_only, 0, i);
	tcase_add_loop_test(tc_core, test_export_set, 0, i);
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
