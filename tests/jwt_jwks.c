/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "jwt_tests.h"

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#endif

/* GnuTLS parses JWKs natively only from 3.8.4; older GnuTLS delegates parsing
 * to OpenSSL. secp256k1 (ES256K) is rejected only by the native GnuTLS parser
 * (GnuTLS has no such curve) — under the OpenSSL fallback it parses fine. So a
 * test that expects ES256K rejection must check for native GnuTLS, not just the
 * GnuTLS backend. */
static int gnutls_native_jwk(jwt_crypto_provider_t type)
{
#if defined(HAVE_GNUTLS) && GNUTLS_VERSION_NUMBER >= 0x030804
	return type == JWT_CRYPTO_OPS_GNUTLS;
#else
	(void)type;
	return 0;
#endif
}

START_TEST(test_jwks_keyring_load)
{
	const jwk_item_t *item;
	int i, ret;
	int fails = 0;

	SET_OPS();

	read_json("jwks_keyring.json");

	for (i = 0; (item = jwks_item_get(g_jwk_set, i)); i++) {
		jwt_builder_auto_t *builder = NULL;
		char_auto *out = NULL;
		jwt_alg_t alg;

		alg = jwks_item_alg(item);

		/* GnuTLS has no secp256k1 (ES256K) curve, so its native JWK
		 * parser rejects such keys; every other backend (and older
		 * GnuTLS, which delegates parsing to OpenSSL) parses them. Skip
		 * the ES256K keys only under native GnuTLS parsing. */
		if (alg == JWT_ALG_ES256K &&
		    gnutls_native_jwk(jwt_test_ops[_i].type))
			continue;

		/* MbedTLS (PSA) rejects RSA keys larger than the crypto build's
		 * PSA_VENDOR_RSA_MAX_KEY_BITS (4096 by default) at parse, so the
		 * two 8192-bit keys in this ring are flagged bad there. */
		if (jwt_test_ops[_i].type == JWT_CRYPTO_OPS_MBEDTLS &&
		    jwks_item_key_bits(item) > 4096) {
			ck_assert_int_ne(jwks_item_error(item), 0);
			continue;
		}

		if (jwks_item_error(item)) {
			fprintf(stderr, "Err KID: %s\n",
				jwks_item_kid(item));
		}
		ck_assert_int_eq(jwks_item_error(item), 0);

		if (alg == JWT_ALG_ES256K)
			continue;

		if (alg == JWT_ALG_NONE || !jwks_item_is_private(item))
			continue;

		builder = jwt_builder_new();
		ck_assert_ptr_nonnull(builder);

		ret = jwt_builder_setkey(builder, alg, item);
		ck_assert_int_eq(ret, 0);

		out = jwt_builder_generate(builder);

		/* MbedTLS has no EdDSA support; rather than producing a token it
		 * must reject EdDSA signing with a clear error. */
		if (alg == JWT_ALG_EDDSA &&
		    jwt_test_ops[_i].type == JWT_CRYPTO_OPS_MBEDTLS) {
			ck_assert_ptr_null(out);
			ck_assert_ptr_nonnull(strstr(
				jwt_builder_error_msg(builder),
				"MbedTLS does not support EdDSA"));
			continue;
		}

		if (out == NULL) {
			fprintf(stderr, "Gen KID(%d/%s): %s\n", i,
				jwt_alg_str(alg),
				jwt_builder_error_msg(builder));
			fails++;
		}
	}
	ck_assert_int_eq(fails, 0);

	item = jwks_find_bykid(g_jwk_set, "SDSDS");
	ck_assert_ptr_null(item);

	item = jwks_find_bykid(g_jwk_set, "354912a0-b90a-435e-886a-1629f7b2665e");
	ck_assert_ptr_nonnull(item);

	ck_assert_int_eq(i, 27);
	i = jwks_item_count(g_jwk_set);
	ck_assert_int_eq(i, 27);

	/* Index 3 is one of the two secp256k1 keys in the keyring. */
	ck_assert(jwks_item_free(g_jwk_set, 3));

	i = jwks_item_count(g_jwk_set);
	ck_assert_int_eq(i, 26);

	/* Native GnuTLS has no secp256k1 curve, so the remaining secp256k1 key
	 * (index 2) was rejected at parse and is freed here; every other backend
	 * (and older GnuTLS via the OpenSSL fallback) parses it, leaving no bad
	 * keys. */
	i = jwks_item_free_bad(g_jwk_set);
	if (gnutls_native_jwk(jwt_test_ops[_i].type)) {
		ck_assert_int_eq(i, 1);
		ck_assert_int_eq(jwks_item_count(g_jwk_set), 25);
	} else if (jwt_test_ops[_i].type == JWT_CRYPTO_OPS_MBEDTLS) {
		/* The two 8192-bit RSA keys exceed the PSA RSA size limit and
		 * were rejected at parse. */
		ck_assert_int_eq(i, 2);
		ck_assert_int_eq(jwks_item_count(g_jwk_set), 24);
	} else {
		ck_assert_int_eq(i, 0);
		ck_assert_int_eq(jwks_item_count(g_jwk_set), 26);
	}

	free_key();
}
END_TEST

#ifdef HAVE_LIBCURL
START_TEST(load_fromurl)
{
	jwk_set_auto_t *jwk_set = NULL;
	const char *test_url;

	SET_OPS();

	jwk_set = jwks_create_fromurl(NULL, 1);
	ck_assert_ptr_null(jwk_set);

	jwk_set = jwks_create_fromurl("file:///DOESNOTEXIST", 1);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert_int_ne(jwks_error(jwk_set), 0);
	jwks_error_clear(jwk_set);

	test_url = getenv("LIBJWT_TEST_URL");
	if (!test_url || !test_url[0])
		test_url = "file://" KEYDIR "/jwks_keyring.json";

	jwk_set = jwks_load_fromurl(jwk_set, test_url, 2);
	ck_assert_ptr_nonnull(jwk_set);

	ck_assert_int_gt(jwks_item_count(jwk_set), 0);

	/* verify=1 now requests full TLS verification (peer + host), the same
	 * as verify=2; both must still load a plain file:// URL successfully. */
	jwk_set = jwks_load_fromurl(jwk_set, test_url, 1);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert_int_gt(jwks_item_count(jwk_set), 0);
}
END_TEST

/* A response larger than JWKS_MAX_RESPONSE_SIZE (1 MiB) must be rejected rather
 * than read into memory unbounded. For a file:// URL CURLOPT_MAXFILESIZE
 * catches the advertised size; the write_cb cap is the belt for bodies that do
 * not advertise their size (e.g. chunked). Either way the load must fail. */
START_TEST(load_fromurl_oversized)
{
	jwk_set_auto_t *jwk_set = NULL;
	char path[] = "/tmp/libjwt_oversized_XXXXXX";
	char *url = NULL;
	size_t i;
	int fd;
	FILE *fp;

	SET_OPS();

	fd = mkstemp(path);
	ck_assert_int_ge(fd, 0);
	fp = fdopen(fd, "w");
	ck_assert_ptr_nonnull(fp);

	/* Write ~1.5 MiB of valid JSON whitespace wrapping an empty keyset, so
	 * the size cap (not a JSON parse error) is what triggers rejection. */
	fputs("{\"keys\":[]", fp);
	for (i = 0; i < (size_t)(1536 * 1024); i++)
		fputc(' ', fp);
	fputs("}", fp);
	fclose(fp);

	ck_assert_int_gt(asprintf(&url, "file://%s", path), 0);

	jwk_set = jwks_create_fromurl(url, 0);
	ck_assert_ptr_nonnull(jwk_set);
	ck_assert_int_ne(jwks_error(jwk_set), 0);

	free(url);
	unlink(path);
}
END_TEST
#else
START_TEST(load_fromurl)
{
	ck_assert_ptr_null(jwks_create_fromurl("file:///", 1));
}
END_TEST
#endif

START_TEST(test_jwks_keyring_all_bad)
{
	const jwk_item_t *item;
	jwk_set_auto_t *jwk_set;
	int i;

        SET_OPS();

	jwk_set = jwks_create_fromfile(KEYDIR "/bad_keys.json");
	ck_assert_ptr_nonnull(jwk_set);

	i = jwks_error_any(jwk_set);
	ck_assert_int_eq(i, 14);

	for (i = 0; (item = jwks_item_get(jwk_set, i)); i++) {
		if (!jwks_item_error(item)) {
			fprintf(stderr, "KID: %s\n",
				jwks_item_kid(item));
		}
		ck_assert_int_ne(jwks_item_error(item), 0);
	}

	ck_assert_int_eq(i, 14);

	i = jwks_item_free_bad(jwk_set);
	ck_assert_int_eq(i, 14);

	i = jwks_item_count(jwk_set);
	ck_assert_int_eq(i, 0);
}
END_TEST

START_TEST(test_jwks_key_op_all_types)
{
	jwk_key_op_t key_ops = JWK_KEY_OP_SIGN | JWK_KEY_OP_VERIFY |
		JWK_KEY_OP_ENCRYPT | JWK_KEY_OP_DECRYPT | JWK_KEY_OP_WRAP |
		JWK_KEY_OP_UNWRAP | JWK_KEY_OP_DERIVE_KEY |
		JWK_KEY_OP_DERIVE_BITS;

	const jwk_item_t *item;

	SET_OPS();

	read_jsonfp("jwks_test-1.json");

	item = jwks_item_get(g_jwk_set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert(!jwks_item_error(item));

	ck_assert_int_eq(jwks_item_key_ops(item), key_ops);

	free_key();
}
END_TEST

START_TEST(test_jwks_key_op_bad_type)
{
	const jwk_item_t *item;
	const char *kid = "264265c2-4ef0-4751-adbd-9739550afe5b";

	SET_OPS();

	read_json("jwks_test-2.json");

	item = jwks_item_get(g_jwk_set, 0);
	ck_assert_ptr_nonnull(item);

	/* The bad key_op is ignored. */
	ck_assert(!jwks_item_error(item));

	/* Only these ops set. */
	ck_assert_int_eq(jwks_item_key_ops(item),
		JWK_KEY_OP_VERIFY | JWK_KEY_OP_DERIVE_BITS);

	ck_assert_int_eq(jwks_item_use(item), JWK_PUB_KEY_USE_ENC);

	/* Check this key ID. */
	ck_assert_str_eq(jwks_item_kid(item), kid);

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks");

	/* Load a whole keyring */
	tcase_add_loop_test(tc_core, test_jwks_keyring_load, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_keyring_all_bad, 0, i);

	tcase_add_loop_test(tc_core, load_fromurl, 0, i);
#ifdef HAVE_LIBCURL
	tcase_add_loop_test(tc_core, load_fromurl_oversized, 0, i);
#endif

	/* Some coverage attempts */
	tcase_add_loop_test(tc_core, test_jwks_key_op_all_types, 0, i);
	tcase_add_loop_test(tc_core, test_jwks_key_op_bad_type, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWKS");
}
