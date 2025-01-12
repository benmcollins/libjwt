/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jwt_tests.h"


static void *test_malloc(size_t size)
{
	return malloc(size);
}

static void test_free(void *ptr)
{
	free(ptr);
}

static void *test_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

static int test_set_alloc(void)
{
	return jwt_set_alloc(test_malloc, test_realloc, test_free);
}

#ifdef JWT_CONSTRUCTOR
START_TEST(test_jwt_crypto_ops)
{
	const char *msg = getenv("JWT_CRYPTO");

	ck_assert_str_eq(msg, "NONEXISTENT");
}
END_TEST
#endif

START_TEST(test_alloc_funcs)
{
	jwt_malloc_t m = NULL;
	jwt_realloc_t r = NULL;
	jwt_free_t f = NULL;
	int ret;

	SET_OPS();

	jwt_get_alloc(&m, &r, &f);
	ck_assert_ptr_null(m);
	ck_assert_ptr_null(r);
	ck_assert_ptr_null(f);

	ret = test_set_alloc();
	ck_assert_int_eq(ret, 0);

	jwt_get_alloc(&m, &r, &f);
	ck_assert(m == test_malloc);
	ck_assert(r == test_realloc);
	ck_assert(f == test_free);

	/* XXX Need to do a build/verify to excercise the functions */
}
END_TEST

static char *__builder(const char *priv, jwt_alg_t alg)
{
	jwt_builder_auto_t *builder;
	jwt_alg_t a_check = JWT_ALG_NONE;
	char *out;
	int ret;

	builder = jwt_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_error(builder), 0);

	read_json(priv);

	if (jwks_item_alg(g_item) == JWT_ALG_NONE)
		a_check = alg;

	ret = jwt_builder_setkey(builder, a_check, g_item);
	ck_assert_int_eq(ret, 0);

	out = jwt_builder_generate(builder);
	ck_assert_ptr_nonnull(out);

	free_key();

	return out;
}

static void __checker(const char *pub, jwt_alg_t alg, char *token)
{
	jwt_checker_auto_t *checker;
	int ret;

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	read_json(pub);

	ret = jwt_checker_setkey(checker, alg, g_item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	if (ret)
		fprintf(stderr, "E: %s\n", jwt_checker_error_msg(checker));
	ck_assert_int_eq(ret, 0);
	free(token);

	free_key();
}

static void __flip_one(const char *priv, const char *pub, jwt_alg_t alg)
{
	char *out = NULL;
	int ret;

	/* If this doesn't work, we wont even bother */
	ret = jwt_set_crypto_ops("gnutls");
	if (ret)
		return;

	/* This one is mandated */
	ret = jwt_set_crypto_ops("openssl");
	ck_assert_int_eq(ret, 0);

	/* Generate on OpenSSL */
	out = __builder(priv, alg);

	/* Switch to GnuTLS */
	ret = jwt_set_crypto_ops("gnutls");
        ck_assert_int_eq(ret, 0);

	/* Verify the OpenSSL token on GnuTLS */
	__checker(pub, alg, out);

	/* Midway through, we switch memory ops */
	test_set_alloc();

	/* Generate on GnuTLS */
	out = __builder(priv, alg);

	/* Switch back to OpenSSL */
	ret = jwt_set_crypto_ops("openssl");
	ck_assert_int_eq(ret, 0);

	/* And verify the GnuTLS token on OpenSSL */
	__checker(pub, alg, out);

	free_key();
}

#define FLIPFLOP_KEY(__name, __pub, __alg)	\
START_TEST(__name)				\
{						\
        __flip_one(#__name ".json",		\
		   #__pub ".json", __alg);	\
}						\
END_TEST

FLIPFLOP_KEY(ec_key_prime256v1,
	     ec_key_prime256v1_pub,
	     JWT_ALG_ES256);
FLIPFLOP_KEY(ec_key_secp384r1,
	     ec_key_secp384r1_pub,
	     JWT_ALG_ES384);
FLIPFLOP_KEY(ec_key_secp521r1,
	     ec_key_secp521r1,
	     JWT_ALG_ES512);

FLIPFLOP_KEY(eddsa_key_ed25519,
	     eddsa_key_ed25519,
	     JWT_ALG_EDDSA);
FLIPFLOP_KEY(eddsa_key_ed448,
	     eddsa_key_ed448_pub,
	     JWT_ALG_EDDSA);

FLIPFLOP_KEY(rsa_key_2048,
	     rsa_key_2048_pub,
	     JWT_ALG_RS256);
FLIPFLOP_KEY(rsa_key_4096,
	     rsa_key_4096,
	     JWT_ALG_RS384);
FLIPFLOP_KEY(rsa_key_8192,
	     rsa_key_8192_pub,
	     JWT_ALG_RS512);

FLIPFLOP_KEY(rsa_pss_key_2048,
	     rsa_pss_key_2048,
	     JWT_ALG_PS256);
FLIPFLOP_KEY(rsa_pss_key_2048_384,
	     rsa_pss_key_2048_384_pub,
	     JWT_ALG_PS384);
FLIPFLOP_KEY(rsa_pss_key_2048_512,
	     rsa_pss_key_2048_512_pub,
	     JWT_ALG_PS512);

FLIPFLOP_KEY(oct_key_256,
	     oct_key_256,
	     JWT_ALG_HS256);
FLIPFLOP_KEY(oct_key_384,
	     oct_key_384,
	     JWT_ALG_HS384);
FLIPFLOP_KEY(oct_key_512,
	     oct_key_512,
	     JWT_ALG_HS512);

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create(title);

	tc_core = tcase_create("Keys");

	tcase_add_test(tc_core, ec_key_prime256v1);
	tcase_add_test(tc_core, ec_key_secp384r1);
	tcase_add_test(tc_core, ec_key_secp521r1);

	tcase_add_test(tc_core, eddsa_key_ed25519);
	tcase_add_test(tc_core, eddsa_key_ed448);

	tcase_add_test(tc_core, rsa_key_2048);
	tcase_add_test(tc_core, rsa_key_4096);
	tcase_add_test(tc_core, rsa_key_8192);

	tcase_add_test(tc_core, rsa_pss_key_2048);
	tcase_add_test(tc_core, rsa_pss_key_2048_384);
	tcase_add_test(tc_core, rsa_pss_key_2048_512);

	tcase_add_test(tc_core, oct_key_256);
	tcase_add_test(tc_core, oct_key_384);
	tcase_add_test(tc_core, oct_key_512);

	suite_add_tcase(s, tc_core);

	/* We run this here so we get some usage out of it */
	tc_core = tcase_create("Utility");
#ifdef JWT_CONSTRUCTOR
	tcase_add_test(tc_core, test_jwt_crypto_ops);
#endif
	tcase_add_test(tc_core, test_alloc_funcs);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("OpenSSL / GnuTLS Cross Testing");
}
