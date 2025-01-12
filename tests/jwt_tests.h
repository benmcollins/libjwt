/* Public domain, no copyright. Use at your own risk. */

#ifndef JWT_TESTS_H
#define JWT_TESTS_H

#include <jwt.h>
#include <check.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef ARRAY_SIZE
#  ifdef __GNUC__
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]) + \
        __builtin_types_compatible_p(typeof(__arr), typeof(&(__arr)[0])) * 0)
#  else
#    define ARRAY_SIZE(__arr) (sizeof(__arr) / sizeof((__arr)[0]))
#  endif
#endif

/* Compatibility with older libCheck versions */
#ifndef ck_assert_ptr_null
#define ck_assert_ptr_null(__X) ck_assert_ptr_eq(__X, NULL)
#define ck_assert_ptr_nonnull(__X) ck_assert_ptr_ne(__X, NULL)
#endif

/* Constant time to make tests consistent. */
#define TS_CONST	1475980545L

typedef struct {
	const char *name;
	jwt_crypto_provider_t type;
} jwt_test_op_t;

__attribute__((unused))
static jwt_test_op_t jwt_test_ops[] = {
#ifdef HAVE_OPENSSL
	{ .name = "openssl", .type = JWT_CRYPTO_OPS_OPENSSL },
#endif
#ifdef HAVE_GNUTLS
	{ .name ="gnutls", .type = JWT_CRYPTO_OPS_GNUTLS },
#endif
#ifdef HAVE_MBEDTLS
	{ .name ="mbedtls", .type = JWT_CRYPTO_OPS_MBEDTLS },
#endif
};

#define JWT_TEST_MAIN(__title) ({					\
	int number_failed = 0;						\
	SRunner *sr;							\
	Suite *s;							\
									\
	s = libjwt_suite(__title);					\
	sr = srunner_create(s);						\
									\
	srunner_run_all(sr, CK_VERBOSE);				\
	number_failed += srunner_ntests_failed(sr);			\
	srunner_free(sr);						\
									\
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;	\
})

#define SET_OPS() ({						\
	int r = jwt_set_crypto_ops(jwt_test_ops[_i].name);	\
	ck_assert_int_eq(r, 0);					\
	const char *ops = jwt_get_crypto_ops();			\
	ck_assert_str_eq(ops, jwt_test_ops[_i].name);		\
})

#define jwt_freemem(__ptr) ({   \
        if (__ptr) {            \
                free(__ptr);	\
                __ptr = NULL;   \
        }                       \
})

static inline void jwt_freememp(char **mem) {
	jwt_freemem(*mem);
}
#define char_auto char  __attribute__((cleanup(jwt_freememp)))

__attribute__((unused)) static jwk_set_t *g_jwk_set;
__attribute__((unused)) static const jwk_item_t *g_item;

__attribute__((unused))
static struct {
	char *key;
	size_t key_len;
} test_data;

__attribute__((unused))
static void read_json(const char *key_file)
{
	char *key_path;
	int ret;

	ret = asprintf(&key_path, KEYDIR "/%s", key_file);
	ck_assert_int_gt(ret, 0);

	g_jwk_set = jwks_create_fromfile(key_path);
	free(key_path);
	ck_assert_ptr_nonnull(g_jwk_set);
	ck_assert(!jwks_error(g_jwk_set));

	/* Just to cover the code path */
	jwks_error_clear(g_jwk_set);

	g_item = jwks_item_get(g_jwk_set, 0);
	ck_assert_ptr_nonnull(g_item);
}

__attribute__((unused))
static void read_jsonfp(const char *key_file)
{
	FILE *fp = NULL;
	char *key_path;
	int ret;

	ret = asprintf(&key_path, KEYDIR "/%s", key_file);
	ck_assert_int_gt(ret, 0);

	fp = fopen(key_path, "r");
	ck_assert_ptr_nonnull(fp);
	free(key_path);

	g_jwk_set = jwks_create_fromfp(fp);
	fclose(fp);
	ck_assert_ptr_nonnull(g_jwk_set);
	ck_assert(!jwks_error(g_jwk_set));

	g_item = jwks_item_get(g_jwk_set, 0);
	ck_assert_ptr_nonnull(g_item);
}

__attribute__((unused))
static void read_key(const char *key_file)
{
	FILE *fp = NULL;
	char *key_path;
	int ret = 0;

	/* This can cause cascading failures if CK_FORK=no */
	ck_assert_ptr_null(g_jwk_set);

	ret = asprintf(&key_path, KEYDIR "/%s", key_file);
	ck_assert_int_gt(ret, 0);

	fp = fopen(key_path, "r");
	free(key_path);
	ck_assert_ptr_nonnull(fp);

	ret = fseek(fp, 0, SEEK_END);
	ck_assert_int_eq(ret, 0);

	test_data.key_len = ftell(fp);
	test_data.key = malloc(test_data.key_len + 1);
	ck_assert_ptr_nonnull(test_data.key);

	rewind(fp);

	test_data.key_len = fread(test_data.key, 1, test_data.key_len, fp);
	ck_assert_int_ne(test_data.key_len, 0);

	test_data.key[test_data.key_len] = '\0';

	ck_assert_int_eq(ferror(fp), 0);

	fclose(fp);
}

__attribute__((unused))
static void free_key(void)
{
	jwks_free(g_jwk_set);
	g_jwk_set = NULL;
	g_item = NULL;
	test_data.key_len = 0;
	free(test_data.key);
	test_data.key = NULL;
}

__attribute__((unused))
static void __verify_jwk(const char *jwt_str, const jwk_item_t *item)
{
	jwt_checker_auto_t *checker = NULL;
	jwt_alg_t alg = JWT_ALG_NONE; // jwks_item_alg(item);
	int ret;

	checker = jwt_checker_new();
	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_error(checker), 0);

	ret = jwt_checker_setkey(checker, alg, item);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, jwt_str);
	ck_assert_int_eq(ret, 0);
}

#endif /* JWT_TESTS_H */
