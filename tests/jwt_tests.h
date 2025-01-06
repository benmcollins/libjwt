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

#define EMPTY_JWT(__jwt) do {		\
	__jwt = jwt_create(NULL);	\
	ck_assert_ptr_nonnull(__jwt);	\
} while(0)

#define jwt_test_auto_t jwt_t __attribute__((cleanup(jwt_test_free)))

#define CREATE_JWT(__j, __f, __a) do {	\
	JWT_CONFIG_DECLARE(__c);	\
	read_key(__f);			\
	__c.alg = __a;			\
	__c.jw_key = g_item;		\
	__j = jwt_create(&__c);		\
	ck_assert_ptr_nonnull(__j);	\
} while(0)

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

#define SET_OPS_JWK() ({					\
	int r = jwt_set_crypto_ops_t(jwt_test_ops[_i].type);	\
	ck_assert_int_eq(r, 0);					\
	if (!jwt_crypto_ops_supports_jwk()) {			\
		errno = 0;					\
		jwk_set_t *jwks = jwks_create(NULL);		\
		ck_assert_ptr_nonnull(jwks);			\
		ck_assert(!jwks_error(jwks));			\
		return;						\
	}							\
})

__attribute__((unused)) static jwk_set_t *g_jwk_set;
__attribute__((unused)) static jwk_item_t *g_item;

__attribute__((unused)) static JWT_CONFIG_DECLARE(t_config);

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

	if (strstr(key_file, ".pem") != NULL)
		return;

	g_jwk_set = jwks_create(test_data.key);
	ck_assert_ptr_nonnull(g_jwk_set);
	ck_assert(!jwks_error(g_jwk_set));

	g_item = jwks_item_get(g_jwk_set, 0);
	ck_assert_ptr_nonnull(g_item);

	t_config.jw_key = g_item;
}

__attribute__((unused))
static void free_key(void)
{
	jwks_free(g_jwk_set);
	jwt_config_init(&t_config);
	g_jwk_set = NULL;
	g_item = NULL;
	test_data.key_len = 0;
	free(test_data.key);
	test_data.key = NULL;
}

__attribute__((unused))
static void jwt_test_free(jwt_t **jwt)
{
	free_key();
	jwt_freep(jwt);
}

__attribute__((unused))
static void __verify_jwt(const char *jwt_str, const jwt_alg_t alg,
			 const char *file)
{
	jwt_auto_t *jwt = NULL;
	int ret = 0;

	read_key(file);

	t_config.alg = alg;

	ret = jwt_verify(&jwt, jwt_str, &t_config);
	free_key();
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt);

	ck_assert_int_eq(jwt_get_alg(jwt), alg);

	free_key();
}

__attribute__((unused))
static void __verify_jwk(const char *jwt_str, jwk_item_t *item)
{
	JWT_CONFIG_DECLARE(config);
	jwt_auto_t *jwt = NULL;
	int ret = 0;

	config.jw_key = item;
	config.alg = item->alg;
	ret = jwt_verify(&jwt, jwt_str, &config);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt);

	/* auto free */
}

__attribute__((unused))
static void __test_alg_key(const jwt_alg_t alg, const char *file, const char *pub)
{
	jwt_auto_t *jwt = NULL;
	int ret = 0;
	char *out;

	CREATE_JWT(jwt, file, alg);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_nonnull(out);

	free_key();

	__verify_jwt(out, alg, pub);

	jwt_free_str(out);

	/* auto free */
}

__attribute__((unused))
static void __verify_alg_key(const char *key_file, const char *jwt_str,
			     const jwt_alg_t alg)
{
	jwt_valid_t *jwt_valid = NULL;
	jwt_auto_t *jwt = NULL;
	int ret = 0;

	read_key(key_file);

	t_config.alg = alg;

	ret = jwt_verify(&jwt, jwt_str, &t_config);

	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt);

	ck_assert_int_eq(alg, jwt_get_alg(jwt));

	jwt_valid_new(&jwt_valid, alg);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(JWT_VALIDATION_SUCCESS, ret);

	jwt_valid_free(jwt_valid);

	free_key();
}

__attribute__((unused))
static void __compare_alg_key(const char *key_file, const char *jwt_str,
			      const jwt_alg_t alg)
{
	jwt_test_auto_t *jwt = NULL;
	int ret = 0;
	char *out;

	CREATE_JWT(jwt, key_file, alg);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_nonnull(out);

	ck_assert_str_eq(out, jwt_str);

	jwt_free_str(out);
}

#endif /* JWT_TESTS_H */
