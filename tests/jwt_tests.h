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
/* Older check doesn't have this. */
#ifndef ck_assert_ptr_ne
#define ck_assert_ptr_ne(X, Y) ck_assert(X != Y)
#define ck_assert_ptr_eq(X, Y) ck_assert(X == Y)
#endif

#ifndef ck_assert_int_gt
#define ck_assert_int_gt(X, Y) ck_assert(X > Y)
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

/* Macro to allocate a new JWT with checks. */
#define ALLOC_JWT(__jwt) do {		\
	int __ret = jwt_new(__jwt);	\
	ck_assert_int_eq(__ret, 0);	\
	ck_assert_ptr_ne(__jwt, NULL);	\
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
		ck_assert_ptr_null(jwks);			\
		ck_assert_int_eq(errno, ENOSYS);		\
		return;						\
	}							\
})

__attribute__((unused)) static JWT_CONFIG_DECLARE(t_config);

__attribute__((unused))
static void read_key(const char *key_file)
{
	FILE *fp = fopen(key_file, "r");
	char *key_path, *t;
	int ret = 0;

	/* This can cause cascading failures if CK_FORK=no */
	ck_assert_ptr_null(t_config.key);
	ck_assert_int_eq(t_config.key_len, 0);

	ret = asprintf(&key_path, KEYDIR "/%s", key_file);
	ck_assert_int_gt(ret, 0);

	fp = fopen(key_path, "r");
	free(key_path);
	ck_assert_ptr_nonnull(fp);

	ret = fseek(fp, 0, SEEK_END);
	ck_assert_int_eq(ret, 0);

	t_config.key_len = ftell(fp);
	t = malloc(t_config.key_len + 1);
	ck_assert_ptr_nonnull(t);

	rewind(fp);

	t_config.key_len = fread(t, 1, t_config.key_len, fp);
	ck_assert_int_ne(t_config.key_len, 0);

	ck_assert_int_eq(ferror(fp), 0);

	fclose(fp);

	t[t_config.key_len] = '\0';
	t_config.key = t;
}

__attribute__((unused))
static void free_key(void)
{
	free((void *)(t_config.key));
	jwt_config_init(&t_config);
}

__attribute__((unused))
static void __verify_jwt(const char *jwt_str, const jwt_alg_t alg, const char *file)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key(file);

	t_config.alg = alg;

	ret = jwt_verify(&jwt, jwt_str, &t_config);
	free_key();
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_ne(jwt, NULL);

	ck_assert_int_eq(jwt_get_alg(jwt), alg);

	jwt_free(jwt);
}

__attribute__((unused))
static void __test_alg_key(const jwt_alg_t alg, const char *file, const char *pub)
{
	jwt_auto_t *jwt = NULL;
	int ret = 0;
	char *out;

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	read_key(file);
	ret = jwt_set_alg(jwt, alg, t_config.key, t_config.key_len);
	free_key();
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	__verify_jwt(out, alg, pub);

	jwt_free_str(out);

	/* auto free */
}

__attribute__((unused))
static void __verify_alg_key(const char *key_file, const char *jwt_str,
			     const jwt_alg_t alg)
{
	jwt_valid_t *jwt_valid = NULL;
	jwt_t *jwt = NULL;
	int ret = 0;

	read_key(key_file);

	t_config.alg = alg;

	ret = jwt_verify(&jwt, jwt_str, &t_config);
	free_key();

	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jwt);

	ck_assert_int_eq(alg, jwt_get_alg(jwt));

	jwt_valid_new(&jwt_valid, alg);

	ret = jwt_validate(jwt, jwt_valid);
	ck_assert_int_eq(JWT_VALIDATION_SUCCESS, ret);

	jwt_valid_free(jwt_valid);
	jwt_free(jwt);
}

__attribute__((unused))
static void __compare_alg_key(const char *key_file, const char *jwt_str,
			      const jwt_alg_t alg)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	ALLOC_JWT(&jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	read_key(key_file);
	ret = jwt_set_alg(jwt, alg, t_config.key, t_config.key_len);
	free_key();
	ck_assert_int_eq(ret, 0);

	out = jwt_encode_str(jwt);
	ck_assert_ptr_ne(out, NULL);

	ck_assert_str_eq(out, jwt_str);

	jwt_free_str(out);
	jwt_free(jwt);
}

#endif /* JWT_TESTS_H */
