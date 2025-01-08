/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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
}
END_TEST

const char dump_exp[] = "\n\
{\n\
    \"alg\": \"none\"\n\
}\n\
.\n\
{\n\
    \"iat\": 1475980545,\n\
    \"iss\": \"files.maclara-llc.com\",\n\
    \"ref\": \"XXXX-YYYY-ZZZZ-AAAA-CCCC\",\n\
    \"sub\": \"user0\"\n\
}\n\
{\"alg\":\"none\"}.{\"iat\":1475980545,\"iss\":\"files.maclara-llc.com\","
	"\"ref\":\"XXXX-YYYY-ZZZZ-AAAA-CCCC\",\"sub\":\"user0\"}";

START_TEST(test_jwt_dump_fp)
{
	char read_back[BUFSIZ];
	FILE *out;
	jwt_t *jwt = NULL;
	int ret = 0;

	SET_OPS();

	ret = test_set_alloc();
	ck_assert_int_eq(ret, 0);

	jwt = jwt_create(NULL);
	ck_assert_ptr_nonnull(jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", TS_CONST);
	ck_assert_int_eq(ret, 0);

	out = fopen("dump_fp_out.txt", "w");
	ck_assert_ptr_ne(out, NULL);

	ret = jwt_dump_fp(jwt, out, 1);
	ck_assert_int_eq(ret, 0);

	ret = jwt_dump_fp(jwt, out, 0);
	ck_assert_int_eq(ret, 0);

	fclose(out);

	out = fopen("dump_fp_out.txt", "r");
        ck_assert_ptr_nonnull(out);
        ret = fread(read_back, 1, sizeof(read_back), out);
        ck_assert_int_gt(ret, 0);
        read_back[ret] = '\0';
        fclose(out);
        unlink("dump_fp_out.txt");

	ck_assert_str_eq(dump_exp, read_back);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dump_str)
{
	jwt_value_t jval;
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ret = test_set_alloc();
	ck_assert_int_eq(ret, 0);

	jwt = jwt_create(NULL);
	ck_assert_ptr_nonnull(jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, 0);

	/* Test 'typ' header: should not be present, cause 'alg' is JWT_ALG_NONE. */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 1);
	ck_assert_ptr_null(jval.str_val);

	out = jwt_dump_str(jwt, 1);
	ck_assert_ptr_nonnull(out);

	/* Test 'typ' header: should not be present, cause 'alg' is JWT_ALG_NONE. */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 1);
	ck_assert_ptr_null(jval.str_val);

	jwt_free_str(out);

	out = jwt_dump_str(jwt, 0);
	ck_assert_ptr_nonnull(out);

	/* Test 'typ' header: should not be present, cause 'alg' is JWT_ALG_NONE. */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_null(jval.str_val);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

#define JSON_GRANTS_PRETTY "\n{\n" \
	"    \"%s\": %ld,\n" \
	"    \"%s\": \"%s\",\n" \
	"    \"%s\": \"%s\",\n" \
	"    \"%s\": \"%s\"\n" \
	"}\n"

#define JSON_GRANTS_COMPACT "{\"%s\":%ld,\"%s\":\"%s\"," \
	"\"%s\":\"%s\",\"%s\":\"%s\"}"


START_TEST(test_jwt_dump_grants_str)
{
	jwt_t *jwt = NULL;
	int ret = 0;
	char *out;
	long timestamp = (long)time(NULL);
	char buf[1024];

	SET_OPS();

	ret = test_set_alloc();
	ck_assert_int_eq(ret, 0);

	jwt = jwt_create(NULL);
	ck_assert_ptr_nonnull(jwt);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", timestamp);
	ck_assert_int_eq(ret, 0);

	out = jwt_dump_grants_str(jwt, 1);
	ck_assert_ptr_nonnull(out);

	/* Sorted Keys are expected */
	snprintf(buf, sizeof(buf), JSON_GRANTS_PRETTY,
			"iat", timestamp,
			"iss", "files.maclara-llc.com",
			"ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC",
			"sub", "user0");
	ck_assert_str_eq(out, buf);

	jwt_free_str(out);

	out = jwt_dump_grants_str(jwt, 0);
	ck_assert_ptr_nonnull(out);

	/* Sorted Keys are expected */
	snprintf(buf, sizeof(buf), JSON_GRANTS_COMPACT,
			"iat", timestamp,
			"iss", "files.maclara-llc.com",
			"ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC",
			"sub", "user0");
	ck_assert_str_eq(out, buf);

	jwt_free_str(out);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dump_str_alg_default_typ_header)
{
	jwt_value_t jval;
	jwt_test_auto_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ret = test_set_alloc();
	ck_assert_int_eq(ret, 0);

	CREATE_JWT(jwt, "oct_key_256.json", JWT_ALG_HS256);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, 0);

	/*
	 * Test 'typ' header: should not be present, cause jwt's header has
	 * not been touched yet by jwt_write_head, this is only called as a
	 * result of calling jwt_dump* methods.
	 */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_ne(ret, 0);
	ck_assert_ptr_null(jval.str_val);

	out = jwt_dump_str(jwt, 1);
	ck_assert_ptr_nonnull(out);

	/*
	 * Test 'typ' header: should be added with default value of 'JWT',
	 * cause 'alg' is set explicitly and jwt's header has been processed
	 * by jwt_write_head.
	 */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "JWT");

	jwt_free_str(out);

	out = jwt_dump_str(jwt, 0);
	ck_assert_ptr_nonnull(out);

	/*
	 * Test 'typ' header: should be added with default value of 'JWT',
	 * cause 'alg' is set explicitly and jwt's header has been
	 * processed by jwt_write_head.
	 */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "JWT");

	jwt_free_str(out);
}
END_TEST

START_TEST(test_jwt_dump_str_alg_custom_typ_header)
{
	jwt_value_t jval;
	jwt_test_auto_t *jwt = NULL;
	int ret = 0;
	char *out;

	SET_OPS();

	ret = test_set_alloc();
	ck_assert_int_eq(ret, 0);

	CREATE_JWT(jwt, "oct_key_256.json", JWT_ALG_HS256);

	ret = jwt_add_grant(jwt, "iss", "files.maclara-llc.com");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "sub", "user0");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
	ck_assert_int_eq(ret, 0);

	ret = jwt_add_grant_int(jwt, "iat", (long)time(NULL));
	ck_assert_int_eq(ret, 0);

	jwt_set_ADD_STR(&jval, "typ", "favourite");
	ret = jwt_header_add(jwt, &jval);
	ck_assert_int_eq(ret, 0);

	/* Test that 'typ' header has been added. */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "favourite");

	/* Test 'typ' header: should be left untouched. */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "favourite");

	out = jwt_dump_str(jwt, 1);
	ck_assert_ptr_nonnull(out);

	/* Test 'typ' header: should be left untouched. */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "favourite");

	jwt_free_str(out);

	out = jwt_dump_str(jwt, 0);
	ck_assert_ptr_nonnull(out);

	/* Test 'typ' header: should be left untouched. */
	jwt_set_GET_STR(&jval, "typ");
	ret = jwt_header_get(jwt, &jval);
	ck_assert_int_eq(ret, 0);
	ck_assert_ptr_nonnull(jval.str_val);
	ck_assert_str_eq(jval.str_val, "favourite");

	jwt_free_str(out);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_dump");

#ifdef JWT_CONSTRUCTOR
	tcase_add_test(tc_core, test_jwt_crypto_ops);
#endif
	tcase_add_loop_test(tc_core, test_alloc_funcs, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_dump_fp, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_dump_str, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_dump_grants_str, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_dump_str_alg_default_typ_header, 0, i);
	tcase_add_loop_test(tc_core, test_jwt_dump_str_alg_custom_typ_header, 0, i);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	JWT_TEST_MAIN("LibJWT Dump");
}
