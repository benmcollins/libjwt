/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* These tokens all carry enc=A256GCM, alg=A256KW (in the per-recipient header)
 * with a syntactically valid but irrelevant encrypted_key/iv/ct/tag. The point
 * is that each is rejected for a STRUCTURAL reason before any crypto, so the
 * exact dummy values do not matter. protected = base64url({"enc":"A256GCM"}).
 * The disjointness cases put a duplicate parameter across two headers. */
static void reject(const char *json)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt;
	size_t pt_len = 0;

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, json, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);
}

#define PROT "\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\""
#define BODY "\"iv\":\"aa\",\"ciphertext\":\"bb\",\"tag\":\"cc\""

/* @rfc{7516,7.2.1} A parameter must not appear in more than one of the
 * protected / shared-unprotected / per-recipient headers. */
START_TEST(disjoint_unprotected_vs_recipient)
{
	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* "kid" in both the shared unprotected header and the recipient header. */
	reject("{" PROT ","
	       "\"unprotected\":{\"kid\":\"a\"},"
	       "\"header\":{\"alg\":\"A256KW\",\"kid\":\"b\"},"
	       "\"encrypted_key\":\"x\"," BODY "}");

	free_key();
}
END_TEST

START_TEST(disjoint_protected_vs_recipient)
{
	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* protected = {"cty":"x","enc":"A256GCM"}; recipient also sets "cty". */
	reject("{\"protected\":\"eyJjdHkiOiJ4IiwiZW5jIjoiQTI1NkdDTSJ9\","
	       "\"header\":{\"alg\":\"A256KW\",\"cty\":\"y\"},"
	       "\"encrypted_key\":\"x\"," BODY "}");

	free_key();
}
END_TEST

START_TEST(disjoint_protected_vs_unprotected)
{
	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* protected = {"cty":"x","enc":"A256GCM"}; unprotected also sets "cty". */
	reject("{\"protected\":\"eyJjdHkiOiJ4IiwiZW5jIjoiQTI1NkdDTSJ9\","
	       "\"unprotected\":{\"cty\":\"y\"},"
	       "\"header\":{\"alg\":\"A256KW\"},"
	       "\"encrypted_key\":\"x\"," BODY "}");

	free_key();
}
END_TEST

/* A General token where a non-matching recipient carries a disjointness
 * violation is still rejected (the check runs per recipient, pre-crypto). */
START_TEST(disjoint_in_general_array)
{
	SET_OPS();
	read_json("oct_key_256_enc.json");

	reject("{" PROT ",\"unprotected\":{\"kid\":\"a\"},"
	       "\"recipients\":[{\"header\":{\"alg\":\"A256KW\",\"kid\":\"b\"},"
	       "\"encrypted_key\":\"x\"}]," BODY "}");

	free_key();
}
END_TEST

/* Well-formed disjoint headers are accepted (the duplicate check does not
 * false-positive on distinct names). This one actually decrypts. */
START_TEST(disjoint_ok_roundtrip)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	static const char MSG[] = "disjoint headers are fine";

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder,
						JWE_FORMAT_JSON_GENERAL), 0);
	/* distinct names across protected and shared-unprotected. */
	ck_assert_int_eq(jwe_builder_add_protected_json(builder, "cty",
							"\"text\""), 0);
	ck_assert_int_eq(jwe_builder_add_unprotected_json(builder, "kid",
							  "\"k1\""), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)MSG,
				   strlen(MSG));
	ck_assert_ptr_nonnull(tok);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, MSG, pt_len);

	free(pt);
	free_key();
}
END_TEST

/* A General recipient entry that is not an object, and a recipient with a
 * non-string encrypted_key, are rejected. */
START_TEST(bad_general_entries)
{
	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* recipient entry is a scalar, not an object. The effective-header build
	 * treats a non-object header as absent, so alg is missing -> no match ->
	 * uniform failure (rejected). */
	reject("{" PROT ",\"recipients\":[5]," BODY "}");

	/* recipient with a matching alg but a non-string encrypted_key. */
	reject("{" PROT ",\"recipients\":[{\"header\":{\"alg\":\"A256KW\"},"
	       "\"encrypted_key\":5}]," BODY "}");

	free_key();
}
END_TEST

/* @rfc{7516,7.2.1} The builder must not EMIT a non-disjoint token: generate
 * rejects an application parameter set in two of the three header locations. */
START_TEST(builder_rejects_nondisjoint)
{
	jwe_builder_auto_t *b1 = NULL, *b2 = NULL;
	jwe_recipient_t *r;
	char *tok;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	/* "kid" in both protected and shared-unprotected. */
	b1 = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(b1, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(b1, JWE_FORMAT_JSON_FLAT), 0);
	ck_assert_int_eq(jwe_builder_add_protected_json(b1, "kid", "\"a\""), 0);
	ck_assert_int_eq(jwe_builder_add_unprotected_json(b1, "kid", "\"b\""), 0);
	tok = jwe_builder_generate(b1, (const unsigned char *)"x", 1);
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(b1), 1);

	/* "kid" in both protected and a per-recipient header. Two A256KW
	 * recipients sharing the oct key keeps the test backend-agnostic; the
	 * disjointness check runs before any wrap, so generate fails on it. */
	b2 = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(b2, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(b2, JWE_FORMAT_JSON_GENERAL), 0);
	ck_assert_int_eq(jwe_builder_add_protected_json(b2, "kid", "\"a\""), 0);
	r = jwe_builder_add_recipient(b2, JWE_ALG_A256KW, g_item);
	ck_assert_ptr_nonnull(r);
	ck_assert_int_eq(jwe_recipient_add_header_json(r, "kid", "\"b\""), 0);
	tok = jwe_builder_generate(b2, (const unsigned char *)"x", 1);
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(b2), 1);

	free_key();
}
END_TEST

/* === A member whose value is JSON null is present (json-c parity) ===
 *
 * json-c's jwt_json_obj_get() gives NULL for a member whose value is JSON
 * null, as for a missing one, so json-c used to take these for absent and
 * decrypt, or (for a null in an unprotected header) fail to copy it. Each is
 * now what it is with Jansson. */

/* Decrypt @tok with (@alg, A256GCM, g_item) and expect it to fail with @msg. */
static void reject_msg(jwe_key_alg_t alg, const char *tok, const char *msg)
{
	jwe_checker_auto_t *checker = jwe_checker_new();
	unsigned char *pt;
	size_t pt_len = 0;

	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, JWE_ENC_A256GCM,
					    g_item), 0);
	pt = jwe_checker_decrypt_all(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_str_eq(jwe_checker_error_msg(checker), msg);
}

/* protected = {"alg":"A256KW","crit":null,"enc":"A256GCM"} */
#define PROT_CRIT_NULL	"eyJhbGciOiJBMjU2S1ciLCJjcml0IjpudWxsLCJlbmMiOiJBMjU2R0NNIn0"
/* protected = {"alg":"A256KW","enc":"A256GCM","zip":null} */
#define PROT_ZIP_NULL	"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjpudWxsfQ"
/* protected = {"enc":"A256GCM","x":null} */
#define PROT_X_NULL	"eyJlbmMiOiJBMjU2R0NNIiwieCI6bnVsbH0"
/* protected = {"alg":null,"enc":"A256GCM"} */
#define PROT_ALG_NULL	"eyJhbGciOm51bGwsImVuYyI6IkEyNTZHQ00ifQ"
#define DUMMY		"aa.bb.cc.dd"

/* A protected "crit" or "zip" that is JSON null, Compact or JSON. */
START_TEST(null_crit_zip)
{
	const char *crit = "JWE \"crit\" header must be an array";
	const char *zip = "JWE \"zip\" is not supported";

	SET_OPS();
	read_json("oct_key_256_enc.json");

	reject_msg(JWE_ALG_A256KW, PROT_CRIT_NULL "." DUMMY, crit);
	reject_msg(JWE_ALG_A256KW, PROT_ZIP_NULL "." DUMMY, zip);
	reject_msg(JWE_ALG_A256KW, "{\"protected\":\"" PROT_CRIT_NULL "\","
		   "\"encrypted_key\":\"x\"," BODY "}", crit);
	reject_msg(JWE_ALG_A256KW, "{\"protected\":\"" PROT_ZIP_NULL "\","
		   "\"encrypted_key\":\"x\"," BODY "}", zip);

	free_key();
}
END_TEST

/* JSON Serialization members that are JSON null. */
START_TEST(null_json_members)
{
	const char *both = "JWE JSON has both General and Flattened members";
	const char *recips = "JWE JSON \"recipients\" must be a non-empty array";

	SET_OPS();
	read_json("oct_key_256_enc.json");

	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"unprotected\":null,"
		   "\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\","
		   BODY "}", "JWE JSON \"unprotected\" is not an object");
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"recipients\":null," BODY "}",
		   recips);
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"recipients\":null,"
		   "\"header\":{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\","
		   BODY "}", both);
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"recipients\":[{\"header\":"
		   "{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\"}],"
		   "\"header\":null," BODY "}", both);
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"recipients\":[{\"header\":"
		   "{\"alg\":\"A256KW\"},\"encrypted_key\":\"x\"}],"
		   "\"encrypted_key\":null," BODY "}", both);
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"header\":null,"
		   "\"encrypted_key\":\"x\"," BODY "}",
		   "JWE JSON recipient \"header\" is not an object");
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"recipients\":[{\"header\":"
		   "null,\"encrypted_key\":\"x\"}]," BODY "}",
		   "JWE JSON recipient \"header\" is not an object");
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"header\":{\"alg\":\"A256KW\"},"
		   "\"encrypted_key\":\"x\",\"aad\":null," BODY "}",
		   "JWE JSON \"aad\" is not a string");
	reject_msg(JWE_ALG_A256KW, "{\"protected\":null," BODY "}",
		   "JWE JSON \"protected\" is not a string");
	free_key();

	/* "encrypted_key" with "dir", which has none. */
	read_json("oct_dir_256.json");
	reject_msg(JWE_ALG_DIR, "{" PROT ",\"header\":{\"alg\":\"dir\"},"
		   "\"encrypted_key\":null," BODY "}",
		   "JWE JSON \"encrypted_key\" is not a string");
	free_key();
}
END_TEST

/* @rfc{7516,7.2.1} A protected parameter that is JSON null is in the protected
 * header, so the same name in the shared or per-recipient header is not
 * disjoint from it. With a null "alg", json-c also used to take the
 * per-recipient "alg" for the recipient's. */
START_TEST(null_disjoint)
{
	const char *disjoint = "JWE header parameters are not disjoint";

	SET_OPS();
	read_json("oct_key_256_enc.json");

	reject_msg(JWE_ALG_A256KW, "{\"protected\":\"" PROT_X_NULL "\","
		   "\"unprotected\":{\"x\":1},\"header\":{\"alg\":\"A256KW\"},"
		   "\"encrypted_key\":\"x\"," BODY "}", disjoint);
	reject_msg(JWE_ALG_A256KW, "{\"protected\":\"" PROT_X_NULL "\","
		   "\"header\":{\"alg\":\"A256KW\",\"x\":1},"
		   "\"encrypted_key\":\"x\"," BODY "}", disjoint);
	reject_msg(JWE_ALG_A256KW, "{\"protected\":\"" PROT_ALG_NULL "\","
		   "\"header\":{\"alg\":\"A256KW\"},"
		   "\"encrypted_key\":\"x\"," BODY "}", disjoint);
	/* A null in the shared header, against the per-recipient one. */
	reject_msg(JWE_ALG_A256KW, "{" PROT ",\"unprotected\":{\"x\":null},"
		   "\"header\":{\"alg\":\"A256KW\",\"x\":1},"
		   "\"encrypted_key\":\"x\"," BODY "}", disjoint);

	free_key();
}
END_TEST

/* Insert @ins into @tok just after the first occurrence of @at. */
static char *splice(const char *tok, const char *at, const char *ins)
{
	const char *p = strstr(tok, at);
	char *out = NULL;

	ck_assert_ptr_nonnull(p);
	p += strlen(at);
	ck_assert_int_gt(asprintf(&out, "%.*s%s%s", (int)(p - tok), tok, ins,
				  p), 0);

	return out;
}

/* A member whose value is JSON null in the shared or the per-recipient
 * header (which the tag does not cover) is a parameter like any other: the
 * token still decrypts. json-c used to fail it with "Error allocating
 * memory". */
START_TEST(null_unprotected_member_ok)
{
	static const char MSG[] = "a null unprotected member";
	jwe_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;
	int n;

	SET_OPS();
	read_json("oct_key_256_enc.json");

	builder = jwe_builder_new();
	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_format(builder, JWE_FORMAT_JSON_FLAT),
			 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)MSG,
				   strlen(MSG));
	ck_assert_ptr_nonnull(tok);

	for (n = 0; n < 2; n++) {
		jwe_checker_auto_t *checker = jwe_checker_new();
		char_auto *mod = n ? splice(tok, "\"header\":{", "\"y\":null,") :
			splice(tok, "{", "\"unprotected\":{\"x\":null},");
		unsigned char *pt;
		size_t pt_len = 0;

		ck_assert_ptr_nonnull(checker);
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_A256KW,
						    JWE_ENC_A256GCM, g_item), 0);
		pt = jwe_checker_decrypt_all(checker, mod, &pt_len);
		ck_assert_msg(pt != NULL, "%s: %s", mod,
			      jwe_checker_error_msg(checker));
		ck_assert_mem_eq(pt, MSG, pt_len);
		free(pt);
	}

	free_key();
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE JSON Negatives");

	tcase_add_loop_test(tc_core, disjoint_unprotected_vs_recipient, 0, i);
	tcase_add_loop_test(tc_core, disjoint_protected_vs_recipient, 0, i);
	tcase_add_loop_test(tc_core, disjoint_protected_vs_unprotected, 0, i);
	tcase_add_loop_test(tc_core, disjoint_in_general_array, 0, i);
	tcase_add_loop_test(tc_core, disjoint_ok_roundtrip, 0, i);
	tcase_add_loop_test(tc_core, bad_general_entries, 0, i);
	tcase_add_loop_test(tc_core, builder_rejects_nondisjoint, 0, i);

	/* json-c behaves as Jansson does (JSON null members) */
	tcase_add_loop_test(tc_core, null_crit_zip, 0, i);
	tcase_add_loop_test(tc_core, null_json_members, 0, i);
	tcase_add_loop_test(tc_core, null_disjoint, 0, i);
	tcase_add_loop_test(tc_core, null_unprotected_member_ok, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE JSON Negatives");
}
