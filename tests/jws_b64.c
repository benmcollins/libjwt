/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7797} JWS unencoded ("b64":false) + detached payloads (issue #315).
 * Runs under each compiled crypto backend (SET_OPS loop) and both JSON
 * backends. The Appendix A payload "$.02" is non-JSON on purpose. */

static const unsigned char RAW[] = "$.02";
#define RAW_LEN 4

static jwk_set_t *load_one(const char *file)
{
	char *path;
	jwk_set_t *set;
	int ret;

	ret = asprintf(&path, KEYDIR "/%s", file);
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);

	return set;
}

static const jwt_serialization_t formats[] = {
	JWT_FORMAT_COMPACT, JWT_FORMAT_JSON_FLAT, JWT_FORMAT_JSON_GENERAL,
};

/* ---- b64=false, attached, every serialization ---- */
START_TEST(test_b64_false_attached)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t f;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	for (f = 0; f < ARRAY_SIZE(formats); f++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, RAW, RAW_LEN), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, formats[f]), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
	}

	jwks_free(ks);
}
END_TEST

/* ---- b64=false, detached, every serialization ---- */
START_TEST(test_b64_false_detached)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t f;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	for (f = 0; f < ARRAY_SIZE(formats); f++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, RAW, RAW_LEN), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
		ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, formats[f]), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
		/* Correct out-of-band payload verifies; a wrong one is rejected. */
		ck_assert_int_eq(jwt_checker_verify_detached(c, tok, RAW, RAW_LEN), 0);
		ck_assert_int_ne(jwt_checker_verify_detached(c, tok,
			(const unsigned char *)"x.99", 4), 0);
	}

	jwks_free(ks);
}
END_TEST

/* ---- b64=true detached JSON claims (a detached JWT, RFC 7515 App F) ---- */
START_TEST(test_b64_true_detached_jwt)
{
	static const unsigned char JSON[] = "{\"sub\":\"alice\"}";
	jwk_set_t *ks;
	const jwk_item_t *ec;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	char_auto *tok = NULL;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_builder_setpayload(b, JSON, strlen((char *)JSON)), 0);
	ck_assert_int_eq(jwt_builder_set_detached(b, 1), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_verify_detached(c, tok, JSON,
		strlen((char *)JSON)), 0);

	jwks_free(ks);
}
END_TEST

/* ---- RFC 7797 Appendix A.4: HS256, detached, unencoded "$.02" ---- */
START_TEST(test_rfc7797_appendix_a)
{
	/* The HMAC key from RFC 7515 Appendix A.1. */
	static const char *KEY =
		"{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ"
		"-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
	/* The detached JWS from RFC 7797 Appendix A.4. */
	static const char *TOKEN =
		"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
		"..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";
	jwk_set_t *ks;
	const jwk_item_t *k;
	jwt_checker_auto_t *c = NULL, *c2 = NULL;

	SET_OPS();

	ks = jwks_create(NULL);
	ck_assert_ptr_nonnull(ks);
	ck_assert_ptr_nonnull(jwks_load(ks, KEY));
	k = jwks_item_get(ks, 0);
	ck_assert_ptr_nonnull(k);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_HS256, k), 0);
	ck_assert_int_eq(jwt_checker_verify_detached(c, TOKEN, RAW, RAW_LEN), 0);

	/* A different payload must not verify against the RFC signature. */
	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c2, JWT_ALG_HS256, k), 0);
	ck_assert_int_ne(jwt_checker_verify_detached(c2, TOKEN,
		(const unsigned char *)"$.03", 4), 0);

	jwks_free(ks);
}
END_TEST

/* base64url({"alg":"ES256","b64":false}) -- "b64" NOT in "crit" -- and
 * base64url({"alg":"ES256","b64":"false","crit":["b64"]}) -- not a boolean. */
#define HDR_NOCRIT	"eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2V9"
#define HDR_NONBOOL	\
	"eyJhbGciOiJFUzI1NiIsImI2NCI6ImZhbHNlIiwiY3JpdCI6WyJiNjQiXX0"
#define ERR_NOCRIT	"\"b64\":false requires \"b64\" in \"crit\" (RFC 7797)"
#define ERR_NONBOOL	"\"b64\" header must be a boolean"

/* ---- Security + builder guards ---- */
START_TEST(test_b64_security)
{
	/* "b64" is validated alike in Compact and in EVERY JSON signature (not
	 * only the first): it must be a boolean, and false needs "crit". */
	static const struct {
		const char *tok;
		const char *err;
	} bad[] = {
		{ HDR_NOCRIT ".$.02.AAAA", ERR_NOCRIT },
		{ HDR_NONBOOL ".$.02.AAAA", ERR_NONBOOL },
		{ "{\"payload\":\"$.02\",\"protected\":\"" HDR_NOCRIT "\","
		  "\"signature\":\"AAAA\"}", ERR_NOCRIT },
		/* base64url({"alg":"ES256"}) is fine; the second is not. */
		{ "{\"payload\":\"e30\",\"signatures\":[{\"protected\":"
		  "\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"AAAA\"},"
		  "{\"protected\":\"" HDR_NONBOOL "\","
		  "\"signature\":\"AAAA\"}]}", ERR_NONBOOL },
	};
	jwk_set_t *ks;
	const jwk_item_t *ec;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	/* base64url({"alg":"ES256","b64":false}) -- b64 NOT in crit. */
	static const char *NOCRIT =
		"eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2V9.$.02.AAAA";
	size_t i;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	/* @rfc{7797,6} b64=false without "b64" in "crit" is rejected. */
	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
	ck_assert_int_ne(jwt_checker_verify(c, NOCRIT), 0);

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		jwt_checker_auto_t *cb = jwt_checker_new();

		ck_assert_int_eq(jwt_checker_setkey(cb, JWT_ALG_ES256, ec), 0);
		ck_assert_int_ne(jwt_checker_verify(cb, bad[i].tok), 0);
		ck_assert_str_eq(jwt_checker_error_msg(cb), bad[i].err);
	}

	/* The builder refuses b64=false without a raw payload (would be a JWT). */
	b = jwt_builder_new();
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
	ck_assert_ptr_null(jwt_builder_generate(b));

	/* An unencoded payload with an embedded NUL cannot be serialized verbatim,
	 * so it is rejected rather than silently truncated. */
	{
		jwt_builder_auto_t *bn = jwt_builder_new();
		static const unsigned char NUL_PT[] = { 'a', '\0', 'b' };

		ck_assert_int_eq(jwt_builder_setkey(bn, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(bn, NUL_PT, 3), 0);
		ck_assert_int_eq(jwt_builder_setb64(bn, 0), 0);
		ck_assert_ptr_null(jwt_builder_generate(bn));
	}

	jwks_free(ks);
}
END_TEST

/* base64url() protected headers of unverifiable "junk" signature entries:
 * {"alg":"ES256","b64":false,"crit":["b64"]} and the same with "HS256" (an alg
 * the checkers below never accept) claim an unencoded payload, while
 * {"alg":"ES256"} and {"alg":"HS256"} carry no "b64" (the default, true). */
#define JUNK_ES256 "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
#define JUNK_HS256 "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
#define PLAIN_ES256 "eyJhbGciOiJFUzI1NiJ9"
#define PLAIN_HS256 "eyJhbGciOiJIUzI1NiJ9"

/* Junk headers repeating "b64": {"alg":"ES256","b64":true,"b64":false,
 * "crit":["b64"]} and {"alg":"ES256","b64":false,"crit":["b64"],"b64":true}.
 * Jansson rejects duplicate members; json-c keeps the LAST one. */
#define DUP_LAST_FALSE "eyJhbGciOiJFUzI1NiIsImI2NCI6dHJ1ZSwiYjY0Ijpm" \
	"YWxzZSwiY3JpdCI6WyJiNjQiXX0"
#define DUP_LAST_TRUE "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsi" \
	"YjY0Il0sImI2NCI6dHJ1ZX0"

#define B64_DISAGREE	"JWS JSON signatures disagree on \"b64\""
#define B64_UNPROT	"JWS \"crit\"/\"b64\" must be in the protected header"
#define B64_CLAIMS	"Claims cannot be validated on an unencoded " \
			"(\"b64\":false) payload (RFC 7797)"
#define CLAIMS_FAILED	"Failed one or more claims"
#define JTI_MISSING	"Required claim \"jti\" is missing"
#define BAD_PROT	"JWS protected header is not valid JSON"

#ifdef HAVE_JSON_C
#define DUP_ERR		B64_DISAGREE	/* its last "b64" disagrees	*/
#else
#define DUP_ERR		BAD_PROT	/* duplicates are rejected	*/
#endif

/* The claims genuine_jwt() signs, as JSON text: its payload segment is the
 * base64url of these bytes. */
static const unsigned char GOOD[] = "{\"aud\":\"good-aud\"}";
#define GOOD_LEN (sizeof(GOOD) - 1)

/* Split a Compact token in place at its first and LAST '.' (an unencoded
 * payload may itself contain '.'): @tok keeps the protected header, and *@p
 * and *@s point at the payload (empty if detached) and the signature. */
static void split_jws(char *tok, char **p, char **s)
{
	*p = strchr(tok, '.');
	*s = strrchr(tok, '.');
	ck_assert_ptr_nonnull(*p);
	ck_assert_ptr_ne(*p, *s);
	*(*p)++ = '\0';
	*(*s)++ = '\0';
}

/* A builder callback spelling out the default "b64":true in the header. */
static int cb_b64_true(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t v;

	(void)config;
	jwt_set_SET_BOOL(&v, "b64", 1);

	return jwt_header_set(jwt, &v) != JWT_VALUE_ERR_NONE;
}

/* A genuine ES256 JWT (JSON claims, so b64=true) over GOOD (no "iat", so every
 * call yields the same payload), split in place: returns the protected header
 * (free it), with *@p and *@s pointing at the payload and the signature inside
 * the same buffer. @b64hdr spells out "b64":true. */
static char *genuine_jwt(const jwk_item_t *ec, int b64hdr, char **p, char **s)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	jwt_value_t v;
	char *tok;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_builder_enable_iat(b, 0), 1);	/* was on */
	jwt_set_SET_STR(&v, "aud", "good-aud");
	ck_assert_int_eq(jwt_builder_claim_set(b, &v), JWT_VALUE_ERR_NONE);
	if (b64hdr)
		ck_assert_int_eq(jwt_builder_setcb(b, cb_b64_true, NULL), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);
	split_jws(tok, p, s);

	return tok;
}

/* A genuine ES256 JWS over the opaque text @raw, unencoded ("b64":false) and
 * optionally @detached, split as genuine_jwt() does. */
static char *unencoded_jws(const jwk_item_t *ec, const char *raw, int detached,
			   char **p, char **s)
{
	jwt_builder_auto_t *b = jwt_builder_new();
	char *tok;

	ck_assert_ptr_nonnull(b);
	ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_builder_setpayload(b, (const unsigned char *)raw,
						strlen(raw)), 0);
	ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
	ck_assert_int_eq(jwt_builder_set_detached(b, detached), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);
	split_jws(tok, p, s);

	return tok;
}

/* A General JWS JSON token over @payload (NULL: detached) whose signature
 * entries are @h1/@s1 and, unless @h2 is NULL, @h2/@s2 (each a "protected"
 * and a "signature" value). Free it. */
static char *json_jws(const char *payload, const char *h1, const char *s1,
		      const char *h2, const char *s2)
{
	char_auto *e1 = NULL, *e2 = NULL;
	char *tok = NULL;

	ck_assert_int_gt(asprintf(&e1, "{\"protected\":\"%s\","
		"\"signature\":\"%s\"}", h1, s1), 0);
	if (h2 != NULL)
		ck_assert_int_gt(asprintf(&e2, ",{\"protected\":\"%s\","
			"\"signature\":\"%s\"}", h2, s2), 0);
	ck_assert_int_gt(asprintf(&tok, "{%s%s%s\"signatures\":[%s%s]}",
		payload ? "\"payload\":\"" : "", payload ? payload : "",
		payload ? "\"," : "", e1, e2 ? e2 : ""), 0);

	return tok;
}

enum { CK_KEY, CK_KEY_ALGS, CK_RING_ANY, CK_RING_ALL, CK_MAX };

/* A checker for the genuine ES256 signer (@ks): its key alone, the key plus an
 * algorithm allowlist, or @ks as a keyring under each policy. A non-NULL @aud
 * is pinned too. */
static jwt_checker_t *ec_checker(int mode, const jwk_set_t *ks, const char *aud)
{
	static const jwt_alg_t algs[] = { JWT_ALG_ES256 };
	jwt_checker_t *c = jwt_checker_new();

	ck_assert_ptr_nonnull(c);
	if (mode == CK_RING_ANY)
		ck_assert_int_eq(jwt_checker_setkeyring(c, ks,
			JWT_VERIFY_POLICY_ANY), 0);
	else if (mode == CK_RING_ALL)
		ck_assert_int_eq(jwt_checker_setkeyring(c, ks,
			JWT_VERIFY_POLICY_ALL), 0);
	else
		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256,
			jwks_item_get(ks, 0)), 0);
	if (mode == CK_KEY_ALGS)
		ck_assert_int_eq(jwt_checker_setalgs(c, algs, 1), 0);
	if (aud != NULL)
		ck_assert_int_eq(jwt_checker_claim_set(c, JWT_CLAIM_AUD, aud),
				 0);

	return c;
}

/* ---- @rfc{7797,3} Every JSON signature must agree on "b64" ---- */
START_TEST(test_b64_json_mixed)
{
	static const char * const junk[] = { JUNK_ES256, JUNK_HS256 };
	jwk_set_t *ks;
	char_auto *h = NULL, *only = NULL;
	char *p, *s;
	size_t j, k;
	int strict;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	h = genuine_jwt(jwks_item_get(ks, 0), 0, &p, &s);

	/* Control: the genuine signature alone verifies, and fails on its
	 * claims against a checker pinning another audience. */
	only = json_jws(p, h, s, NULL, NULL);
	for (strict = 0; strict < 2; strict++) {
		jwt_checker_auto_t *c = ec_checker(CK_KEY, ks,
			strict ? "other-aud" : NULL);

		ck_assert_int_eq(jwt_checker_verify(c, only), strict);
		if (strict)
			ck_assert_str_eq(jwt_checker_error_msg(c),
					 CLAIMS_FAILED);
	}

	/* An unverifiable "b64":false entry before or after the genuine one
	 * (with an alg the checker accepts, or one its policy skips) must never
	 * switch off the claim checks the genuine signature is then held to.
	 * The mismatch is fatal under every key, keyring and policy, with or
	 * without a claim pin. */
	for (j = 0; j < 2 * ARRAY_SIZE(junk); j++) {
		char_auto *tok = (j % 2) ?
			json_jws(p, junk[j / 2], "AA", h, s) :
			json_jws(p, h, s, junk[j / 2], "AA");

		for (k = 0; k < 2 * CK_MAX; k++) {
			jwt_checker_auto_t *c = ec_checker(k / 2, ks,
				(k % 2) ? "other-aud" : NULL);

			ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c),
					 B64_DISAGREE);
		}
	}

	jwks_free(ks);
}
END_TEST

/* ---- Nor can a junk entry get an unencoded payload decoded as claims ---- */
START_TEST(test_b64_json_reverse)
{
	static const char * const junk[] = { PLAIN_ES256, PLAIN_HS256 };
	jwk_set_t *ks;
	const jwk_item_t *ec;
	char_auto *jh = NULL, *h = NULL, *only = NULL;
	char *jp, *js, *p, *s;
	size_t j, k;
	int pin;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	/* The trusted key signed, as an opaque unencoded payload, text that
	 * base64url-decodes to claims a checker pinning "good-aud" accepts:
	 * a JWT's payload segment. */
	jh = genuine_jwt(ec, 0, &jp, &js);
	h = unencoded_jws(ec, jp, 0, &p, &s);
	ck_assert_str_eq(p, jp);

	/* Control: alone, it verifies with no pin, and is rejected by the pin:
	 * an unencoded payload carries no claims. */
	only = json_jws(p, h, s, NULL, NULL);
	for (pin = 0; pin < 2; pin++) {
		jwt_checker_auto_t *c = ec_checker(CK_KEY, ks,
			pin ? "good-aud" : NULL);

		ck_assert_int_eq(jwt_checker_verify(c, only), pin);
		if (pin)
			ck_assert_str_eq(jwt_checker_error_msg(c), B64_CLAIMS);
	}

	/* An unverifiable entry WITHOUT "b64" (so true) before or after it must
	 * never get that text decoded into the claims: the mismatch is fatal
	 * under every key, keyring and policy, pinned or not. */
	for (j = 0; j < 2 * ARRAY_SIZE(junk); j++) {
		char_auto *tok = (j % 2) ?
			json_jws(p, junk[j / 2], "AA", h, s) :
			json_jws(p, h, s, junk[j / 2], "AA");

		for (k = 0; k < 2 * CK_MAX; k++) {
			jwt_checker_auto_t *c = ec_checker(k / 2, ks,
				(k % 2) ? "good-aud" : NULL);

			ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c),
					 B64_DISAGREE);
		}
	}

	jwks_free(ks);
}
END_TEST

/* Verify the detached JSON @tok (then free it) over @body with every key and
 * keyring mode; @err NULL: it must verify. */
static void detached_case(const jwk_set_t *ks, char *tok, const void *body,
			  size_t len, const char *err)
{
	int k;

	for (k = 0; k < CK_MAX; k++) {
		jwt_checker_auto_t *c = ec_checker(k, ks, NULL);
		int ret = jwt_checker_verify_detached(c, tok, body, len);

		if (err == NULL) {
			ck_assert_int_eq(ret, 0);
		} else {
			ck_assert_int_ne(ret, 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), err);
		}
	}

	free(tok);
}

/* ---- Nor how a detached payload is put back in, either way ---- */
START_TEST(test_b64_json_detached)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	char_auto *h = NULL, *uh = NULL;
	char *p, *s, *up, *us;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	/* A genuine b64=true signature over GOOD (its payload segment is the
	 * text p), and a genuine detached b64=false one over the text p. */
	h = genuine_jwt(ec, 0, &p, &s);
	uh = unencoded_jws(ec, p, 1, &up, &us);
	ck_assert_str_eq(up, "");

	/* Controls: each verifies alone, over the body it signed. */
	detached_case(ks, json_jws(NULL, h, s, NULL, NULL), GOOD, GOOD_LEN,
		      NULL);
	detached_case(ks, json_jws(NULL, uh, us, NULL, NULL), p, strlen(p),
		      NULL);

	/* A "b64":false junk entry would have the body inserted raw, so that
	 * the text p passed for the payload the b64=true signature signed... */
	detached_case(ks, json_jws(NULL, JUNK_ES256, "AA", h, s), p, strlen(p),
		      B64_DISAGREE);
	detached_case(ks, json_jws(NULL, h, s, JUNK_ES256, "AA"), GOOD,
		      GOOD_LEN, B64_DISAGREE);

	/* ...and a "b64"-less one would base64url-encode it, so that GOOD
	 * passed for the text p the b64=false signature signed. */
	detached_case(ks, json_jws(NULL, PLAIN_ES256, "AA", uh, us), GOOD,
		      GOOD_LEN, B64_DISAGREE);
	detached_case(ks, json_jws(NULL, uh, us, PLAIN_ES256, "AA"), p,
		      strlen(p), B64_DISAGREE);

	jwks_free(ks);
}
END_TEST

/* ---- A junk entry repeating "b64" is rejected on either JSON backend ---- */
START_TEST(test_b64_json_dup)
{
	jwk_set_t *ks;
	const jwk_item_t *ec;
	char_auto *h = NULL, *uh = NULL;
	char *p, *s, *up, *us;
	size_t first, k;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);
	h = genuine_jwt(ec, 0, &p, &s);
	uh = unencoded_jws(ec, p, 0, &up, &us);

	/* Jansson rejects the duplicate members; json-c keeps the last "b64",
	 * which is chosen to disagree with the genuine entry's. */
	for (first = 0; first < 2; first++) {
		char_auto *t1 = first ?
			json_jws(p, DUP_LAST_FALSE, "AA", h, s) :
			json_jws(p, h, s, DUP_LAST_FALSE, "AA");
		char_auto *t2 = first ?
			json_jws(up, DUP_LAST_TRUE, "AA", uh, us) :
			json_jws(up, uh, us, DUP_LAST_TRUE, "AA");

		for (k = 0; k < 2 * CK_MAX; k++) {
			const char *aud = (k % 2) ? "good-aud" : NULL;
			jwt_checker_auto_t *c1 = ec_checker(k / 2, ks, aud);
			jwt_checker_auto_t *c2 = ec_checker(k / 2, ks, aud);

			ck_assert_int_ne(jwt_checker_verify(c1, t1), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c1), DUP_ERR);
			ck_assert_int_ne(jwt_checker_verify(c2, t2), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c2), DUP_ERR);
		}
	}

	jwks_free(ks);
}
END_TEST

/* ---- Signatures that agree on "b64" still verify ---- */
START_TEST(test_b64_json_agree)
{
	jwk_set_t *eks, *rks, *ring;
	const jwk_item_t *ec;
	char_auto *h1 = NULL, *h2 = NULL, *gen = NULL, *unenc = NULL;
	char *p1, *s1, *p2, *s2;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c1 = NULL, *c2 = NULL;

	SET_OPS();
	eks = load_one("ec_key_prime256v1.json");
	rks = load_one("rsa_key_2048.json");
	ec = jwks_item_get(eks, 0);
	ring = jwks_create(NULL);
	ck_assert_ptr_nonnull(ring);
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/ec_key_prime256v1.json"));
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
		KEYDIR "/rsa_key_2048.json"));

	/* "b64":true spelled out in one signature's protected header is the
	 * default the other's omits: the same value, so they agree. */
	h1 = genuine_jwt(ec, 0, &p1, &s1);
	h2 = genuine_jwt(ec, 1, &p2, &s2);
	ck_assert_str_eq(p1, p2);
	ck_assert_str_ne(h1, h2);
	gen = json_jws(p1, h1, s1, h2, s2);

	c1 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c1, eks,
		JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_eq(jwt_checker_verify(c1, gen), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(c1), 2);

	/* Two signatures over the same unencoded payload agree on false. */
	b = jwt_builder_new();
	ck_assert_ptr_nonnull(jwt_builder_add_signature(b, JWT_ALG_ES256, ec));
	ck_assert_ptr_nonnull(jwt_builder_add_signature(b, JWT_ALG_RS256,
		jwks_item_get(rks, 0)));
	ck_assert_int_eq(jwt_builder_setpayload(b, RAW, RAW_LEN), 0);
	ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
	unenc = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(unenc);

	c2 = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkeyring(c2, ring,
		JWT_VERIFY_POLICY_ALL), 0);
	ck_assert_int_eq(jwt_checker_verify(c2, unenc), 0);
	ck_assert_uint_eq(jwt_checker_sig_count(c2), 2);

	jwks_free(eks);
	jwks_free(rks);
	jwks_free(ring);
}
END_TEST

/* ---- After a mismatch, the same checker verifies a good token cleanly ---- */
START_TEST(test_b64_reuse)
{
	jwk_set_t *ks;
	char_auto *h = NULL, *good = NULL, *bad = NULL, *compact = NULL;
	char *p, *s;
	jwt_checker_auto_t *c = NULL;
	int round;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	h = genuine_jwt(jwks_item_get(ks, 0), 0, &p, &s);
	good = json_jws(p, h, s, NULL, NULL);
	bad = json_jws(p, JUNK_ES256, "AA", h, s);
	ck_assert_int_gt(asprintf(&compact, "%s.%s.%s", h, p, s), 0);

	c = ec_checker(CK_KEY, ks, "good-aud");
	for (round = 0; round < 2; round++) {
		ck_assert_int_ne(jwt_checker_verify(c, bad), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), B64_DISAGREE);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 0);

		/* JSON, then Compact: no stale error or signature state. */
		ck_assert_int_eq(jwt_checker_verify(c, round ? compact : good),
				 0);
		ck_assert_int_eq(jwt_checker_error(c), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c), "");
		ck_assert_uint_eq(jwt_checker_sig_count(c), 1);
		ck_assert_int_eq(jwt_checker_sig_verified(c, 0), 1);
	}

	jwks_free(ks);
}
END_TEST

/* ---- @rfc{7797,7} An unencoded payload is never JWT claims ---- */
START_TEST(test_b64_false_claims)
{
	/* Raw bytes that happen to spell a claim set: opaque when unencoded. */
	static const unsigned char CLAIMS[] =
		"{\"iss\":\"me\",\"sub\":\"alice\",\"aud\":\"good-aud\"}";
	static const struct {
		jwt_claims_t pin;	/* 0: none			*/
		const char *val;
		const char *req;	/* require({req}), or NULL	*/
		const char *err_jwt;	/* b64=true; NULL: verifies	*/
		const char *err_raw;	/* b64=false; NULL: verifies	*/
	} cases[] = {
		/* No pins: verifies, like any opaque payload. */
		{ 0,		 NULL,	     NULL,  NULL,	   NULL },
		/* As JWT claims these hold; unencoded, there are none. */
		{ JWT_CLAIM_ISS, "me",	     NULL,  NULL,	   B64_CLAIMS },
		{ JWT_CLAIM_SUB, "alice",    NULL,  NULL,	   B64_CLAIMS },
		{ JWT_CLAIM_AUD, "good-aud", NULL,  NULL,	   B64_CLAIMS },
		{ 0,		 NULL,	     "sub", NULL,	   B64_CLAIMS },
		/* Mismatched or missing JWT claims: messages unchanged. */
		{ JWT_CLAIM_ISS, "you",	     NULL,  CLAIMS_FAILED, B64_CLAIMS },
		{ 0,		 NULL,	     "jti", JTI_MISSING,   B64_CLAIMS },
	};
	const size_t len = sizeof(CLAIMS) - 1;
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t k, i;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	/* Compact, JSON Flattened and JSON General; b64=false and true;
	 * attached and detached. */
	for (k = 0; k < 4 * ARRAY_SIZE(formats); k++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		char_auto *tok = NULL;
		int det = k % 2, b64 = (k / 2) % 2;

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b, CLAIMS, len), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, b64), 0);
		ck_assert_int_eq(jwt_builder_set_detached(b, det), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, formats[k / 4]), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		for (i = 0; i < ARRAY_SIZE(cases); i++) {
			jwt_checker_auto_t *c = jwt_checker_new();
			const char *req[] = { cases[i].req };
			const char *err = b64 ? cases[i].err_jwt
					      : cases[i].err_raw;
			int ret;

			ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256,
							    ec), 0);
			if (cases[i].pin)
				ck_assert_int_eq(jwt_checker_claim_set(c,
					cases[i].pin, cases[i].val), 0);
			if (cases[i].req)
				ck_assert_int_eq(jwt_checker_require(c, req, 1),
						 0);

			ret = det ? jwt_checker_verify_detached(c, tok, CLAIMS,
								len)
				  : jwt_checker_verify(c, tok);
			if (err == NULL) {
				ck_assert_int_eq(ret, 0);
			} else {
				ck_assert_int_ne(ret, 0);
				ck_assert_str_eq(jwt_checker_error_msg(c), err);
			}
		}
	}

	jwks_free(ks);
}
END_TEST

static int jti_calls;

/* A jti callback accepting any id, counting its calls. */
static int jti_accept(const jwt_t *jwt, jwt_config_t *config, const char *jti)
{
	(void)jwt;
	(void)config;
	(void)jti;
	jti_calls++;

	return 0;
}

/* ---- Nor can a jti callback accept an unencoded payload ---- */
START_TEST(test_b64_false_jti)
{
	static const char * const payloads[] = {
		"{\"sub\":\"alice\"}", "{\"jti\":\"id-1\"}",
	};
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t k;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	/* Compact, JSON Flattened and JSON General; b64=false and true; with
	 * and without a "jti" in the bytes. */
	for (k = 0; k < 4 * ARRAY_SIZE(formats); k++) {
		jwt_builder_auto_t *b = jwt_builder_new();
		jwt_checker_auto_t *c = jwt_checker_new();
		char_auto *tok = NULL;
		const char *pl = payloads[k % 2];
		int has_jti = k % 2, b64 = (k / 2) % 2;

		ck_assert_int_eq(jwt_builder_setkey(b, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_builder_setpayload(b,
			(const unsigned char *)pl, strlen(pl)), 0);
		ck_assert_int_eq(jwt_builder_setb64(b, b64), 0);
		ck_assert_int_eq(jwt_builder_set_format(b, formats[k / 4]), 0);
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);

		ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
		ck_assert_int_eq(jwt_checker_setjti(c, jti_accept, NULL), 0);
		jti_calls = 0;

		if (b64 && has_jti) {
			ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
			ck_assert_int_eq(jti_calls, 1);
			continue;
		}

		/* A JWT without "jti" keeps its error; unencoded bytes that
		 * spell one are still not claims. */
		ck_assert_int_ne(jwt_checker_verify(c, tok), 0);
		ck_assert_str_eq(jwt_checker_error_msg(c),
				 b64 ? CLAIMS_FAILED : B64_CLAIMS);
		ck_assert_int_eq(jti_calls, 0);
	}

	jwks_free(ks);
}
END_TEST

/* ---- @rfc{7515,4.1.11}/@rfc{7797,3} "crit"/"b64" only when protected ---- */
START_TEST(test_b64_unprotected)
{
	static const struct {
		const char *hdr;	/* the unprotected "header"	*/
		const char *err;	/* NULL: must verify		*/
	} cases[] = {
		{ "{\"kid\":\"hint\"}",			NULL },	/* control */
		{ "{\"b64\":false}",			B64_UNPROT },
		{ "{\"b64\":true}",			B64_UNPROT },
		{ "{\"crit\":[\"b64\"]}",		B64_UNPROT },
		{ "{\"crit\":[\"exp1\"],\"exp1\":1}",	B64_UNPROT },
	};
	jwk_set_t *ks;
	char_auto *h = NULL;
	char *p, *s;
	size_t i, t;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	h = genuine_jwt(jwks_item_get(ks, 0), 0, &p, &s);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		char_auto *flat = NULL, *gen = NULL;
		const char *toks[2];

		/* The same entry, Flattened and General. */
		ck_assert_int_gt(asprintf(&flat, "{\"payload\":\"%s\","
			"\"protected\":\"%s\",\"header\":%s,"
			"\"signature\":\"%s\"}", p, h, cases[i].hdr, s), 0);
		ck_assert_int_gt(asprintf(&gen, "{\"payload\":\"%s\","
			"\"signatures\":[{\"protected\":\"%s\",\"header\":%s,"
			"\"signature\":\"%s\"}]}", p, h, cases[i].hdr, s), 0);
		toks[0] = flat;
		toks[1] = gen;

		for (t = 0; t < ARRAY_SIZE(toks); t++) {
			jwt_checker_auto_t *c = ec_checker(CK_KEY, ks, NULL);
			int ret = jwt_checker_verify(c, toks[t]);

			if (cases[i].err == NULL) {
				ck_assert_int_eq(ret, 0);
			} else {
				ck_assert_int_ne(ret, 0);
				ck_assert_str_eq(jwt_checker_error_msg(c),
						 cases[i].err);
			}
		}
	}

	jwks_free(ks);
}
END_TEST

#define B64_SETB64	"\"b64\" cannot be set as a header: " \
			"use jwt_builder_setb64()"
#define B64_MISMATCH	"A \"b64\" header must match jwt_builder_setb64()"

/* A builder callback merging the JSON object @config->ctx into the header,
 * as an application can with jwt_header_set(). */
static int cb_merge_hdr(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t v;

	jwt_set_SET_JSON(&v, NULL, config->ctx);

	return jwt_header_set(jwt, &v) != JWT_VALUE_ERR_NONE;
}

/* ---- The builder cannot mint what jwt_checker_verify() rejects ---- */
START_TEST(test_b64_builder_guards)
{
	static const struct {
		int b64;		/* jwt_builder_setb64()		*/
		const char *hdr;	/* merged by the callback	*/
		int ok;
	} cbs[] = {
		/* A "b64" that matches the setting is harmless... */
		{ 1, "{\"b64\":true}",				1 },
		{ 0, "{\"b64\":false}",				1 },
		/* ...but a JWT claiming "b64":false (which would dodge the
		 * raw-payload guard), the converse, or a non-boolean is not. */
		{ 1, "{\"b64\":false,\"crit\":[\"b64\"]}",	0 },
		{ 0, "{\"b64\":true}",				0 },
		{ 1, "{\"b64\":\"false\"}",			0 },
	};
	jwk_set_t *ks;
	const jwk_item_t *ec;
	jwt_builder_auto_t *b = NULL;
	jwt_checker_auto_t *c = NULL;
	jwt_signature_t *sig;
	jwt_value_t v, bad[4];
	char_auto *tok = NULL;
	size_t i, f;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	/* jwt_builder_header_set() refuses "b64" by name, whatever its value,
	 * and inside a nameless JSON object to merge, of which nothing is
	 * set. Other names and objects still are. */
	b = jwt_builder_new();
	ck_assert_ptr_nonnull(b);
	jwt_set_SET_BOOL(&bad[0], "b64", 0);
	jwt_set_SET_STR(&bad[1], "b64", "true");
	jwt_set_SET_JSON(&bad[2], NULL, "{\"x-ext\":1,\"b64\":false}");
	jwt_set_SET_JSON(&bad[3], "", "{\"b64\":true}");
	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		ck_assert_int_eq(jwt_builder_header_set(b, &bad[i]),
				 JWT_VALUE_ERR_INVALID);
		ck_assert_str_eq(jwt_builder_error_msg(b), B64_SETB64);
		jwt_builder_error_clear(b);
	}
	jwt_set_GET_BOOL(&v, "b64");
	ck_assert_int_eq(jwt_builder_header_get(b, &v), JWT_VALUE_ERR_NOEXIST);
	jwt_set_GET_INT(&v, "x-ext");
	ck_assert_int_eq(jwt_builder_header_get(b, &v), JWT_VALUE_ERR_NOEXIST);
	jwt_set_SET_JSON(&v, NULL, "{\"x-ext\":1}");
	ck_assert_int_eq(jwt_builder_header_set(b, &v), JWT_VALUE_ERR_NONE);
	jwt_set_SET_BOOL(&v, "x-b64", 0);
	ck_assert_int_eq(jwt_builder_header_set(b, &v), JWT_VALUE_ERR_NONE);
	ck_assert_int_eq(jwt_builder_error(b), 0);

	/* Per signature, "b64" is in neither header and "crit" only in the
	 * protected one (values that parse on both JSON backends). */
	sig = jwt_builder_add_signature(b, JWT_ALG_ES256, ec);
	ck_assert_ptr_nonnull(sig);
	ck_assert_int_ne(jwt_signature_add_protected_json(sig, "b64",
							  "[false]"), 0);
	ck_assert_int_ne(jwt_signature_add_header_json(sig, "b64",
						       "[false]"), 0);
	ck_assert_int_ne(jwt_signature_add_header_json(sig, "crit",
						       "[\"x-sig\"]"), 0);
	ck_assert_int_eq(jwt_signature_add_protected_json(sig, "x-sig",
							  "[false]"), 0);
	ck_assert_int_eq(jwt_signature_add_protected_json(sig, "crit",
							  "[\"x-sig\"]"), 0);
	ck_assert_int_eq(jwt_signature_add_header_json(sig, "kid", "\"hint\""),
			 0);
	ck_assert_int_eq(jwt_builder_set_format(b, JWT_FORMAT_JSON_FLAT), 0);
	tok = jwt_builder_generate(b);
	ck_assert_ptr_nonnull(tok);

	c = jwt_checker_new();
	ck_assert_int_eq(jwt_checker_setkey(c, JWT_ALG_ES256, ec), 0);
	ck_assert_int_eq(jwt_checker_understands(c, "x-sig"), 0);
	ck_assert_int_eq(jwt_checker_verify(c, tok), 0);

	/* A "b64" header set by the callback with jwt_header_set() must match
	 * jwt_builder_setb64(), in every serialization. */
	for (f = 0; f < ARRAY_SIZE(formats); f++) {
		for (i = 0; i < ARRAY_SIZE(cbs); i++) {
			jwt_builder_auto_t *bb = jwt_builder_new();
			jwt_checker_auto_t *cc = NULL;
			char_auto *t = NULL;

			ck_assert_int_eq(jwt_builder_setkey(bb, JWT_ALG_ES256,
							    ec), 0);
			ck_assert_int_eq(jwt_builder_set_format(bb, formats[f]),
					 0);
			if (!cbs[i].b64) {
				ck_assert_int_eq(jwt_builder_setpayload(bb, RAW,
							RAW_LEN), 0);
				ck_assert_int_eq(jwt_builder_setb64(bb, 0), 0);
			}
			ck_assert_int_eq(jwt_builder_setcb(bb, cb_merge_hdr,
						(void *)cbs[i].hdr), 0);
			t = jwt_builder_generate(bb);
			if (!cbs[i].ok) {
				ck_assert_ptr_null(t);
				ck_assert_str_eq(jwt_builder_error_msg(bb),
						 B64_MISMATCH);
				continue;
			}
			ck_assert_ptr_nonnull(t);

			cc = jwt_checker_new();
			ck_assert_int_eq(jwt_checker_setkey(cc, JWT_ALG_ES256,
							    ec), 0);
			ck_assert_int_eq(jwt_checker_verify(cc, t), 0);
		}
	}

	jwks_free(ks);
}
END_TEST

#define CRIT_STRINGS	"\"crit\" header entries must be strings"

/* ---- Every "crit" entry must be a string, a JSON null included ---- */
START_TEST(test_b64_crit_entries)
{
	/* json-c hands a null entry back as NULL: not a string either. */
	static const char * const crits[] = {
		"[null]", "[\"x-ext\",null]", "[\"x-ext\",1]",
	};
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t i, f, b64;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	for (i = 0; i < ARRAY_SIZE(crits); i++) {
		for (f = 0; f < ARRAY_SIZE(formats); f++) {
			for (b64 = 0; b64 < 2; b64++) {
				jwt_builder_auto_t *b = jwt_builder_new();
				char_auto *tok = NULL;
				jwt_value_t v;

				ck_assert_int_eq(jwt_builder_setkey(b,
						JWT_ALG_ES256, ec), 0);
				ck_assert_int_eq(jwt_builder_set_format(b,
						formats[f]), 0);
				if (!b64) {
					ck_assert_int_eq(jwt_builder_setpayload(
						b, RAW, RAW_LEN), 0);
					ck_assert_int_eq(jwt_builder_setb64(b,
						0), 0);
				}
				jwt_set_SET_JSON(&v, "x-ext", "[1]");
				ck_assert_int_eq(jwt_builder_header_set(b, &v),
						 JWT_VALUE_ERR_NONE);
				jwt_set_SET_JSON(&v, "crit", (char *)crits[i]);
				ck_assert_int_eq(jwt_builder_header_set(b, &v),
						 JWT_VALUE_ERR_NONE);

				tok = jwt_builder_generate(b);
				ck_assert_ptr_null(tok);
				ck_assert_str_eq(jwt_builder_error_msg(b),
						 CRIT_STRINGS);
			}
		}
	}

	jwks_free(ks);
}
END_TEST

/* A verify callback recording, as the checker sees it, the protected "crit"
 * of each signature in turn. A signature without one is rejected. */
struct crit_seen {
	unsigned int n;
	char *crit[2];
};

static int cb_crit_seen(jwt_t *jwt, jwt_config_t *config)
{
	struct crit_seen *seen = config->ctx;
	jwt_value_t v;

	if (seen->n == ARRAY_SIZE(seen->crit))
		return 1;

	jwt_set_GET_JSON(&v, "crit");
	if (jwt_header_get(jwt, &v) != JWT_VALUE_ERR_NONE)
		return 1;
	seen->crit[seen->n++] = v.json_val;

	return 0;
}

#define CRIT_ABSENT(n)	"\"crit\" lists \"" n "\" which is not in " \
			"the header"
#define CRIT_TWICE(n)	"\"crit\" lists \"" n "\" more than once"
#define CRIT_REG(n)	"\"crit\" cannot list registered header \"" n "\""
#define CRIT_ARRAY	"\"crit\" header must be an array"
#define CRIT_EMPTY	"\"crit\" header must not be empty"

/* ---- A signature's own protected "crit" adds to the shared one ---- */
START_TEST(test_b64_sig_crit)
{
	static const struct {
		int b64;		/* jwt_builder_setb64() */
		const char *crit;	/* this signature's protected "crit" */
		int x_sig;		/* "x-sig": 1 protected, 2 header */
		/* Without and with a shared jwt_builder_setcrit("x-ext"): the
		 * token's "crit" (an array), or else the builder's error. */
		const char *res[2];
	} cases[] = {
		/* The shared names stay listed, first. */
		{ 0, "[\"x-sig\"]", 1,
		  { "[\"b64\",\"x-sig\"]", "[\"b64\",\"x-ext\",\"x-sig\"]" } },
		{ 1, "[\"x-sig\"]", 1,
		  { "[\"x-sig\"]", "[\"x-ext\",\"x-sig\"]" } },
		/* One listed here as well is listed once. */
		{ 0, "[\"x-sig\",\"b64\"]", 1,
		  { "[\"b64\",\"x-sig\"]", "[\"b64\",\"x-ext\",\"x-sig\"]" } },
		{ 1, "[\"x-ext\",\"x-sig\"]", 1,
		  { CRIT_ABSENT("x-ext"), "[\"x-ext\",\"x-sig\"]" } },
		/* A name must be in the protected header... */
		{ 1, "[\"b64\"]", 0,
		  { CRIT_ABSENT("b64"), CRIT_ABSENT("b64") } },
		{ 1, "[\"x-sig\"]", 0,
		  { CRIT_ABSENT("x-sig"), CRIT_ABSENT("x-sig") } },
		{ 0, "[\"x-sig\"]", 2,
		  { CRIT_ABSENT("x-sig"), CRIT_ABSENT("x-sig") } },
		/* ...and the list valid on its own, shared one or not. */
		{ 0, "{\"x-sig\":1}", 1, { CRIT_ARRAY, CRIT_ARRAY } },
		{ 1, "[]", 0, { CRIT_EMPTY, CRIT_EMPTY } },
		{ 0, "[\"x-sig\",1]", 1, { CRIT_STRINGS, CRIT_STRINGS } },
		{ 1, "[\"x-sig\",null]", 1, { CRIT_STRINGS, CRIT_STRINGS } },
		{ 1, "[\"kid\"]", 0, { CRIT_REG("kid"), CRIT_REG("kid") } },
		{ 0, "[\"x-sig\",\"x-sig\"]", 1,
		  { CRIT_TWICE("x-sig"), CRIT_TWICE("x-sig") } },
		{ 0, "[\"b64\",\"b64\"]", 0,
		  { CRIT_TWICE("b64"), CRIT_TWICE("b64") } },
	};
	jwk_set_t *ks;
	const jwk_item_t *ec;
	size_t i, f, ext;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	ec = jwks_item_get(ks, 0);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		/* Per-signature headers are only in the JSON serializations. */
		for (f = 1; f < ARRAY_SIZE(formats); f++) {
			for (ext = 0; ext < 2; ext++) {
				jwt_builder_auto_t *b = jwt_builder_new();
				jwt_checker_auto_t *c = NULL;
				struct crit_seen seen = { 0 };
				char_auto *tok = NULL;
				jwt_signature_t *sig;
				jwt_value_t v;
				int ret = 0;

				sig = jwt_builder_add_signature(b,
						JWT_ALG_ES256, ec);
				ck_assert_ptr_nonnull(sig);
				ck_assert_int_eq(jwt_builder_set_format(b,
						formats[f]), 0);
				if (!cases[i].b64) {
					ck_assert_int_eq(jwt_builder_setpayload(
						b, RAW, RAW_LEN), 0);
					ck_assert_int_eq(jwt_builder_setb64(b,
						0), 0);
				}
				if (ext) {
					jwt_set_SET_JSON(&v, "x-ext", "[1]");
					ck_assert_int_eq(jwt_builder_header_set(
						b, &v), JWT_VALUE_ERR_NONE);
					ck_assert_int_eq(jwt_builder_setcrit(b,
						"x-ext"), 0);
				}
				if (cases[i].x_sig == 1)
					ret = jwt_signature_add_protected_json(
						sig, "x-sig", "[1]");
				else if (cases[i].x_sig == 2)
					ret = jwt_signature_add_header_json(
						sig, "x-sig", "[1]");
				ck_assert_int_eq(ret, 0);
				ck_assert_int_eq(
					jwt_signature_add_protected_json(sig,
					"crit", cases[i].crit), 0);

				tok = jwt_builder_generate(b);
				if (cases[i].res[ext][0] != '[') {
					ck_assert_ptr_null(tok);
					ck_assert_str_eq(
						jwt_builder_error_msg(b),
						cases[i].res[ext]);
					continue;
				}
				ck_assert_ptr_nonnull(tok);

				c = jwt_checker_new();
				ck_assert_int_eq(jwt_checker_setkey(c,
					JWT_ALG_ES256, ec), 0);
				ck_assert_int_eq(jwt_checker_understands(c,
					"x-sig"), 0);
				ck_assert_int_eq(jwt_checker_understands(c,
					"x-ext"), 0);
				ck_assert_int_eq(jwt_checker_setcb(c,
					cb_crit_seen, &seen), 0);
				ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
				ck_assert_uint_eq(seen.n, 1);
				ck_assert_str_eq(seen.crit[0],
						 cases[i].res[ext]);
				free(seen.crit[0]);
			}
		}
	}

	jwks_free(ks);
}
END_TEST

/* ---- Two signers over one unencoded payload, one with its own "crit" ---- */
START_TEST(test_b64_sig_crit_multi)
{
	/* Each round's "crit", as each signature carries it. */
	static const char * const want[][2] = {
		{ "[\"b64\",\"x-ext\",\"x-sig\"]", "[\"b64\",\"x-ext\"]" },
		{ "[\"b64\",\"x-ext\",\"x-sig\"]", "[\"b64\",\"x-ext\"]" },
		/* Base64url claims now: "b64" is no longer shared. */
		{ "[\"x-ext\",\"x-sig\"]", "[\"x-ext\"]" },
	};
	jwk_set_t *ks, *rsa, *ring;
	jwt_builder_auto_t *b = NULL;
	jwt_signature_t *s1, *s2;
	jwt_value_t v;
	size_t n;

	SET_OPS();
	ks = load_one("ec_key_prime256v1.json");
	rsa = load_one("rsa_key_2048.json");
	ring = load_one("ec_key_prime256v1.json");
	ck_assert_ptr_nonnull(jwks_load_fromfile(ring,
				KEYDIR "/rsa_key_2048.json"));

	b = jwt_builder_new();
	s1 = jwt_builder_add_signature(b, JWT_ALG_ES256, jwks_item_get(ks, 0));
	ck_assert_ptr_nonnull(s1);
	s2 = jwt_builder_add_signature(b, JWT_ALG_RS256,
				       jwks_item_get(rsa, 0));
	ck_assert_ptr_nonnull(s2);
	ck_assert_int_eq(jwt_builder_setpayload(b, RAW, RAW_LEN), 0);
	ck_assert_int_eq(jwt_builder_setb64(b, 0), 0);
	jwt_set_SET_JSON(&v, "x-ext", "[1]");
	ck_assert_int_eq(jwt_builder_header_set(b, &v), JWT_VALUE_ERR_NONE);
	ck_assert_int_eq(jwt_builder_setcrit(b, "x-ext"), 0);
	ck_assert_int_eq(jwt_signature_add_protected_json(s1, "x-sig", "[1]"),
			 0);
	ck_assert_int_eq(jwt_signature_add_protected_json(s1, "crit",
							  "[\"x-sig\"]"), 0);

	/* Generating must leave each signature's own "crit" as it was. Had
	 * the first one kept the shared names, it would still list "b64" in
	 * the last round, which the builder refuses. Generating twice with
	 * the same settings cannot tell. */
	for (n = 0; n < ARRAY_SIZE(want); n++) {
		jwt_checker_auto_t *c = jwt_checker_new();
		struct crit_seen seen = { 0 };
		char_auto *tok = NULL;

		if (n == ARRAY_SIZE(want) - 1) {
			ck_assert_int_eq(jwt_builder_setpayload(b, NULL, 0), 0);
			ck_assert_int_eq(jwt_builder_setb64(b, 1), 0);
		}
		tok = jwt_builder_generate(b);
		ck_assert_ptr_nonnull(tok);
		ck_assert_int_eq(jwt_checker_setkeyring(c, ring,
					JWT_VERIFY_POLICY_ALL), 0);
		ck_assert_int_eq(jwt_checker_understands(c, "x-sig"), 0);
		ck_assert_int_eq(jwt_checker_understands(c, "x-ext"), 0);
		ck_assert_int_eq(jwt_checker_setcb(c, cb_crit_seen, &seen), 0);
		ck_assert_int_eq(jwt_checker_verify(c, tok), 0);
		ck_assert_uint_eq(jwt_checker_sig_count(c), 2);
		ck_assert_uint_eq(seen.n, 2);
		ck_assert_str_eq(seen.crit[0], want[n][0]);
		ck_assert_str_eq(seen.crit[1], want[n][1]);
		free(seen.crit[0]);
		free(seen.crit[1]);
	}

	jwks_free(ks);
	jwks_free(rsa);
	jwks_free(ring);
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jws_b64");

	tcase_add_loop_test(tc_core, test_b64_false_attached, 0, i);
	tcase_add_loop_test(tc_core, test_b64_false_detached, 0, i);
	tcase_add_loop_test(tc_core, test_b64_true_detached_jwt, 0, i);
	tcase_add_loop_test(tc_core, test_rfc7797_appendix_a, 0, i);
	tcase_add_loop_test(tc_core, test_b64_security, 0, i);
	tcase_add_loop_test(tc_core, test_b64_json_mixed, 0, i);
	tcase_add_loop_test(tc_core, test_b64_json_reverse, 0, i);
	tcase_add_loop_test(tc_core, test_b64_json_detached, 0, i);
	tcase_add_loop_test(tc_core, test_b64_json_dup, 0, i);
	tcase_add_loop_test(tc_core, test_b64_json_agree, 0, i);
	tcase_add_loop_test(tc_core, test_b64_reuse, 0, i);
	tcase_add_loop_test(tc_core, test_b64_false_claims, 0, i);
	tcase_add_loop_test(tc_core, test_b64_false_jti, 0, i);
	tcase_add_loop_test(tc_core, test_b64_unprotected, 0, i);
	tcase_add_loop_test(tc_core, test_b64_builder_guards, 0, i);
	tcase_add_loop_test(tc_core, test_b64_crit_entries, 0, i);
	tcase_add_loop_test(tc_core, test_b64_sig_crit, 0, i);
	tcase_add_loop_test(tc_core, test_b64_sig_crit_multi, 0, i);

	tcase_set_timeout(tc_core, 60);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT RFC 7797 unencoded/detached payload (#315)");
}
