/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* Backend affinity (issue #320): a jwk_item is bound to the crypto backend that
 * parsed it, and key operations route to that backend regardless of the active
 * jwt_ops. Each test sets the active backend with SET_OPS() (the "use" backend),
 * then parses a key under EVERY backend (the "parse" backend) and exercises it
 * under the active one. Before affinity, a cross-backend asymmetric key failed
 * ("Key is not compatible"); now every (parse, use) pair must succeed. */

static const char PT[] = "cross-backend proof-of-possession plaintext";

static jwk_set_t *load_under(size_t ops_idx, const char *file)
{
	char *path;
	jwk_set_t *set;
	int ret;

	/* Parse the JWK under jwt_test_ops[ops_idx]; this binds item->provider. */
	ret = jwt_set_crypto_ops(jwt_test_ops[ops_idx].name);
	ck_assert_int_eq(ret, 0);

	ret = asprintf(&path, KEYDIR "/%s", file);
	ck_assert_int_gt(ret, 0);
	set = jwks_create_fromfile(path);
	free(path);
	ck_assert_ptr_nonnull(set);

	return set;
}

static const struct {
	const char *file;
	jwt_alg_t alg;
} sig_keys[] = {
	{ "ec_key_prime256v1.json", JWT_ALG_ES256 },	/* backend-specific */
	{ "rsa_key_2048.json",      JWT_ALG_RS256 },	/* backend-specific */
	{ "oct_key_256.json",       JWT_ALG_HS256 },	/* cross-compatible (ANY) */
};

START_TEST(test_xbackend_sign_verify)
{
	size_t k, p;

	SET_OPS(); /* active ("use") backend = jwt_test_ops[_i] */

	for (k = 0; k < ARRAY_SIZE(sig_keys); k++) {
		for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
			jwt_builder_auto_t *builder = NULL;
			jwt_checker_auto_t *checker = NULL;
			char_auto *token = NULL;
			jwk_set_t *set;
			const jwk_item_t *key;

			/* Parse under backend p ... */
			set = load_under(p, sig_keys[k].file);
			key = jwks_item_get(set, 0);
			ck_assert_ptr_nonnull(key);

			/* ... then switch the active backend to the use one. */
			ck_assert_int_eq(jwt_set_crypto_ops(
				jwt_test_ops[_i].name), 0);

			builder = jwt_builder_new();
			ck_assert_int_eq(jwt_builder_setkey(builder,
				sig_keys[k].alg, key), 0);
			token = jwt_builder_generate(builder);
			ck_assert_ptr_nonnull(token);

			checker = jwt_checker_new();
			ck_assert_int_eq(jwt_checker_setkey(checker,
				sig_keys[k].alg, key), 0);
			ck_assert_int_eq(jwt_checker_verify(checker, token), 0);

			jwks_free(set);
		}
	}
}
END_TEST

static void jwe_roundtrip_xbackend(size_t use_i, jwe_key_alg_t alg,
				   jwe_enc_t enc, const char *file)
{
	size_t p;

	for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
		jwe_builder_auto_t *builder = NULL;
		jwe_checker_auto_t *checker = NULL;
		char_auto *token = NULL;
		unsigned char *pt = NULL;
		size_t pt_len = 0;
		jwk_set_t *set;
		const jwk_item_t *key;

		set = load_under(p, file);
		key = jwks_item_get(set, 0);
		ck_assert_ptr_nonnull(key);

		ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[use_i].name), 0);

		builder = jwe_builder_new();
		ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, key), 0);
		token = jwe_builder_generate(builder, (const unsigned char *)PT,
					     strlen(PT));
		ck_assert_ptr_nonnull(token);

		checker = jwe_checker_new();
		ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, key), 0);
		pt = jwe_checker_decrypt(checker, token, &pt_len);
		ck_assert_ptr_nonnull(pt);
		ck_assert_uint_eq(pt_len, strlen(PT));
		ck_assert_mem_eq(pt, PT, pt_len);
		free(pt);

		jwks_free(set);
	}
}

START_TEST(test_xbackend_jwe_rsa)
{
	SET_OPS();
	/* RSA-OAEP-256 wraps the CEK with the recipient RSA key (decrypt_cek_rsa
	 * / encrypt_cek_rsa route to the key's backend). */
	jwe_roundtrip_xbackend(_i, JWE_ALG_RSA_OAEP_256, JWE_ENC_A256GCM,
			       "rsa_key_2048_enc.json");
}
END_TEST

START_TEST(test_xbackend_jwe_ecdh)
{
	SET_OPS();
	/* ECDH-ES derives the agreed key from the recipient EC key (ecdh_derive
	 * routes to the key's backend). */
	jwe_roundtrip_xbackend(_i, JWE_ALG_ECDH_ES_A256KW, JWE_ENC_A256GCM,
			       "ec_key_prime256v1_enc.json");
}
END_TEST

/* A key that one backend could not load is in error, and JWE refuses it
 * whichever backend is active when it is used. Such a key has no origin
 * backend, so it would otherwise be handed to the active one. secp256k1 does
 * not load under GnuTLS, nor an 8192-bit RSA key under MbedTLS; where a key
 * does load there is nothing to check. */
START_TEST(test_xbackend_jwe_errored)
{
	static const struct {
		const char *file;
		jwe_key_alg_t alg;
	} keys[] = {
		{ "ec_key_secp256k1_enc.json", JWE_ALG_ECDH_ES },
		{ "rsa_key_8192.json",         JWE_ALG_RSA_OAEP_256 },
		/* A key flagged in error (a malformed "x5c") on EVERY backend, so
		 * the refusal is exercised even in a single-backend build, where
		 * the two above may load. "oct" keys are backend-agnostic. */
		{ "oct_key_256_enc_bad_x5c.json", JWE_ALG_A256KW },
	};
	size_t k, p;

	SET_OPS();

	for (k = 0; k < ARRAY_SIZE(keys); k++) {
		for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
			jwe_builder_auto_t *builder = NULL;
			jwe_checker_auto_t *checker = NULL;
			jwk_set_t *set;
			const jwk_item_t *key;

			set = load_under(p, keys[k].file);
			key = jwks_item_get(set, 0);
			ck_assert_ptr_nonnull(key);

			ck_assert_int_eq(jwt_set_crypto_ops(
				jwt_test_ops[_i].name), 0);

			if (!jwks_item_error(key)) {
				jwks_free(set);
				continue;
			}

			builder = jwe_builder_new();
			ck_assert_int_eq(jwe_builder_setkey(builder,
				keys[k].alg, JWE_ENC_A256GCM, key), 1);
			ck_assert_str_eq(jwe_builder_error_msg(builder),
				"Key is in error and cannot be used for JWE");

			checker = jwe_checker_new();
			ck_assert_int_eq(jwe_checker_setkey(checker,
				keys[k].alg, JWE_ENC_A256GCM, key), 1);
			ck_assert_str_eq(jwe_checker_error_msg(checker),
				"Key is in error and cannot be used for JWE");

			jwks_free(set);
		}
	}
}
END_TEST

/* Free a key while a DIFFERENT backend is active than the one that parsed it.
 * Only the origin backend can release the key's provider_data, so this must not
 * leak (issue #327, completing #320). The leak is proven absent by the
 * memcheck CI row; here we just exercise every (parse, free) backend pair. */
START_TEST(test_xbackend_free)
{
	static const char *files[] = {
		"ec_key_prime256v1.json",	/* EC: EVP_PKEY / PSA / gnutls key */
		"rsa_key_2048.json",		/* RSA */
		"oct_key_256.json",		/* oct: backend-agnostic (ANY) */
	};
	size_t k, p;

	SET_OPS(); /* the active ("free") backend = jwt_test_ops[_i] */

	for (k = 0; k < ARRAY_SIZE(files); k++) {
		for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
			/* Parse under backend p ... */
			jwk_set_t *set = load_under(p, files[k]);

			/* ... then free while the use backend (_i) is active. */
			ck_assert_int_eq(jwt_set_crypto_ops(
				jwt_test_ops[_i].name), 0);
			jwks_free(set);
		}
	}
}
END_TEST

/* A key that failed to load under one backend is never handed to another: it
 * has no key object, and the active backend used to be given it all the same
 * (OpenSSL then crashed on one that MbedTLS had refused). Every (parse, use)
 * pair refuses such a key on every path a key takes. The tokens are a header
 * for the key's "alg", an empty claim set ("e30") and a junk signature. */
#define ERR_KEY		"Key is in error and cannot be used"

static const jwk_item_t *bad_cb_key;

static int bad_key_cb(jwt_t *jwt, jwt_config_t *config)
{
	(void)jwt;
	config->key = bad_cb_key;

	return 0;
}

START_TEST(test_xbackend_errored_key)
{
	static const struct {
		const char *file;	/* a key file, or ...		*/
		const char *jwk;	/* ... an inline JWK		*/
		jwt_alg_t alg;
		const char *tok;	/* without a "kid"		*/
		const char *tok_kid;	/* with the key's "kid"		*/
		const char *kid;	/* that "kid"			*/
	} keys[] = {
		/* Over the 4096 bits MbedTLS loads; fine elsewhere. */
		{ "rsa_key_8192_pub.json", NULL, JWT_ALG_RS512,
		  "eyJhbGciOiJSUzUxMiJ9.e30.AAAA",
		  "eyJhbGciOiJSUzUxMiIsImtpZCI6IjgzZDQzMGU0LTU3OTctNGFiMC1i"
		  "OGU3LWM2MjBlYTRjY2I1ZSJ9.e30.AAAA",
		  "83d430e4-5797-4ab0-b8e7-c620ea4ccb5e" },
		/* A point that is not on the curve (and its private key). */
		{ NULL, "{\"kty\":\"EC\",\"alg\":\"ES256\",\"kid\":\"bad\","
		  "\"crv\":\"P-256\","
		  "\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
		  "\"y\":\"795Zo2s891l9E7Jb57g9CEvRVGk_LJ7Hy0ixzGcV8UE\","
		  "\"d\":\"wDvSCv8kxkqIVTYPpgEm4Efs6lKzf-95W8Qej4F1yEM\"}",
		  JWT_ALG_ES256,
		  "eyJhbGciOiJFUzI1NiJ9.e30.AAAA",
		  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImJhZCJ9.e30.AAAA", "bad" },
		/* An X25519 "x" of the wrong length, offered for EdDSA. */
		{ NULL, "{\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"kid\":\"bad\","
		  "\"crv\":\"X25519\",\"x\":\"AAAA\"}",
		  JWT_ALG_EDDSA,
		  "eyJhbGciOiJFZERTQSJ9.e30.AAAA",
		  "eyJhbGciOiJFZERTQSIsImtpZCI6ImJhZCJ9.e30.AAAA", "bad" },
	};
	size_t k, p;

	SET_OPS(); /* active ("use") backend = jwt_test_ops[_i] */

	for (k = 0; k < ARRAY_SIZE(keys); k++) {
		for (p = 0; p < ARRAY_SIZE(jwt_test_ops); p++) {
			jwt_builder_auto_t *b = NULL;
			jwt_checker_auto_t *c = NULL, *ccb = NULL, *cr = NULL;
			char_auto *want_scan = NULL, *want_kid = NULL;
			jwk_set_t *set;
			const jwk_item_t *key;

			/* Parse under backend p ... */
			if (keys[k].file != NULL) {
				set = load_under(p, keys[k].file);
			} else {
				ck_assert_int_eq(jwt_set_crypto_ops(
					jwt_test_ops[p].name), 0);
				set = jwks_create(keys[k].jwk);
				ck_assert_ptr_nonnull(set);
			}
			key = jwks_item_get(set, 0);
			ck_assert_ptr_nonnull(key);

			/* ... then switch the active backend to the use one. */
			ck_assert_int_eq(jwt_set_crypto_ops(
				jwt_test_ops[_i].name), 0);

			/* Only a key the parse backend could not load. */
			if (!jwks_item_error(key)) {
				jwks_free(set);
				continue;
			}

			/* Set on a checker or a builder. */
			c = jwt_checker_new();
			ck_assert_int_ne(jwt_checker_setkey(c, keys[k].alg,
							    key), 0);
			ck_assert_str_eq(jwt_checker_error_msg(c), ERR_KEY);
			ck_assert_int_ne(jwt_checker_verify(c, keys[k].tok), 0);

			b = jwt_builder_new();
			ck_assert_int_ne(jwt_builder_setkey(b, keys[k].alg,
							    key), 0);
			ck_assert_str_eq(jwt_builder_error_msg(b), ERR_KEY);

			/* Returned by a verify callback. */
			ccb = jwt_checker_new();
			bad_cb_key = key;
			ck_assert_int_eq(jwt_checker_setcb(ccb, bad_key_cb,
							   NULL), 0);
			ck_assert_int_ne(jwt_checker_verify(ccb, keys[k].tok),
					 0);
			ck_assert_str_eq(jwt_checker_error_msg(ccb), ERR_KEY);

			/* In a keyring: the scan, the "kid", and a callback.
			 * #354: the scan has no compatible key (the errored key
			 * is skipped), the "kid" names no usable key, and the
			 * callback's errored key reports its own error. */
			cr = jwt_checker_new();
			ck_assert_int_eq(jwt_checker_setkeyring(cr, set,
				JWT_VERIFY_POLICY_ANY), 0);
			ck_assert_int_ne(jwt_checker_verify(cr, keys[k].tok), 0);
			ck_assert_int_gt(asprintf(&want_scan,
				"No keyring key can verify \"%s\"",
				jwt_alg_str(keys[k].alg)), 0);
			ck_assert_str_eq(jwt_checker_error_msg(cr), want_scan);
			ck_assert_int_ne(jwt_checker_verify(cr,
							    keys[k].tok_kid), 0);
			ck_assert_int_gt(asprintf(&want_kid,
				"No signature key with \"kid\" \"%s\" "
				"in the keyring", keys[k].kid), 0);
			ck_assert_str_eq(jwt_checker_error_msg(cr), want_kid);
			ck_assert_int_eq(jwt_checker_setcb(cr, bad_key_cb,
							   NULL), 0);
			ck_assert_int_ne(jwt_checker_verify(cr, keys[k].tok), 0);
			ck_assert_str_eq(jwt_checker_error_msg(cr), ERR_KEY);

			jwks_free(set);
		}
	}
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_xbackend");

	tcase_add_loop_test(tc_core, test_xbackend_sign_verify, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_jwe_rsa, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_jwe_ecdh, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_jwe_errored, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_free, 0, i);
	tcase_add_loop_test(tc_core, test_xbackend_errored_key, 0, i);

	tcase_set_timeout(tc_core, 60);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT cross-backend key affinity (#320)");
}
