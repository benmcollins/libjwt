/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

static int count_dots(const char *s)
{
	int n = 0;
	for (; *s; s++)
		if (*s == '.')
			n++;
	return n;
}

static void roundtrip(const char *keyfile, jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json(keyfile);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES, enc,
					    g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* ECDH-ES (Direct) has an empty Encrypted Key (like dir). */
	ck_assert_int_eq(count_dots(tok), 4);
	ck_assert_ptr_nonnull(strstr(tok, ".."));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES, enc,
					    g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(rt_p256_gcm)
{
	SET_OPS();
	roundtrip("ec_key_prime256v1_enc.json", JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_p256_cbc)
{
	SET_OPS();
	roundtrip("ec_key_prime256v1_enc.json", JWE_ENC_A128CBC_HS256);
}
END_TEST

START_TEST(rt_p384)
{
	SET_OPS();
	roundtrip("ec_key_secp384r1_enc.json", JWE_ENC_A256GCM);
}
END_TEST

START_TEST(rt_p521)
{
	SET_OPS();
	roundtrip("ec_key_secp521r1_enc.json", JWE_ENC_A256GCM);
}
END_TEST

START_TEST(tamper_epk)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *hdr_end;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* The epk is in the protected header (first segment). Corrupting a
	 * header character changes both the agreed key and the AAD, so the
	 * decrypt must fail. */
	hdr_end = strchr(tok, '.');
	ck_assert_ptr_nonnull(hdr_end);
	/* Flip a char a few positions into the header (past kty/crv). */
	tok[20] = (tok[20] == 'A') ? 'B' : 'A';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(wrong_key)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	read_json("ec_key_prime256v1_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* A different P-256 key derives a different CEK -> tag fails. */
	read_json("ec_key_prime256v1.json");
	checker = jwe_checker_new();
	/* The stock key is use:sig, so setkey itself rejects it. */
	ck_assert_int_ne(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	(void)pt;
	(void)pt_len;
	free_key();
}
END_TEST

START_TEST(curve_mismatch)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	/* Encrypt to a P-256 recipient... */
	read_json("ec_key_prime256v1_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* ...decrypt with a P-384 key: the epk curve will not match. */
	read_json("ec_key_secp384r1_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	free_key();
}
END_TEST

/* @rfc{7518,4.6} ECDH-ES+A*KW: the agreed key wraps a generated CEK, carried
 * in a non-empty Encrypted Key segment. */
static void kw_roundtrip(jwe_key_alg_t alg, jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	/* Non-empty Encrypted Key (unlike Direct mode). */
	ck_assert_ptr_null(strstr(tok, ".."));

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(kw_128)
{
	SET_OPS();
	kw_roundtrip(JWE_ALG_ECDH_ES_A128KW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(kw_192)
{
	SET_OPS();
	kw_roundtrip(JWE_ALG_ECDH_ES_A192KW, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(kw_256)
{
	SET_OPS();
	kw_roundtrip(JWE_ALG_ECDH_ES_A256KW, JWE_ENC_A128CBC_HS256);
}
END_TEST

START_TEST(kw_tamper_ek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *ek;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Corrupt the Encrypted Key (2nd segment). @rfc{7516,11.5}: the unwrap
	 * fails, a random CEK is substituted, and the AEAD tag fails. */
	ek = strchr(tok, '.') + 1;
	ck_assert_int_ne(*ek, '.');
	*ek = (*ek == 'Q') ? 'R' : 'Q';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES_A256KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(kw_bad_base64_ek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL, *bad = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *first_dot, *second_dot;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Replace the Encrypted Key segment with non-base64url junk so the
	 * decode (not the unwrap) is what fails -> @rfc{7516,11.5} random CEK. */
	first_dot = strchr(tok, '.');
	second_dot = strchr(first_dot + 1, '.');
	ck_assert_int_gt(asprintf(&bad, "%.*s.@@@@%s",
				  (int)(first_dot - tok), tok, second_dot), 0);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, bad, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(kw_empty_ek_rejected)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES_A128KW,
					    JWE_ENC_A256GCM, g_item), 0);

	/* ECDH-ES+A128KW with an empty Encrypted Key is invalid. Header is
	 * base64url({"alg":"ECDH-ES+A128KW","enc":"A256GCM"}). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZHQ00ifQ..aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(decrypt_nonempty_ek)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL, *bad = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *first_dot;
	int ret;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	/* Splice a non-empty Encrypted Key into the (empty) second segment:
	 * replace "hdr.." with "hdr.X.". */
	first_dot = strstr(tok, "..");
	ck_assert_ptr_nonnull(first_dot);
	ret = asprintf(&bad, "%.*s.QUJD.%s",
		       (int)(first_dot - tok), tok, first_dot + 2);
	ck_assert_int_gt(ret, 0);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, bad, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

START_TEST(unsupported_curve)
{
	jwe_builder_auto_t *builder = NULL;
	char_auto *tok = NULL;
	int ret;

	SET_OPS();

	/* secp256k1 is a valid EC key but not a JWE ECDH-ES curve. setkey
	 * accepts it (EC kty), but generation must fail. */
	read_json("ec_key_secp256k1_enc.json");
	builder = jwe_builder_new();

	/* A backend that cannot load secp256k1 at all (GnuTLS, for one) leaves
	 * the key in error, and setkey refuses a key in error. */
	if (jwks_item_error(g_item)) {
		ret = jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					 JWE_ENC_A256GCM, g_item);
		ck_assert_int_eq(ret, 1);
		ck_assert_str_eq(jwe_builder_error_msg(builder),
				 "Key is in error and cannot be used for JWE");
		free_key();
		return;
	}

	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_null(tok);
	ck_assert_int_eq(jwe_builder_error(builder), 1);

	free_key();
}
END_TEST

START_TEST(missing_epk)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);

	/* ECDH-ES token with no "epk" in the header must be rejected. Header
	 * is base64url({"alg":"ECDH-ES","enc":"A256GCM"}). */
	pt = jwe_checker_decrypt(checker,
		"eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9..aa.bb.cc",
		&pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* @rfc{7518,4.6} ECDH-ES on the OKP X-curves (X25519/X448). */
static void okp_roundtrip(const char *keyfile, jwe_key_alg_t alg,
			  jwe_enc_t enc)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	read_json(keyfile);

	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, alg, enc, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, alg, enc, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}

START_TEST(x25519_direct)
{
	SET_OPS();
	if (gnutls_okp_jwk_broken(jwt_test_ops[_i].type))
		return;
	okp_roundtrip("okp_x25519_enc.json", JWE_ALG_ECDH_ES, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(x25519_cbc)
{
	SET_OPS();
	if (gnutls_okp_jwk_broken(jwt_test_ops[_i].type))
		return;
	okp_roundtrip("okp_x25519_enc.json", JWE_ALG_ECDH_ES,
		      JWE_ENC_A128CBC_HS256);
}
END_TEST

START_TEST(x25519_kw)
{
	SET_OPS();
	if (gnutls_okp_jwk_broken(jwt_test_ops[_i].type))
		return;
	okp_roundtrip("okp_x25519_enc.json", JWE_ALG_ECDH_ES_A256KW,
		      JWE_ENC_A256GCM);
}
END_TEST

START_TEST(x448_direct)
{
	SET_OPS();
	if (gnutls_okp_jwk_broken(jwt_test_ops[_i].type))
		return;
	okp_roundtrip("okp_x448_enc.json", JWE_ALG_ECDH_ES, JWE_ENC_A256GCM);
}
END_TEST

START_TEST(ed25519_rejected)
{
	jwe_builder_auto_t *builder = NULL;

	SET_OPS();

	/* An Ed25519 (signing) OKP key, even marked use:enc, must not be
	 * usable for ECDH-ES key agreement. */
	read_json("eddsa_key_ed25519_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_ne(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	free_key();
}
END_TEST

START_TEST(okp_curve_mismatch)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();

	if (gnutls_okp_jwk_broken(jwt_test_ops[_i].type))
		return;

	/* Encrypt to an X25519 recipient... */
	read_json("okp_x25519_enc.json");
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);
	free_key();

	/* ...decrypt with an X448 key: the epk curve will not match. */
	read_json("okp_x448_enc.json");
	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	free_key();
}
END_TEST

START_TEST(partyinfo)
{
	jwe_builder_auto_t *builder = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	const unsigned char apu[] = "Alice";
	const unsigned char apv[] = "Bob";

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	/* @rfc{7518,4.6.2} With apu/apv set, they are emitted in the header and
	 * bound into the Concat KDF. The same header carries them on decrypt,
	 * so the round-trip succeeds and "apu"/"apv" appear in the token. */
	builder = jwe_builder_new();
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	ck_assert_int_eq(jwe_builder_set_partyinfo(builder, apu, 5, apv, 3), 0);
	tok = jwe_builder_generate(builder, (const unsigned char *)PT,
				   strlen(PT));
	ck_assert_ptr_nonnull(tok);

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}
END_TEST

START_TEST(partyinfo_binds_kdf)
{
	jwe_builder_auto_t *b_with = NULL, *b_without = NULL;
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok_with = NULL, *tok_without = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0, hlen_with = 0, hlen_without = 0;
	const unsigned char apu[] = "Alice";

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	/* A token built WITH apu and one WITHOUT must have different protected
	 * headers (apu is present only in the first), proving it is emitted. */
	b_with = jwe_builder_new();
	jwe_builder_setkey(b_with, JWE_ALG_ECDH_ES, JWE_ENC_A256GCM, g_item);
	jwe_builder_set_partyinfo(b_with, apu, 5, NULL, 0);
	tok_with = jwe_builder_generate(b_with, (const unsigned char *)PT,
					strlen(PT));
	ck_assert_ptr_nonnull(tok_with);

	b_without = jwe_builder_new();
	jwe_builder_setkey(b_without, JWE_ALG_ECDH_ES, JWE_ENC_A256GCM, g_item);
	tok_without = jwe_builder_generate(b_without, (const unsigned char *)PT,
					   strlen(PT));
	ck_assert_ptr_nonnull(tok_without);

	/* Protected-header segments differ in length (apu adds a member). */
	hlen_with = strchr(tok_with, '.') - tok_with;
	hlen_without = strchr(tok_without, '.') - tok_without;
	ck_assert_int_ne(hlen_with, hlen_without);

	/* And the apu token round-trips (the same header carries apu, so the
	 * KDF agrees on both ends). */
	checker = jwe_checker_new();
	jwe_checker_setkey(checker, JWE_ALG_ECDH_ES, JWE_ENC_A256GCM, g_item);
	pt = jwe_checker_decrypt(checker, tok_with, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_mem_eq(pt, PT, strlen(PT));

	free(pt);
	free_key();
}
END_TEST

START_TEST(partyinfo_replace)
{
	jwe_builder_auto_t *builder = NULL;
	const unsigned char apu[] = "Alice";

	SET_OPS();
	read_json("ec_key_prime256v1_enc.json");

	builder = jwe_builder_new();
	/* Setting partyinfo (incl. replacing and NULL-clearing) and the
	 * NULL-object guard. */
	ck_assert_int_eq(jwe_builder_set_partyinfo(builder, apu, 5, NULL, 0), 0);
	ck_assert_int_eq(jwe_builder_set_partyinfo(builder, NULL, 0, apu, 5), 0);
	ck_assert_int_eq(jwe_builder_set_partyinfo(builder, NULL, 0, NULL, 0), 0);
	ck_assert_int_ne(jwe_builder_set_partyinfo(NULL, apu, 5, NULL, 0), 0);

	free_key();
}
END_TEST

/* @rfc{7518,C} External known-answer test for the ECDH-ES Concat KDF.
 *
 * RFC 7518 Appendix C gives a complete worked ECDH-ES key-agreement example:
 * P-256, AlgorithmID "A128GCM", apu="Alice" (QWxpY2U), apv="Bob" (Qm9i),
 * keydatalen 128, recipient (Bob) static key, ephemeral (epk) key, and the
 * resulting derived key "VqqN6vgjbSBcIijNcacQGg".
 *
 * We pin a complete ECDH-ES (Direct) + A128GCM compact token whose protected
 * header carries the RFC's exact epk/apu/apv, and whose A128GCM ciphertext was
 * produced with the RFC's derived key as the CEK (IV = 00010203...0B). The
 * recipient static key is tests/keys/ec_key_prime256v1_rfc7518_c_enc.json.
 *
 * Decrypting it proves libjwt's Concat KDF (concat_kdf() in the backends)
 * interoperates with the RFC vector: the agreement + KDF must reproduce the
 * exact CEK or the AEAD tag fails. It also proves the KDF is NIST SP 800-56A
 * Concat (HKDF or any other KDF would derive a different CEK and fail), and
 * that apu/apv are bound into the derivation. ECDH-ES is curve-deterministic,
 * so this holds identically under every crypto backend (loop test). */
static const char KAT_RFC7518_C[] =
	"eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImFwdSI6IlFXeHBZMlUiLCJh"
	"cHYiOiJRbTlpIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZ0kw"
	"R0FJTEJkdTdUNTNha3JGbU15R2NzRjNuNWRPN01td05CSEtXNVNWMCIsInkiOiJTTFdf"
	"eFNmZnpsUFdySEVWSTMwREhNXzRlZ1Z3dDNOUXFlVUQ3bk1GcHBzIn19.."
	"AAECAwQFBgcICQoL.D6lxkS_zkJKLMA4lGrsPj16kHZ1qXO2XjTYGJWBrlcF-EICbruU."
	"L12narVF24e8QZRi0iUg2A";

START_TEST(kat_rfc7518_appc)
{
	jwe_checker_auto_t *checker = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;

	SET_OPS();
	read_json("ec_key_prime256v1_rfc7518_c_enc.json");

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A128GCM, g_item), 0);

	/* The CEK is fixed by the RFC's agreement + Concat KDF; the GCM tag only
	 * verifies if libjwt derives byte-for-byte the same key. PT is the same
	 * plaintext encrypted into the pinned token. */
	pt = jwe_checker_decrypt(checker, KAT_RFC7518_C, &pt_len);
	ck_assert_ptr_nonnull(pt);
	ck_assert_int_eq(pt_len, strlen(PT));
	ck_assert_mem_eq(pt, PT, pt_len);

	free(pt);
	free_key();
}
END_TEST

START_TEST(kat_rfc7518_appc_tampered_hdr)
{
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	char *dot;

	SET_OPS();
	read_json("ec_key_prime256v1_rfc7518_c_enc.json");

	tok = strdup(KAT_RFC7518_C);
	ck_assert_ptr_nonnull(tok);

	/* Corrupt one byte deep inside the protected header (the base64url of the
	 * JSON carrying alg/enc/apu/apv/epk). The header determines both the
	 * Concat KDF inputs and the AAD, so any change makes the derived CEK and
	 * the AEAD tag disagree with the RFC vector and decryption must fail.
	 * This guards against a vacuous pass: the KAT only succeeds with the exact
	 * agreement + KDF the RFC specifies, not regardless of input. */
	dot = strchr(tok, '.');
	ck_assert_ptr_nonnull(dot);
	ck_assert_int_gt(dot - tok, 80);
	tok[80] = (tok[80] == 'A') ? 'B' : 'A';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A128GCM, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* Every content encryption algorithm. ECDH-ES (Direct) derives a CEK of the
 * enc's length: 16/24/32 octets for AES-GCM and 32/48/64 for AES-CBC-HMAC, so
 * A192CBC-HS384 and A256CBC-HS512 need more than one Concat KDF round. */
static const jwe_enc_t ALL_ENCS[] = {
	JWE_ENC_A128GCM, JWE_ENC_A192GCM, JWE_ENC_A256GCM,
	JWE_ENC_A128CBC_HS256, JWE_ENC_A192CBC_HS384, JWE_ENC_A256CBC_HS512,
};

/* @rfc{7518,4.6.2} ECDH-ES (Direct) round-trips with every enc on every NIST
 * curve under the active backend. */
START_TEST(rt_ec_all_enc)
{
	static const char *const keys[] = {
		"ec_key_prime256v1_enc.json",
		"ec_key_secp384r1_enc.json",
		"ec_key_secp521r1_enc.json",
	};
	size_t k, e;

	SET_OPS();

	for (k = 0; k < ARRAY_SIZE(keys); k++)
		for (e = 0; e < ARRAY_SIZE(ALL_ENCS); e++)
			roundtrip(keys[k], ALL_ENCS[e]);
}
END_TEST

/* The same on the OKP X-curves (skipped where the backend cannot load them). */
START_TEST(rt_okp_all_enc)
{
	static const char *const keys[] = {
		"okp_x25519_enc.json",
		"okp_x448_enc.json",
	};
	size_t k, e;

	SET_OPS();
	if (gnutls_okp_jwk_broken(jwt_test_ops[_i].type))
		return;

	for (k = 0; k < ARRAY_SIZE(keys); k++)
		for (e = 0; e < ARRAY_SIZE(ALL_ENCS); e++)
			okp_roundtrip(keys[k], JWE_ALG_ECDH_ES, ALL_ENCS[e]);
}
END_TEST

/* External known-answer vectors: Project Wycheproof
 * testvectors_v1/json_web_encryption_test.json (C2SP/wycheproof on GitHub),
 * test group "jwe_ec", tcIds 78-81 ("acceptsEcdhEsA256Gcm",
 * "acceptsEcdhEsA128CbcHs256", "acceptsEcdhEsA192CbcHs384",
 * "acceptsEcdhEsA256CbcHs512"), all "result": "valid". The group's private
 * key is the RFC 7518 Appendix C P-256 "Bob" key, i.e.
 * tests/keys/ec_key_prime256v1_rfc7518_c_enc.json, and every plaintext is
 * "foo" (hex 666f6f). tcIds 80 and 81 need a 48- and a 64-octet CEK, so they
 * only decrypt with the full multi-round Concat KDF. */
static const struct {
	jwe_enc_t enc;
	const char *jwe;
} WYCHEPROOF_ECDH_ES[] = {
	/* tcId 78 */
	{ JWE_ENC_A256GCM,
	  "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJrdHkiOiJF"
	  "QyIsIngiOiJVVG5YNXUtdFBIdG1pOEFpN0gxV3dXODl2RG5Fc2lpVkdtNkU2Z2l0"
	  "d3hZIiwieSI6InhKN296QjdDYzZpcWtTYnJXMDRvTUZDNEFMWE9Sd1VzTTBvdUZj"
	  "cU55QUkiLCJjcnYiOiJQLTI1NiJ9fQ..iNb-34xvFG8M4MI5.6RXw."
	  "EBpJ0EC39zNuSyZqSFMlvw" },
	/* tcId 79 */
	{ JWE_ENC_A128CBC_HS256,
	  "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJr"
	  "dHkiOiJFQyIsIngiOiJaYVVtQUQ3UXM2VkQzQmUyVTVNZmRYcS1mbHhWQWZfTW5o"
	  "dVFNYzFEXzZVIiwieSI6InR5ck5FOFl6eFU3UTZ5SHMwcUFELV9TMlFkY1BXdDg2"
	  "anlNS1BUZUdibGciLCJjcnYiOiJQLTI1NiJ9fQ..ANTia7KFASPuVluJoWzksA."
	  "kyivxxBQM412o5J8yrgGTQ.D-aHzy07zhj3nMBauohSTA" },
	/* tcId 80 */
	{ JWE_ENC_A192CBC_HS384,
	  "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTE5MkNCQy1IUzM4NCIsImVwayI6eyJr"
	  "dHkiOiJFQyIsIngiOiJhNG1GMGlQZTA1RnFRcXV4RU41U0hEWjdreDdJaVhMTlkw"
	  "WXpsWnJ4V2ZzIiwieSI6Im5pN0JhUTd5d2YyaWllX2NpZ18tWnB3Z3J6RkxIcHgx"
	  "cmptQlNfcmV3eFEiLCJjcnYiOiJQLTI1NiJ9fQ..Y5DdmICU3_O-mzSVsPxNvg."
	  "Y6evmTZ14UUyCeZLND-AFA._1W6s7XJ091oDyX4x_WNdwe62sHIAUUj" },
	/* tcId 81 */
	{ JWE_ENC_A256CBC_HS512,
	  "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJr"
	  "dHkiOiJFQyIsIngiOiJrZGU4dnFQZjRkQnpXdE9BMmZPdnlHeW9TUWV1MUNaUHVr"
	  "MXh0dFl6NDN3IiwieSI6ImhldDhvbGZMWUFJc1h3aWxYTjlZYWpnVDhELV9fVk1L"
	  "eTlIQUVKYXJtaGsiLCJjcnYiOiJQLTI1NiJ9fQ..0G12ehbKyO5OUQ-ZaNOo2w."
	  "S2GLVuQMMV_GMwej3KQclA.4xn4IsvQz_3qhfOWHSGdBkmkCY3Q_chXPKekt4tbadA" },
};

START_TEST(kat_wycheproof_ecdh_es)
{
	size_t v;

	SET_OPS();
	read_json("ec_key_prime256v1_rfc7518_c_enc.json");

	for (v = 0; v < ARRAY_SIZE(WYCHEPROOF_ECDH_ES); v++) {
		jwe_checker_auto_t *checker = NULL;
		unsigned char *pt = NULL;
		size_t pt_len = 0;

		checker = jwe_checker_new();
		ck_assert_ptr_nonnull(checker);
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					WYCHEPROOF_ECDH_ES[v].enc, g_item), 0);
		pt = jwe_checker_decrypt(checker, WYCHEPROOF_ECDH_ES[v].jwe,
					 &pt_len);
		ck_assert_msg(pt != NULL, "Wycheproof vector %zu: %s", v,
			      jwe_checker_error_msg(checker));
		ck_assert_int_eq(pt_len, 3);
		ck_assert_mem_eq(pt, "foo", 3);
		free(pt);
	}

	free_key();
}
END_TEST

/* @rfc{7518,4.6.2} Multi-round Concat KDF known answers, with PartyInfo.
 *
 * Inputs are the RFC 7518 Appendix C keys: Bob's static P-256 key
 * (tests/keys/ec_key_prime256v1_rfc7518_c_enc.json) and Alice's ephemeral
 * key (d = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo", whose public half
 * is the epk below), apu = "Alice", apv = "Bob". The shared secret is
 *
 *   Z = 9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4
 *
 * The expected CEKs were computed independently in Python with hashlib, as
 * SHA-256(counter || Z || OtherInfo) for counter = 1, 2 (32-bit big-endian),
 * concatenated and truncated, where OtherInfo = len32("enc") || "enc" ||
 * len32("Alice") || "Alice" || len32("Bob") || "Bob" || be32(keydatalen*8)
 * (the same code reproduces the RFC's A128GCM key "VqqN6vgjbSBcIijNcacQGg"):
 *
 *   A192CBC-HS384 (48 octets):
 *     60597bbf9eb991c5162f19f3728c27440a74602fa26ace48796b6a9322dd13cb
 *     c26d50be3342992dccb45c81a7b5d5b7
 *   A256CBC-HS512 (64 octets):
 *     3986aa79f6396420e580e5d3890f623fee5d4522307929eb99ee3425a001ecc1
 *     75b1754e3fb644ce825034b562523e9a8806bca8d76afa861e9b79515803225d
 *
 * Each token was then produced in Python (the "cryptography" package's
 * AES-CBC + hmac) with that CEK, IV = 000102...0f, and PT as the plaintext.
 * Decrypting it proves the derived CEK matches byte-for-byte, including the
 * second-round octets, the counter and the SuppPubInfo bit length. */
static const struct {
	jwe_enc_t enc;
	const char *jwe;
} KAT_KDF_MULTIROUND[] = {
	{ JWE_ENC_A192CBC_HS384,
	  "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTE5MkNCQy1IUzM4NCIsImFwdSI6IlFX"
	  "eHBZMlUiLCJhcHYiOiJRbTlpIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0y"
	  "NTYiLCJ4IjoiZ0kwR0FJTEJkdTdUNTNha3JGbU15R2NzRjNuNWRPN01td05CSEtX"
	  "NVNWMCIsInkiOiJTTFdfeFNmZnpsUFdySEVWSTMwREhNXzRlZ1Z3dDNOUXFlVUQ3"
	  "bk1GcHBzIn19..AAECAwQFBgcICQoLDA0ODw."
	  "k3CGlw6wNbJbH4CYiReAWUQ98Gu7MVt5-AHwsvmd93gyVxcZQWznNquqiz0eZgrD."
	  "Uff00h9HF8A81dM0glAagsjLiPEmymr-" },
	{ JWE_ENC_A256CBC_HS512,
	  "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImFwdSI6IlFX"
	  "eHBZMlUiLCJhcHYiOiJRbTlpIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0y"
	  "NTYiLCJ4IjoiZ0kwR0FJTEJkdTdUNTNha3JGbU15R2NzRjNuNWRPN01td05CSEtX"
	  "NVNWMCIsInkiOiJTTFdfeFNmZnpsUFdySEVWSTMwREhNXzRlZ1Z3dDNOUXFlVUQ3"
	  "bk1GcHBzIn19..AAECAwQFBgcICQoLDA0ODw."
	  "CJ5u-ciUOxeguYydCd9VPMunOxHZpG1XJi6Bq8m-cosRB033wPsqRh5XvvkOlumA."
	  "EYntgD2b88j52vEUdjcVLYs_0AtnshvLJLRIuu71KAQ" },
};

START_TEST(kat_kdf_multiround)
{
	size_t v;

	SET_OPS();
	read_json("ec_key_prime256v1_rfc7518_c_enc.json");

	for (v = 0; v < ARRAY_SIZE(KAT_KDF_MULTIROUND); v++) {
		jwe_checker_auto_t *checker = NULL;
		unsigned char *pt = NULL;
		size_t pt_len = 0;

		checker = jwe_checker_new();
		ck_assert_ptr_nonnull(checker);
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					KAT_KDF_MULTIROUND[v].enc, g_item), 0);
		pt = jwe_checker_decrypt(checker, KAT_KDF_MULTIROUND[v].jwe,
					 &pt_len);
		ck_assert_msg(pt != NULL, "KDF KAT %zu: %s", v,
			      jwe_checker_error_msg(checker));
		ck_assert_int_eq(pt_len, strlen(PT));
		ck_assert_mem_eq(pt, PT, pt_len);
		free(pt);
	}

	free_key();
}
END_TEST

/* Guard against a vacuous pass: the A256CBC-HS512 KAT with one authentication
 * tag character corrupted must be rejected. (A KDF whose second round were
 * wrong would derive a bad AES key half, which the plaintext check above
 * catches; this checks the MAC half is really enforced.) */
START_TEST(kat_kdf_multiround_tampered)
{
	jwe_checker_auto_t *checker = NULL;
	char_auto *tok = NULL;
	unsigned char *pt = NULL;
	size_t pt_len = 0, len;

	SET_OPS();
	read_json("ec_key_prime256v1_rfc7518_c_enc.json");

	tok = strdup(KAT_KDF_MULTIROUND[1].jwe);
	ck_assert_ptr_nonnull(tok);
	len = strlen(tok);
	tok[len - 2] = (tok[len - 2] == 'A') ? 'B' : 'A';

	checker = jwe_checker_new();
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256CBC_HS512, g_item), 0);
	pt = jwe_checker_decrypt(checker, tok, &pt_len);
	ck_assert_ptr_null(pt);
	ck_assert_int_eq(jwe_checker_error(checker), 1);

	free_key();
}
END_TEST

/* Both backends route ECDH-ES to the OpenSSL EVP_PKEY, so a token from one
 * provider must decrypt under all. */
START_TEST(interop)
{
	char_auto *tok = NULL;
	size_t b;

	if (ARRAY_SIZE(jwt_test_ops) < 2)
		return;

	ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[0].name), 0);
	read_json("ec_key_prime256v1_enc.json");
	{
		jwe_builder_auto_t *builder = jwe_builder_new();
		ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					JWE_ENC_A256GCM, g_item), 0);
		tok = jwe_builder_generate(builder, (const unsigned char *)PT,
					   strlen(PT));
		ck_assert_ptr_nonnull(tok);
	}
	free_key();

	for (b = 0; b < ARRAY_SIZE(jwt_test_ops); b++) {
		jwe_checker_auto_t *checker = NULL;
		unsigned char *pt = NULL;
		size_t pt_len = 0;

		ck_assert_int_eq(jwt_set_crypto_ops(jwt_test_ops[b].name), 0);
		read_json("ec_key_prime256v1_enc.json");
		checker = jwe_checker_new();
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					JWE_ENC_A256GCM, g_item), 0);
		pt = jwe_checker_decrypt(checker, tok, &pt_len);
		ck_assert_ptr_nonnull(pt);
		ck_assert_mem_eq(pt, PT, strlen(PT));
		free(pt);
		free_key();
	}
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("JWE ECDH-ES");

	tcase_add_loop_test(tc_core, rt_p256_gcm, 0, i);
	tcase_add_loop_test(tc_core, rt_p256_cbc, 0, i);
	tcase_add_loop_test(tc_core, rt_p384, 0, i);
	tcase_add_loop_test(tc_core, rt_p521, 0, i);
	tcase_add_loop_test(tc_core, tamper_epk, 0, i);
	tcase_add_loop_test(tc_core, wrong_key, 0, i);
	tcase_add_loop_test(tc_core, curve_mismatch, 0, i);
	tcase_add_loop_test(tc_core, kw_128, 0, i);
	tcase_add_loop_test(tc_core, kw_192, 0, i);
	tcase_add_loop_test(tc_core, kw_256, 0, i);
	tcase_add_loop_test(tc_core, kw_tamper_ek, 0, i);
	tcase_add_loop_test(tc_core, kw_bad_base64_ek, 0, i);
	tcase_add_loop_test(tc_core, kw_empty_ek_rejected, 0, i);
	tcase_add_loop_test(tc_core, decrypt_nonempty_ek, 0, i);
	tcase_add_loop_test(tc_core, unsupported_curve, 0, i);
	tcase_add_loop_test(tc_core, missing_epk, 0, i);
	tcase_add_loop_test(tc_core, x25519_direct, 0, i);
	tcase_add_loop_test(tc_core, x25519_cbc, 0, i);
	tcase_add_loop_test(tc_core, x25519_kw, 0, i);
	tcase_add_loop_test(tc_core, x448_direct, 0, i);
	tcase_add_loop_test(tc_core, ed25519_rejected, 0, i);
	tcase_add_loop_test(tc_core, okp_curve_mismatch, 0, i);
	tcase_add_loop_test(tc_core, partyinfo, 0, i);
	tcase_add_loop_test(tc_core, partyinfo_binds_kdf, 0, i);
	tcase_add_loop_test(tc_core, partyinfo_replace, 0, i);
	tcase_add_loop_test(tc_core, kat_rfc7518_appc, 0, i);
	tcase_add_loop_test(tc_core, kat_rfc7518_appc_tampered_hdr, 0, i);
	tcase_add_loop_test(tc_core, rt_ec_all_enc, 0, i);
	tcase_add_loop_test(tc_core, rt_okp_all_enc, 0, i);
	tcase_add_loop_test(tc_core, kat_wycheproof_ecdh_es, 0, i);
	tcase_add_loop_test(tc_core, kat_kdf_multiround, 0, i);
	tcase_add_loop_test(tc_core, kat_kdf_multiround_tampered, 0, i);
	tcase_add_test(tc_core, interop);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE ECDH-ES");
}
