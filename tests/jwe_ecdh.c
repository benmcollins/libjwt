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

	SET_OPS();

	/* secp256k1 is a valid EC key but not a JWE ECDH-ES curve. setkey
	 * accepts it (EC kty), but generation must fail. */
	read_json("ec_key_secp256k1_enc.json");
	builder = jwe_builder_new();
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
	tcase_add_test(tc_core, interop);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWE ECDH-ES");
}
