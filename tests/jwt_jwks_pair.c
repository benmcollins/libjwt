/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* A private JWK that also states its public key.
 *
 * An OKP key (RFC 8037) carries "x" next to its "d", an AKP key (ML-DSA) "pub"
 * next to its "priv". OpenSSL and GnuTLS make the key object from the private
 * member alone, while the thumbprint, the public export and whoever reads the
 * JWK go by the public member. If the two disagreed, the key that signs and
 * verifies would not be the key the item claims to be, and a checker pinned to
 * a thumbprint would verify with somebody else's key. Such a JWK must not
 * load.
 *
 * The keys are put together here from the members of the pairs in tests/keys.
 * Any octet string of the right length is an OKP private key, and "x" and "d"
 * are equally long on every curve, so a pair's own "x" does duty as somebody
 * else's "d", and its "d" as somebody else's "x". */

#define MISMATCH_OKP	"OKP private key does not match its public key"
#define NOT_CONFIRMED	"Embedded JWK is missing or not confirmed"
#define IN_ERROR	"Key is in error and cannot be used"

static const char PT[] = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}";

/* How a key type spells its members. */
struct kind {
	const char *kty;
	const char *sel;	/* the member that picks the curve or variant */
	const char *pub;
	const char *priv;
};

static const struct kind OKP = { "OKP", "crv", "x", "d" };

static const struct {
	const char *crv;
	const char *pub;	/* the file with the "x" of a pair...	*/
	const char *priv;	/* ...and the one with its "d"		*/
	int ecdh;		/* an X curve: key agreement only	*/
} okp[] = {
	{ "Ed25519", "eddsa_key_ed25519.json", "eddsa_key_ed25519.json", 0 },
	{ "Ed448", "eddsa_key_ed448_pub.json", "eddsa_key_ed448.json", 0 },
	{ "X25519", "okp_x25519_enc.json", "okp_x25519_enc.json", 1 },
	{ "X448", "okp_x448_enc.json", "okp_x448_enc.json", 1 },
};

/* Which of the two rules a backend is held to. OpenSSL and GnuTLS make a
 * private OKP key from "d" alone, so they have to hold "x" against it
 * (test_okp_pair_mismatch). MbedTLS keeps the two members as they come and uses
 * each for its own half of a key agreement (test_okp_members_apart). That is
 * how LibJWT's backends are written, not what a crypto library can or cannot
 * do, and it is not probed for: the probe would be the check under test. */
static int key_from_private(jwt_crypto_provider_t type)
{
	return type != JWT_CRYPTO_OPS_MBEDTLS;
}

/* The value of the string member @name in tests/keys/@file. The caller frees
 * it. */
static char *member(const char *file, const char *name)
{
	char *path, *text, *pat, *p, *end, *val;
	long size;
	FILE *fp;

	ck_assert_int_gt(asprintf(&path, KEYDIR "/%s", file), 0);
	fp = fopen(path, "r");
	free(path);
	ck_assert_ptr_nonnull(fp);
	ck_assert_int_eq(fseek(fp, 0, SEEK_END), 0);
	size = ftell(fp);
	ck_assert_int_gt(size, 0);
	rewind(fp);

	text = malloc(size + 1);
	ck_assert_ptr_nonnull(text);
	ck_assert_uint_eq(fread(text, 1, size, fp), (size_t)size);
	fclose(fp);
	text[size] = '\0';

	/* "name": "value" */
	ck_assert_int_gt(asprintf(&pat, "\"%s\"", name), 0);
	p = strstr(text, pat);
	ck_assert_ptr_nonnull(p);
	p = strchr(p + strlen(pat), '"');
	ck_assert_ptr_nonnull(p);
	end = strchr(++p, '"');
	ck_assert_ptr_nonnull(end);
	val = strndup(p, end - p);
	ck_assert_ptr_nonnull(val);

	free(pat);
	free(text);

	return val;
}

/* A JWK of kind @k for the curve or variant @which. @pub is the JSON text of
 * its public member and @priv the base64url of its private one; NULL leaves
 * the member out. The caller frees it. */
static char *jwk_raw(const struct kind *k, const char *which, const char *pub,
		     const char *priv)
{
	char_auto *m_pub = NULL, *m_priv = NULL;
	char *json;

	if (pub != NULL)
		ck_assert_int_gt(asprintf(&m_pub, ",\"%s\":%s", k->pub,
					  pub), 0);
	if (priv != NULL)
		ck_assert_int_gt(asprintf(&m_priv, ",\"%s\":\"%s\"", k->priv,
					  priv), 0);
	ck_assert_int_gt(asprintf(&json, "{\"kty\":\"%s\",\"%s\":\"%s\"%s%s}",
				  k->kty, k->sel, which, m_pub ? m_pub : "",
				  m_priv ? m_priv : ""), 0);

	return json;
}

/* The same with @pub given as base64url, like @priv. */
static char *jwk(const struct kind *k, const char *which, const char *pub,
		 const char *priv)
{
	char_auto *quoted = NULL;

	if (pub != NULL)
		ck_assert_int_gt(asprintf(&quoted, "\"%s\"", pub), 0);

	return jwk_raw(k, which, quoted, priv);
}

/* @b64 with one character replaced: the first one or, for @end, the last one
 * that holds six bits of the value, which is the one before the last. Still
 * base64url of the same length. The caller frees it. */
static char *tweak(const char *b64, int end)
{
	size_t at = end ? strlen(b64) - 2 : 0;
	char *out = strdup(b64);

	ck_assert_ptr_nonnull(out);
	out[at] = out[at] == 'A' ? 'B' : 'A';

	return out;
}

/* Load the JWK @json, which is freed. The caller frees the set. */
static jwk_set_t *load(char *json)
{
	char_auto *owned = json;
	jwk_set_t *set = jwks_create(owned);

	ck_assert_ptr_nonnull(set);
	ck_assert_ptr_nonnull(jwks_item_get(set, 0));

	return set;
}

/* The JWK @json (freed) must load as a key, private or not as @priv says. The
 * caller frees the set. */
static jwk_set_t *good(char *json, int priv)
{
	jwk_set_t *set = load(json);
	const jwk_item_t *item = jwks_item_get(set, 0);

	ck_assert_msg(jwks_item_error(item) == 0, "%s",
		      jwks_item_error_msg(item));
	ck_assert_int_eq(jwks_item_is_private(item), priv);

	return set;
}

/* The JWK @json (freed) must be in error, with @msg if that is not NULL,
 * describe no key and, like every key in error, be of no use. */
static void bad(char *json, const char *msg)
{
	jwk_set_auto_t *set = load(json);
	const jwk_item_t *item = jwks_item_get(set, 0);
	jwt_builder_auto_t *builder = jwt_builder_new();
	jwt_checker_auto_t *checker = jwt_checker_new();
	jwe_builder_auto_t *enc = jwe_builder_new();
	jwe_checker_auto_t *dec = jwe_checker_new();
	char_auto *tp = NULL;

	ck_assert_int_ne(jwks_item_error(item), 0);
	if (msg != NULL)
		ck_assert_str_eq(jwks_item_error_msg(item), msg);

	ck_assert_int_eq(jwks_item_is_private(item), 0);
	ck_assert_int_eq(jwks_item_key_bits(item), 0);
	ck_assert_ptr_null(jwks_item_pem(item));

	/* Nor does it go by the thumbprint of the key it states. */
	tp = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_null(tp);

	/* Nothing signs, verifies, encrypts or decrypts with it. */
	ck_assert_ptr_nonnull(builder);
	ck_assert_ptr_nonnull(checker);
	ck_assert_ptr_nonnull(enc);
	ck_assert_ptr_nonnull(dec);
	ck_assert_int_ne(jwt_builder_setkey(builder, JWT_ALG_NONE, item), 0);
	ck_assert_str_eq(jwt_builder_error_msg(builder), IN_ERROR);
	ck_assert_int_ne(jwt_checker_setkey(checker, JWT_ALG_NONE, item), 0);
	ck_assert_str_eq(jwt_checker_error_msg(checker), IN_ERROR);
	ck_assert_int_ne(jwe_builder_setkey(enc, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, item), 0);
	ck_assert_str_eq(jwe_builder_error_msg(enc), IN_ERROR " for JWE");
	ck_assert_int_ne(jwe_checker_setkey(dec, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, item), 0);
	ck_assert_str_eq(jwe_checker_error_msg(dec), IN_ERROR " for JWE");
}

/* A token signed with @key. @hdr, if not NULL, is the JSON of its "jwk" header.
 * The caller frees it. */
static char *sign(const jwk_item_t *key, jwt_alg_t alg, char *hdr)
{
	jwt_builder_auto_t *builder = jwt_builder_new();
	jwt_value_t v;
	char *token;

	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setkey(builder, alg, key), 0);
	if (hdr != NULL) {
		jwt_set_SET_JSON(&v, "jwk", hdr);
		ck_assert_int_eq(jwt_builder_header_set(builder, &v),
				 JWT_VALUE_ERR_NONE);
	}

	token = jwt_builder_generate(builder);
	ck_assert_msg(token != NULL, "%s", jwt_builder_error_msg(builder));

	return token;
}

/* @token must verify with @key. */
static void verifies(const jwk_item_t *key, jwt_alg_t alg, const char *token)
{
	jwt_checker_auto_t *checker = jwt_checker_new();

	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwt_checker_setkey(checker, alg, key), 0);
	ck_assert_msg(jwt_checker_verify(checker, token) == 0, "%s",
		      jwt_checker_error_msg(checker));
}

/* Whether the active backend signs with the private Ed25519 or Ed448 key
 * @key. Not every backend has EdDSA, and one without it loads the keys all the
 * same. */
static int signs_eddsa(const jwk_item_t *key)
{
	jwt_builder_auto_t *builder = jwt_builder_new();
	char_auto *token = NULL;

	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_EDDSA, key), 0);
	token = jwt_builder_generate(builder);

	return token != NULL;
}

/* Verify @token by its header key, confirmed by the pin @jkt or, if that is
 * NULL, by the allow-list @ring. It must verify if @ok and otherwise fail at
 * the confirmation of the header key. */
static void embedded(const char *token, const char *jkt, const jwk_set_t *ring,
		     int ok)
{
	jwt_checker_auto_t *checker = jwt_checker_new();
	int ret;

	ck_assert_ptr_nonnull(checker);
	if (jkt != NULL)
		ret = jwt_checker_enable_embedded_jwk(checker,
					JWK_THUMBPRINT_SHA256, jkt);
	else
		ret = jwt_checker_enable_embedded_jwk_keyring(checker,
					JWK_THUMBPRINT_SHA256, ring);
	ck_assert_int_eq(ret, 0);

	ret = jwt_checker_verify(checker, token);
	if (ok) {
		ck_assert_msg(ret == 0, "%s", jwt_checker_error_msg(checker));
	} else {
		ck_assert_int_ne(ret, 0);
		ck_assert_str_eq(jwt_checker_error_msg(checker), NOT_CONFIRMED);
	}
}

/* What the rule is there to stop. @victim is somebody's public JWK and @forged
 * the same with the attacker's private member added: it has the victim's
 * thumbprint, and without the rule it verifies what the attacker signs. A token
 * signed with @attacker that carries @forged as its header key must not pass a
 * checker that trusts @victim, by pin or by allow-list. All three are JSON and
 * are freed. */
static void forgery(char *victim, char *attacker, char *forged, jwt_alg_t alg)
{
	jwk_set_auto_t *ring = good(victim, 0);
	jwk_set_auto_t *signer = good(attacker, 1);
	char_auto *hdr = forged;
	char_auto *jkt = NULL, *token = NULL;

	jkt = jwks_item_thumbprint(jwks_item_get(ring, 0),
				   JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	token = sign(jwks_item_get(signer, 0), alg, hdr);

	embedded(token, jkt, NULL, 0);
	embedded(token, NULL, ring, 0);
}

/* What the owner of @pair (a private JWK, as JSON, freed) sends: its public
 * key @pub (JSON, freed) in the header of a token it signed. That passes, by
 * pin and by allow-list. */
static void honest(char *pub, char *pair, jwt_alg_t alg)
{
	char_auto *hdr = strdup(pub);
	jwk_set_auto_t *ring = good(pub, 0);
	jwk_set_auto_t *signer = good(pair, 1);
	char_auto *jkt = NULL, *token = NULL;

	ck_assert_ptr_nonnull(hdr);
	jkt = jwks_item_thumbprint(jwks_item_get(ring, 0),
				   JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	token = sign(jwks_item_get(signer, 0), alg, hdr);

	embedded(token, jkt, NULL, 1);
	embedded(token, NULL, ring, 1);
}

/* An ECDH-ES token for @key. The caller frees it. */
static char *encrypt_to(const jwk_item_t *key)
{
	jwe_builder_auto_t *builder = jwe_builder_new();
	char *token;

	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, key), 0);
	token = jwe_builder_generate(builder, (const unsigned char *)PT,
				     strlen(PT));
	ck_assert_msg(token != NULL, "%s", jwe_builder_error_msg(builder));

	return token;
}

/* Whether @key decrypts @token. */
static int decrypts(const jwk_item_t *key, const char *token)
{
	jwe_checker_auto_t *checker = jwe_checker_new();
	unsigned char *pt;
	size_t len = 0;
	int ok;

	ck_assert_ptr_nonnull(checker);
	ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					    JWE_ENC_A256GCM, key), 0);
	pt = jwe_checker_decrypt(checker, token, &len);
	ok = pt != NULL && len == strlen(PT) && !memcmp(pt, PT, len);
	free(pt);

	return ok;
}

/* A pair that does match, its public half and its private member alone all
 * load as they did before, and are one and the same key. */
START_TEST(test_okp_pair)
{
	jwt_crypto_provider_t type = jwt_test_ops[_i].type;
	size_t n;

	SET_OPS();

	for (n = 0; n < ARRAY_SIZE(okp); n++) {
		const char *crv = okp[n].crv;
		jwk_set_auto_t *pair = NULL, *pub = NULL, *seed = NULL;
		char_auto *x = NULL, *d = NULL, *tp = NULL, *tp_pub = NULL;
		char_auto *token = NULL;

		/* GnuTLS < 3.8.13 cannot do X25519 or X448 and refuses them. */
		if (okp[n].ecdh && gnutls_okp_jwk_broken(type))
			continue;

		x = member(okp[n].pub, "x");
		d = member(okp[n].priv, "d");

		pair = good(jwk(&OKP, crv, x, d), 1);
		pub = good(jwk(&OKP, crv, x, NULL), 0);

		tp = jwks_item_thumbprint(jwks_item_get(pair, 0),
					  JWK_THUMBPRINT_SHA256);
		tp_pub = jwks_item_thumbprint(jwks_item_get(pub, 0),
					      JWK_THUMBPRINT_SHA256);
		ck_assert_ptr_nonnull(tp);
		ck_assert_ptr_nonnull(tp_pub);
		ck_assert_str_eq(tp, tp_pub);

		/* Nor can it load a private key without its "x". */
		if (!gnutls_okp_jwk_broken(type))
			seed = good(jwk(&OKP, crv, NULL, d), 1);

		if (okp[n].ecdh) {
			token = encrypt_to(jwks_item_get(pub, 0));
			ck_assert(decrypts(jwks_item_get(pair, 0), token));
			if (seed != NULL)
				ck_assert(decrypts(jwks_item_get(seed, 0),
						   token));
		} else if (signs_eddsa(jwks_item_get(pair, 0))) {
			token = sign(jwks_item_get(seed ? seed : pair, 0),
				     JWT_ALG_EDDSA, NULL);
			verifies(jwks_item_get(pub, 0), JWT_ALG_EDDSA, token);
			verifies(jwks_item_get(pair, 0), JWT_ALG_EDDSA, token);
		}
	}
}
END_TEST

/* A private key whose "x" is not the public key of its "d" is in error. */
START_TEST(test_okp_pair_mismatch)
{
	jwt_crypto_provider_t type = jwt_test_ops[_i].type;
	size_t n;

	SET_OPS();

	if (!key_from_private(type))
		return;

	for (n = 0; n < ARRAY_SIZE(okp); n++) {
		const char *crv = okp[n].crv;
		char_auto *x = NULL, *d = NULL, *x1 = NULL, *x2 = NULL;
		char_auto *x_long = NULL, *x_short = NULL;

		if (okp[n].ecdh && gnutls_okp_jwk_broken(type))
			continue;

		x = member(okp[n].pub, "x");
		d = member(okp[n].priv, "d");

		/* Somebody's public key with another private key: the JWK
		 * that verified the other key's signatures under this "x". */
		bad(jwk(&OKP, crv, x, x), MISMATCH_OKP);

		/* The other way around, and an "x" that is off by one
		 * character, at its start or at its end. They need not be
		 * points on the curve, which a library is free to say first. */
		x1 = tweak(x, 0);
		x2 = tweak(x, 1);
		bad(jwk(&OKP, crv, d, d), NULL);
		bad(jwk(&OKP, crv, x1, d), NULL);
		bad(jwk(&OKP, crv, x2, d), NULL);

		/* An "x" of another length that begins like the right one. */
		ck_assert_int_gt(asprintf(&x_long, "%sAAAA", x), 0);
		x_short = strndup(x, strlen(x) - 4);
		ck_assert_ptr_nonnull(x_short);
		bad(jwk(&OKP, crv, x_long, d), NULL);
		bad(jwk(&OKP, crv, x_short, d), NULL);

		/* An "x" that is no octet string at all still counts as one
		 * that was stated. */
		bad(jwk_raw(&OKP, crv, "\"\"", d), NULL);
		bad(jwk_raw(&OKP, crv, "\"!\"", d), NULL);
		bad(jwk_raw(&OKP, crv, "5", d), NULL);
		bad(jwk_raw(&OKP, crv, "null", d), NULL);
	}
}
END_TEST

/* A forged header key gets nowhere, on the curves that sign. */
START_TEST(test_okp_embedded_forgery)
{
	jwt_crypto_provider_t type = jwt_test_ops[_i].type;
	size_t n;

	SET_OPS();

	/* GnuTLS < 3.8.13 cannot load the attacker's key, a private key
	 * without its "x". */
	if (gnutls_okp_jwk_broken(type))
		return;

	for (n = 0; n < ARRAY_SIZE(okp); n++) {
		const char *crv = okp[n].crv;
		jwk_set_auto_t *pair = NULL;
		char_auto *x = NULL, *d = NULL;

		if (okp[n].ecdh)
			continue;

		x = member(okp[n].pub, "x");
		d = member(okp[n].priv, "d");

		/* The tokens are signed here, which takes EdDSA. */
		pair = good(jwk(&OKP, crv, x, d), 1);
		if (!signs_eddsa(jwks_item_get(pair, 0)))
			continue;

		honest(jwk(&OKP, crv, x, NULL), jwk(&OKP, crv, x, d),
		       JWT_ALG_EDDSA);
		forgery(jwk(&OKP, crv, x, NULL), jwk(&OKP, crv, NULL, x),
			jwk(&OKP, crv, x, x), JWT_ALG_EDDSA);
	}
}
END_TEST

/* Where the two members are kept apart, a mismatched pair loads, and what is
 * encrypted to it goes to the owner of the "x" it states, as everybody who
 * reads the JWK expects. No operation takes a public key from "d". */
START_TEST(test_okp_members_apart)
{
	jwt_crypto_provider_t type = jwt_test_ops[_i].type;
	size_t n;

	SET_OPS();

	if (key_from_private(type))
		return;

	for (n = 0; n < ARRAY_SIZE(okp); n++) {
		const char *crv = okp[n].crv;
		jwk_set_auto_t *pair = NULL, *mixed = NULL, *other = NULL;
		char_auto *x = NULL, *d = NULL, *token = NULL;

		x = member(okp[n].pub, "x");
		d = member(okp[n].priv, "d");

		pair = good(jwk(&OKP, crv, x, d), 1);
		mixed = good(jwk(&OKP, crv, x, x), 1);
		other = good(jwk(&OKP, crv, NULL, x), 1);

		/* The Ed curves are only stored. */
		if (!okp[n].ecdh)
			continue;

		token = encrypt_to(jwks_item_get(mixed, 0));
		ck_assert(decrypts(jwks_item_get(pair, 0), token));
		ck_assert(!decrypts(jwks_item_get(other, 0), token));
		ck_assert(!decrypts(jwks_item_get(mixed, 0), token));
	}
}
END_TEST

#ifdef LIBJWT_HAVE_ML_DSA

#define MISMATCH_AKP	"AKP private key does not match its public key"
#define INVALID_AKP	"Invalid AKP pub"

static const struct kind AKP = { "AKP", "alg", "pub", "priv" };

static const struct {
	const char *alg_str;
	jwt_alg_t alg;
	const char *file;	/* a pair: "pub" and the "priv" seed */
} akp[] = {
	{ "ML-DSA-44", JWT_ALG_ML_DSA_44, "mldsa_key_44.json" },
	{ "ML-DSA-65", JWT_ALG_ML_DSA_65, "mldsa_key_65.json" },
	{ "ML-DSA-87", JWT_ALG_ML_DSA_87, "mldsa_key_87.json" },
};

/* Whether the active backend can use ML-DSA, which only OpenSSL and a GnuTLS
 * with a PQC provider can (one without still loads a public key). Asked with
 * a seed alone, which the rule does not touch: a pair that it put in error
 * would make these tests skip themselves. */
static int mldsa_supported(void)
{
	char_auto *seed = member(akp[0].file, "priv");
	jwk_set_auto_t *set = load(jwk(&AKP, akp[0].alg_str, NULL, seed));

	return jwks_item_error(jwks_item_get(set, 0)) == 0;
}

/* As test_okp_pair and test_okp_pair_mismatch, for every ML-DSA variant. Any
 * 32 octets are the seed of a key of any variant, so the next variant's seed
 * is somebody else's key here. */
START_TEST(test_akp_pair)
{
	size_t n;

	SET_OPS();

	if (!mldsa_supported())
		return;

	for (n = 0; n < ARRAY_SIZE(akp); n++) {
		const char *alg = akp[n].alg_str;
		const char *next = akp[(n + 1) % ARRAY_SIZE(akp)].file;
		jwk_set_auto_t *pair = NULL, *pub_set = NULL, *seed_set = NULL;
		char_auto *pub = NULL, *seed = NULL, *pub2 = NULL;
		char_auto *seed2 = NULL, *pub_a = NULL, *pub_b = NULL;
		char_auto *pub_long = NULL;
		char_auto *tp = NULL, *tp_pub = NULL, *token = NULL;

		pub = member(akp[n].file, "pub");
		seed = member(akp[n].file, "priv");
		seed2 = member(next, "priv");
		pub2 = member(next, "pub");

		pair = good(jwk(&AKP, alg, pub, seed), 1);
		pub_set = good(jwk(&AKP, alg, pub, NULL), 0);
		seed_set = good(jwk(&AKP, alg, NULL, seed), 1);

		tp = jwks_item_thumbprint(jwks_item_get(pair, 0),
					  JWK_THUMBPRINT_SHA256);
		tp_pub = jwks_item_thumbprint(jwks_item_get(pub_set, 0),
					      JWK_THUMBPRINT_SHA256);
		ck_assert_ptr_nonnull(tp);
		ck_assert_ptr_nonnull(tp_pub);
		ck_assert_str_eq(tp, tp_pub);

		token = sign(jwks_item_get(seed_set, 0), akp[n].alg, NULL);
		verifies(jwks_item_get(pub_set, 0), akp[n].alg, token);
		verifies(jwks_item_get(pair, 0), akp[n].alg, token);

		/* Somebody's public key with another seed. */
		bad(jwk(&AKP, alg, pub, seed2), MISMATCH_AKP);

		/* A "pub" of another length, off by one character, or the right
		 * key with extra trailing octets (the right prefix but the wrong
		 * length, which GnuTLS tells by the length before the tail
		 * compare). All are a true mismatch, not an unusable member. */
		pub_a = tweak(pub, 0);
		pub_b = tweak(pub, 1);
		ck_assert_int_gt(asprintf(&pub_long, "%sAAAA", pub), 0);
		bad(jwk(&AKP, alg, pub2, seed), MISMATCH_AKP);
		bad(jwk(&AKP, alg, pub_a, seed), MISMATCH_AKP);
		bad(jwk(&AKP, alg, pub_b, seed), MISMATCH_AKP);
		bad(jwk(&AKP, alg, pub_long, seed), MISMATCH_AKP);

		/* A "pub" that is no usable octet string is told apart from a
		 * true mismatch: empty, not base64url, or not a string. */
		bad(jwk_raw(&AKP, alg, "\"\"", seed), INVALID_AKP);
		bad(jwk_raw(&AKP, alg, "\"!\"", seed), INVALID_AKP);
		bad(jwk_raw(&AKP, alg, "5", seed), INVALID_AKP);
		bad(jwk_raw(&AKP, alg, "null", seed), INVALID_AKP);
	}
}
END_TEST

/* A forged header key gets nowhere, for every ML-DSA variant. */
START_TEST(test_akp_embedded_forgery)
{
	size_t n;

	SET_OPS();

	if (!mldsa_supported())
		return;

	for (n = 0; n < ARRAY_SIZE(akp); n++) {
		const char *alg = akp[n].alg_str;
		const char *next = akp[(n + 1) % ARRAY_SIZE(akp)].file;
		char_auto *pub = NULL, *seed = NULL, *seed2 = NULL;

		pub = member(akp[n].file, "pub");
		seed = member(akp[n].file, "priv");
		seed2 = member(next, "priv");

		honest(jwk(&AKP, alg, pub, NULL), jwk(&AKP, alg, pub, seed),
		       akp[n].alg);
		forgery(jwk(&AKP, alg, pub, NULL), jwk(&AKP, alg, NULL, seed2),
			jwk(&AKP, alg, pub, seed2), akp[n].alg);
	}
}
END_TEST

#endif /* LIBJWT_HAVE_ML_DSA */

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);

	tc_core = tcase_create("jwt_jwks_pair");

	tcase_add_loop_test(tc_core, test_okp_pair, 0, i);
	tcase_add_loop_test(tc_core, test_okp_pair_mismatch, 0, i);
	tcase_add_loop_test(tc_core, test_okp_embedded_forgery, 0, i);
	tcase_add_loop_test(tc_core, test_okp_members_apart, 0, i);
#ifdef LIBJWT_HAVE_ML_DSA
	tcase_add_loop_test(tc_core, test_akp_pair, 0, i);
	tcase_add_loop_test(tc_core, test_akp_embedded_forgery, 0, i);
#endif

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT JWK private and public member");
}
