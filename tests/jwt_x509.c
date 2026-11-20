/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7517,4.7,4.8,4.9} X.509 JWK parameters x5c / x5t / x5t#S256 (issue #314,
 * phase 1). Runs under each crypto backend (SET_OPS) and both JSON backends. */

static jwk_set_t *load(const char *file)
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

/* A JWK with an x5c chain and a matching x5t#S256 parses cleanly and exposes
 * the DER leaf + thumbprints. */
START_TEST(test_x5c_parse)
{
	jwk_set_t *set;
	const jwk_item_t *item;
	const unsigned char *der;
	size_t der_len = 0;

	SET_OPS();
	set = load("ec_key_with_x5c.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);

	/* One cert in the chain; the leaf is real DER (SEQUENCE tag 0x30). */
	ck_assert_uint_eq(jwks_item_x5c_count(item), 1);
	der = jwks_item_x5c(item, 0, &der_len);
	ck_assert_ptr_nonnull(der);
	ck_assert_uint_gt(der_len, 0);
	ck_assert_int_eq(der[0], 0x30);

	/* Out-of-range index returns NULL. */
	ck_assert_ptr_null(jwks_item_x5c(item, 1, &der_len));

	/* x5t#S256 is present (and was validated against the leaf at parse). */
	ck_assert_ptr_nonnull(jwks_item_x5t_s256(item));
	/* This fixture has no legacy x5t. */
	ck_assert_ptr_null(jwks_item_x5t(item));

	jwks_free(set);
}
END_TEST

/* A JWK whose x5t#S256 disagrees with its x5c leaf is rejected (RFC 7517 4.9). */
START_TEST(test_x5t_mismatch)
{
	jwk_set_t *set;
	const jwk_item_t *item;

	SET_OPS();
	set = load("ec_key_x5c_bad_x5t.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 1);
	ck_assert_ptr_nonnull(strstr(jwks_item_error_msg(item), "x5t#S256"));

	jwks_free(set);
}
END_TEST

/* A JWK in error exposes no certificate chain and no certificate thumbprint,
 * whatever put it in error: a stated "x5t#S256" that is not that of its "x5c"
 * leaf, in a key file and inline. Without the chain there is nothing to check
 * the thumbprints against: the JWK is not in error, and both are returned as
 * stated. */
START_TEST(test_x5c_of_errored_key)
{
	static const char fmt[] = "{\"kty\":\"oct\",\"k\":"
		"\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\","
		"\"x5t\":\"c3RhdGVkLXNoYTE\","
		"\"x5t#S256\":\"c3RhdGVkLXNoYTI1Ng\"%s}";
	jwk_set_auto_t *ok = NULL, *bad = NULL, *file = NULL;
	char *ok_json, *bad_json;
	const jwk_item_t *item;
	size_t der_len = 99;

	SET_OPS();

	ck_assert_int_gt(asprintf(&ok_json, fmt, ""), 0);
	ck_assert_int_gt(asprintf(&bad_json, fmt, ",\"x5c\":[\"AAAA\"]"), 0);

	ok = jwks_create(ok_json);
	free(ok_json);
	ck_assert_ptr_nonnull(ok);
	item = jwks_item_get(ok, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);
	ck_assert_str_eq(jwks_item_x5t(item), "c3RhdGVkLXNoYTE");
	ck_assert_str_eq(jwks_item_x5t_s256(item), "c3RhdGVkLXNoYTI1Ng");

	bad = jwks_create(bad_json);
	free(bad_json);
	ck_assert_ptr_nonnull(bad);
	item = jwks_item_get(bad, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);
	ck_assert_uint_eq(jwks_item_x5c_count(item), 0);
	ck_assert_ptr_null(jwks_item_x5c(item, 0, &der_len));
	ck_assert_uint_eq(der_len, 99);
	ck_assert_ptr_null(jwks_item_x5t(item));
	ck_assert_ptr_null(jwks_item_x5t_s256(item));

	file = load("ec_key_x5c_bad_x5t.json");
	item = jwks_item_get(file, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_ne(jwks_item_error(item), 0);
	ck_assert_uint_eq(jwks_item_x5c_count(item), 0);
	ck_assert_ptr_null(jwks_item_x5c(item, 0, &der_len));
	ck_assert_uint_eq(der_len, 99);
	ck_assert_ptr_null(jwks_item_x5t_s256(item));
}
END_TEST

/* A JWK with no X.509 parameters exposes none. */
START_TEST(test_no_x5c)
{
	jwk_set_t *set;
	const jwk_item_t *item;
	size_t len = 99;

	SET_OPS();
	set = load("ec_key_prime256v1_pub.json");
	item = jwks_item_get(set, 0);
	ck_assert_ptr_nonnull(item);
	ck_assert_int_eq(jwks_item_error(item), 0);

	ck_assert_uint_eq(jwks_item_x5c_count(item), 0);
	ck_assert_ptr_null(jwks_item_x5c(item, 0, &len));
	ck_assert_ptr_null(jwks_item_x5t(item));
	ck_assert_ptr_null(jwks_item_x5t_s256(item));

	jwks_free(set);
}
END_TEST

/* @rfc{7517,4.7} "The key in the first certificate MUST match the public key
 * represented by other members of the JWK": the tests from here on. */

#define MSG_NO_MATCH	"\"x5c\" leaf certificate does not match the JWK's key"
#define MSG_NOT_CERT	"Invalid JWK: \"x5c\" leaf is not a valid certificate"
#define MSG_OCT		"Invalid JWK: \"x5c\" is not valid for an \"oct\" key"
#define MSG_X5T \
	"\"x5t#S256\" does not match the \"x5c\" leaf certificate"
#define NO_ERROR	""

/* The contents of the file @name in tests/keys, as a string. */
static char *slurp(const char *name)
{
	char *path, *buf;
	size_t got;
	FILE *fp;
	long len;
	int ret;

	ret = asprintf(&path, KEYDIR "/%s", name);
	ck_assert_int_gt(ret, 0);
	fp = fopen(path, "rb");
	ck_assert_msg(fp != NULL, "Cannot open %s", path);
	free(path);

	ret = fseek(fp, 0, SEEK_END);
	ck_assert_int_eq(ret, 0);
	len = ftell(fp);
	ck_assert_int_gt(len, 0);
	rewind(fp);

	buf = malloc(len + 1);
	ck_assert_ptr_nonnull(buf);
	got = fread(buf, 1, len, fp);
	ck_assert_uint_eq(got, len);
	buf[len] = '\0';
	fclose(fp);

	return buf;
}

/* Standard base64 with padding, which is what an "x5c" entry is. */
static char *b64(const unsigned char *in, size_t len)
{
	static const char abc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				  "abcdefghijklmnopqrstuvwxyz0123456789+/";
	char *out = malloc((len + 2) / 3 * 4 + 1);
	size_t i, o = 0;

	ck_assert_ptr_nonnull(out);

	for (i = 0; i < len; i += 3) {
		unsigned int v = in[i] << 16;

		if (i + 1 < len)
			v |= in[i + 1] << 8;
		if (i + 2 < len)
			v |= in[i + 2];

		out[o++] = abc[v >> 18];
		out[o++] = abc[(v >> 12) & 0x3f];
		out[o++] = i + 1 < len ? abc[(v >> 6) & 0x3f] : '=';
		out[o++] = i + 2 < len ? abc[v & 0x3f] : '=';
	}
	out[o] = '\0';

	return out;
}

/* The value of the hex digit @c, which is not a capital. */
static unsigned int hex_digit(char c)
{
	static const char digits[] = "0123456789abcdef";
	const char *at = c ? strchr(digits, c) : NULL;

	ck_assert_msg(at != NULL, "Not a hex digit: %c", c);

	return (unsigned int)(at - digits);
}

/* Room for the largest certificate that is made below. */
static unsigned char der_buf[1 << 17];

/* Write the octets that the text at *@spec stands for to @out (in der_buf),
 * up to the end of the text or to a "]", and return how many there are. The
 * text is pairs of hex digits. "[" to its "]" stands for the length octets
 * (DER) of what is between them, followed by that, and "xx*N" for N octets
 * xx. So "30[ 02[ 05 ] ]" is a SEQUENCE that holds the INTEGER 5. Where a
 * length has to be wrong, it is written out in hex. */
static size_t der(const char **spec, unsigned char *out)
{
	size_t room = der_buf + sizeof(der_buf) - out, n = 0, len;
	const char *s = *spec;

	for (; *s != '\0' && *s != ']'; s++) {
		if (*s == ' ')
			continue;

		ck_assert_uint_gt(room, n + 4);

		if (*s == '[') {
			/* The contents first, behind the most that the
			 * length octets can take. */
			unsigned char *body = out + n + 4;

			s++;
			len = der(&s, body);
			ck_assert_int_eq(*s, ']');

			if (len >= 0x10000) {
				out[n++] = 0x83;
				out[n++] = (len >> 16) & 0xff;
				out[n++] = (len >> 8) & 0xff;
			} else if (len >= 0x100) {
				out[n++] = 0x82;
				out[n++] = (len >> 8) & 0xff;
			} else if (len >= 0x80) {
				out[n++] = 0x81;
			}
			out[n++] = len & 0xff;

			memmove(out + n, body, len);
			n += len;
			continue;
		}

		out[n] = hex_digit(s[0]) << 4 | hex_digit(s[1]);
		s++;

		len = 1;
		if (s[1] == '*') {
			char *end;

			len = strtoul(s + 2, &end, 10);
			s = end - 1;
		}
		ck_assert_uint_gt(room, n + len);
		memset(out + n, out[n], len);
		n += len;
	}

	*spec = s;

	return n;
}

/* One "x5c" entry, the base64 of a DER certificate, from @leaf: the name of
 * a PEM certificate in tests/keys/x5c, or DER as der() takes it. */
static char *x5c_entry(const char *leaf)
{
	char *path, *pem, *line, *out;
	size_t len;
	int ret;

	if (strstr(leaf, ".crt") == NULL) {
		len = der(&leaf, der_buf);
		ck_assert_int_eq(*leaf, '\0');

		return b64(der_buf, len);
	}

	ret = asprintf(&path, "x5c/%s", leaf);
	ck_assert_int_gt(ret, 0);
	pem = slurp(path);
	free(path);

	/* The lines between "-----BEGIN" and "-----END" are that base64. */
	out = pem;
	for (line = strtok(pem, "\r\n"); line; line = strtok(NULL, "\r\n")) {
		if (line[0] == '-')
			continue;

		len = strlen(line);
		memmove(out, line, len);
		out += len;
	}
	*out = '\0';

	return pem;
}

/* The JSON array of the "x5c" entries @leaf and, unless it is NULL, @next. */
static char *x5c_array(const char *leaf, const char *next)
{
	char *first = x5c_entry(leaf), *second = NULL, *json;
	int ret;

	if (next != NULL) {
		second = x5c_entry(next);
		ret = asprintf(&json, "[\"%s\",\"%s\"]", first, second);
	} else {
		ret = asprintf(&json, "[\"%s\"]", first);
	}
	ck_assert_int_gt(ret, 0);

	free(first);
	free(second);

	return json;
}

/* Load one JWK. @key is the name of a file in tests/keys that holds one key,
 * or the members of a JWK. @x5c, unless it is NULL, becomes its "x5c". */
static jwk_set_t *jwk_load(const char *key, const char *x5c)
{
	char *json, *file = NULL;
	jwk_set_t *set;
	int ret;

	if (key[0] != '"') {
		const char *kty;

		/* A member can go in front of any other. */
		file = slurp(key);
		kty = strstr(file, "\"kty\"");
		ck_assert_ptr_nonnull(kty);
		if (x5c != NULL)
			ret = asprintf(&json, "%.*s\"x5c\":%s,%s",
				       (int)(kty - file), file, x5c, kty);
		else
			ret = asprintf(&json, "%s", file);
	} else if (x5c != NULL) {
		ret = asprintf(&json, "{%s,\"x5c\":%s}", key, x5c);
	} else {
		ret = asprintf(&json, "{%s}", key);
	}
	ck_assert_int_gt(ret, 0);
	free(file);

	set = jwks_create(json);
	free(json);
	ck_assert_ptr_nonnull(set);
	ck_assert_msg(!jwks_error(set), "%s: %s", key, jwks_error_msg(set));
	ck_assert_uint_eq(jwks_item_count(set), 1);

	return set;
}

/* Load @key as it is, and again with @x5c (JSON) as its "x5c". If the backend
 * can load the key at all, then with "x5c" it must end up with the error
 * @want, or with none for "". If not (not every backend has every kind of
 * key), it must keep the error that it has without "x5c", whatever comes with
 * it. Returns whether the key itself loads. */
static int x5c_check(const char *what, const char *key, const char *x5c,
		     const char *want)
{
	jwk_set_t *plain_set = jwk_load(key, NULL);
	jwk_set_t *set = jwk_load(key, x5c);
	const jwk_item_t *plain = jwks_item_get(plain_set, 0);
	const jwk_item_t *item = jwks_item_get(set, 0);
	int loads = !jwks_item_error(plain);

	if (!loads)
		want = jwks_item_error_msg(plain);

	ck_assert_msg(!strcmp(jwks_item_error_msg(item), want),
		      "%s (%s): [%s], and not [%s]", what, key,
		      jwks_item_error_msg(item), want);
	ck_assert_msg(!jwks_item_error(item) == (loads && !want[0]),
		      "%s (%s): error is %d", what, key, jwks_item_error(item));

	jwks_free(set);
	jwks_free(plain_set);

	return loads;
}

/* As x5c_check(), with the one certificate @leaf (see x5c_entry()). */
static int leaf_check(const char *what, const char *key, const char *leaf,
		      const char *want)
{
	char *x5c = x5c_array(leaf, NULL);
	int loads = x5c_check(what, key, x5c, want);

	free(x5c);

	return loads;
}

/* The P-256 test key (ec_key_prime256v1_pub.json): as a JWK, and its
 * coordinates in hex. */
#define EC_JWK_X	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\""
#define EC_JWK_Y	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\""
#define EC_JWK	"\"kty\":\"EC\",\"crv\":\"P-256\"," EC_JWK_X "," EC_JWK_Y
#define EC_JWK_D	"\"d\":\"wDvSCv8kxkqIVTYPpgEm4Efs6lKzf-95W8Qej4F1yEM\""
#define EC_X \
	"63ef83752a42679a05de3fff87e49d349230bc1e5a238017ce9444ac65235ab3"
#define EC_Y \
	"fdb493097943794fa96596ce2835152c036ca5221eb8a65f4ccf2bb57146fd15"

/* The modulus of the RSA test key (rsa_key_2048_pub.json): as "n" and in hex.
 * Its exponent is 65537: "AQAB" and 010001. */
#define RSA_JWK_N \
	"wtpMAM4l1H995oqlqdMhuqNuffp4-4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8" \
	"y9iGkWfhouZqNJbMFry-iBs-z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24M" \
	"sGNkpNt0GISaaiqv51NMZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCu" \
	"laMD-b3Mcsjlh0yvSq7g6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIky" \
	"PS_85M4Y6Ss_T-OWi1OeK49NdYBvFP-hNVEoeZzJz5K_nd6C35IX0t2bN5CVXchU" \
	"FmaUMYk2iPdhXdsC720tBw"
#define RSA_N \
	"c2da4c00ce25d47f7de68aa5a9d321baa36e7dfa78fb86940b0b8513d079b3d3" \
	"09afade0c9ff235b4a03afb31bd576fccbd8869167e1a2e66a3496cc16bcbe88" \
	"1b3ecf64ed245d3abdb1d06736a30ec76ec775d57d7bfdbfa7432089b2536e0c" \
	"b06364a4db7418849a6a2aafe7534c6505f49a23975d676442f5936455e19ac1" \
	"429892c4ebba101526abe21cdf01a0ae95a303f9bdcc72c8e5874caf4aaee0ea" \
	"cc2221ab04537a8d2ca6890191337f2c2ba1562bdc1c0cd488956d078a808932" \
	"3d2ffce4ce18e92b3f4fe3968b539e2b8f4d75806f14ffa1355128799cc9cf92" \
	"bf9dde82df9217d2dd9b3790955dc85416669431893688f7615ddb02ef6d2d07"

/* The Ed25519 test key (eddsa_key_ed25519_pub.json), in hex: its first octet
 * and the other 31. */
#define ED_X_1	"1d"
#define ED_X_31	"48fed7890de8de22e6a35591f121c0a8827feb52aef447b2d41db55f1ae503"
#define ED_X	ED_X_1 ED_X_31

/* The key of oct_key_256.json. */
#define OCT_JWK \
	"\"kty\":\"oct\",\"k\":\"0gmNspkRljssLSrldySnYUS-zhtCo5sqeqo_yl7n2XA\""

/* tests/keys/x5c has a certificate for every kind of key in tests/keys, made
 * with the OpenSSL command line. ec_key_prime256v1.crt is self-signed and its
 * key signed the others; it carries no basicConstraints, so it is not a CA a
 * path validator would accept, which does not matter here -- LibJWT reads only
 * the leaf's key, never the issuer or the rest of the chain.
 * ec_other_prime256v1.crt is for a P-256 key that is not in tests/keys: up to
 * 3.6.2 it was the "x5c" of ec_key_with_x5c.json. */
static const struct {
	const char *key;	/* see jwk_load() */
	const char *leaf;	/* a certificate in tests/keys/x5c */
	const char *want;	/* see x5c_check() */
} leaves[] = {
	/* Each kind of key with its own certificate. */
	{ "rsa_key_2048_pub.json", "rsa_key_2048.crt", NO_ERROR },
	/* The certificate has an id-RSASSA-PSS key. */
	{ "rsa_pss_key_2048_pub.json", "rsa_pss_key_2048.crt", NO_ERROR },
	{ "ec_key_prime256v1_pub.json", "ec_key_prime256v1.crt", NO_ERROR },
	{ "ec_key_secp384r1_pub.json", "ec_key_secp384r1.crt", NO_ERROR },
	/* This JWK has "x" and "y" of 65 octets, the certificate of 66. */
	{ "ec_key_secp521r1_pub.json", "ec_key_secp521r1.crt", NO_ERROR },
	{ "ec_key_secp256k1_pub.json", "ec_key_secp256k1.crt", NO_ERROR },
	{ "eddsa_key_ed25519_pub.json", "eddsa_key_ed25519.crt", NO_ERROR },
	{ "eddsa_key_ed448_pub.json", "eddsa_key_ed448.crt", NO_ERROR },
	{ "okp_x25519_enc.json", "okp_x25519.crt", NO_ERROR },
	{ "okp_x448_enc.json", "okp_x448.crt", NO_ERROR },
	{ "mldsa_key_44_pub.json", "mldsa_key_44.crt", NO_ERROR },
	{ "mldsa_key_65_pub.json", "mldsa_key_65.crt", NO_ERROR },
	{ "mldsa_key_87_pub.json", "mldsa_key_87.crt", NO_ERROR },

	/* A private key is compared by its public members ... */
	{ "rsa_key_2048.json", "rsa_key_2048.crt", NO_ERROR },
	{ "ec_key_prime256v1.json", "ec_key_prime256v1.crt", NO_ERROR },
	{ "eddsa_key_ed25519.json", "eddsa_key_ed25519.crt", NO_ERROR },
	{ "mldsa_key_44.json", "mldsa_key_44.crt", NO_ERROR },
	/* ... so it has to have them: these two are "d" and "priv" only. */
	{ "eddsa_key_ed448.json", "eddsa_key_ed448.crt", MSG_NO_MATCH },
	{ "\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\","
	  "\"priv\":\"HwKfY0o00KZ4fgL_UvuSoaXqpVlu4F-ixMj-JG53iUw\"",
	  "mldsa_key_44.crt", MSG_NO_MATCH },
	/* A public member that is not a string is as good as none, where a
	 * backend loads a private key with such an "x" at all. */
	{ "\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":5,"
	  "\"d\":\"XY5oUZqGWVZhX7J09hG-rRnAKXiw1g_aBh-Bc52KZ_Y\"",
	  "eddsa_key_ed25519.crt", MSG_NO_MATCH },

	/* The certificate of another key of the same kind. In the second of
	 * these "x5t#S256" is right for that certificate, which is what 3.6.2
	 * had as its valid fixture. In the third it is wrong as well, and
	 * that is still what is reported. */
	{ "ec_key_prime256v1_pub.json", "ec_other_prime256v1.crt",
	  MSG_NO_MATCH },
	{ EC_JWK ",\"x5t#S256\":"
	  "\"VfRPuC5FT0H8B2LTXMZQHh0g9qzP60IulYGJhZeCOJ8\"",
	  "ec_other_prime256v1.crt", MSG_NO_MATCH },
	{ EC_JWK ",\"x5t#S256\":"
	  "\"AfRPuC5FT0H8B2LTXMZQHh0g9qzP60IulYGJhZeCOJ8\"",
	  "ec_other_prime256v1.crt", MSG_X5T },
	{ "rsa_key_2048_pub.json", "rsa_pss_key_2048.crt", MSG_NO_MATCH },
	{ "rsa_pss_key_2048_pub.json", "rsa_key_2048.crt", MSG_NO_MATCH },
	{ "rsa_key_2048.json", "rsa_pss_key_2048.crt", MSG_NO_MATCH },
	{ "ec_key_prime256v1.json", "ec_other_prime256v1.crt", MSG_NO_MATCH },

	/* Another curve, parameter set or kind of key. */
	{ "ec_key_prime256v1_pub.json", "ec_key_secp256k1.crt", MSG_NO_MATCH },
	{ "ec_key_secp384r1_pub.json", "ec_key_prime256v1.crt", MSG_NO_MATCH },
	{ "ec_key_secp521r1_pub.json", "ec_key_secp384r1.crt", MSG_NO_MATCH },
	{ "ec_key_secp256k1_pub.json", "ec_key_prime256v1.crt", MSG_NO_MATCH },
	{ "eddsa_key_ed25519_pub.json", "okp_x25519.crt", MSG_NO_MATCH },
	{ "eddsa_key_ed448_pub.json", "eddsa_key_ed25519.crt", MSG_NO_MATCH },
	{ "okp_x25519_enc.json", "okp_x448.crt", MSG_NO_MATCH },
	{ "okp_x448_enc.json", "eddsa_key_ed448.crt", MSG_NO_MATCH },
	{ "mldsa_key_44_pub.json", "mldsa_key_65.crt", MSG_NO_MATCH },
	{ "mldsa_key_65_pub.json", "mldsa_key_87.crt", MSG_NO_MATCH },
	{ "mldsa_key_87_pub.json", "mldsa_key_44.crt", MSG_NO_MATCH },
	{ "rsa_key_2048_pub.json", "ec_key_prime256v1.crt", MSG_NO_MATCH },
	{ "ec_key_prime256v1_pub.json", "rsa_key_2048.crt", MSG_NO_MATCH },
	{ "eddsa_key_ed25519_pub.json", "ec_key_prime256v1.crt", MSG_NO_MATCH },
	{ "mldsa_key_44_pub.json", "eddsa_key_ed25519.crt", MSG_NO_MATCH },

	/* A certificate is for a public key. */
	{ "oct_key_256.json", "ec_key_prime256v1.crt", MSG_OCT },

	/* What the members say, and not how: the last character of this "x"
	 * has bits set that are not part of the key. RSA and EC values are
	 * numbers, here with three more zero octets in front. */
	{ "\"kty\":\"OKP\",\"crv\":\"Ed25519\","
	  "\"x\":\"HUj-14kN6N4i5qNVkfEhwKiCf-tSrvRHstQdtV8a5QP\"",
	  "eddsa_key_ed25519.crt", NO_ERROR },
	{ "\"kty\":\"RSA\",\"n\":\"AAAA" RSA_JWK_N "\",\"e\":\"AAAAAQAB\"",
	  "rsa_key_2048.crt", NO_ERROR },
	{ "\"kty\":\"EC\",\"crv\":\"P-256\","
	  "\"x\":\"AAAAY--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
	  "\"y\":\"AAAA_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"",
	  "ec_key_prime256v1.crt", NO_ERROR },
	/* The same RSA modulus with another exponent is another key: 1, and
	 * 65537 with a zero octet behind it. */
	{ "\"kty\":\"RSA\",\"n\":\"" RSA_JWK_N "\",\"e\":\"AQ\"",
	  "rsa_key_2048.crt", MSG_NO_MATCH },
	{ "\"kty\":\"RSA\",\"n\":\"" RSA_JWK_N "\",\"e\":\"AQABAA\"",
	  "rsa_key_2048.crt", MSG_NO_MATCH },
	/* Where a backend takes more than the registered ones: a name of its
	 * own for the curve, and "x" plus the prime of the field. */
	{ "\"kty\":\"EC\",\"crv\":\"prime256v1\"," EC_JWK_X "," EC_JWK_Y,
	  "ec_key_prime256v1.crt", MSG_NO_MATCH },
	{ "\"kty\":\"EC\",\"crv\":\"P-256\","
	  "\"x\":\"AWPvg3QqQmebBd4__4fknTSSMLwfWiOAF86URKxlI1qy\"," EC_JWK_Y,
	  "ec_key_prime256v1.crt", MSG_NO_MATCH },
	/* A key that does not load keeps its own error: "y" is "x" here,
	 * which is not a point on the curve. */
	{ "\"kty\":\"EC\",\"crv\":\"P-256\"," EC_JWK_X ","
	  "\"y\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\"",
	  "ec_key_prime256v1.crt", MSG_NO_MATCH },
};

START_TEST(test_x5c_leaf_key)
{
	int loads = 0;
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(leaves); i++)
		loads += leaf_check(leaves[i].leaf, leaves[i].key,
				    leaves[i].leaf, leaves[i].want);

	/* Every backend has RSA, the three NIST curves and "oct". */
	ck_assert_int_ge(loads, 20);
}
END_TEST

/* A certificate as der() takes it, with stubs for all that is not looked at:
 * the tbsCertificate is version 3, serialNumber 1, then signature, issuer,
 * validity and subject, and then the SubjectPublicKeyInfo @spki. After it come
 * signatureAlgorithm and signatureValue. */
#define TBS_HEAD	"a0[ 02 01 02 ] 02 01 01"
#define TBS_NAMES	"30[] 30[] 30[] 30[]"
#define TBS(spki)	"30[" TBS_HEAD TBS_NAMES spki "]"
#define CERT_SIG	"30[] 03[ 00 ]"
#define CERT(spki)	"30[" TBS(spki) CERT_SIG "]"

/* For the P-256 test key: id-ecPublicKey with secp256r1, and the point. */
#define OID_EC		"06 07 2a8648ce3d0201"
#define EC_ALG		"30[" OID_EC "06 08 2a8648ce3d030107 ]"
#define EC_POINT	"04" EC_X EC_Y
#define EC_SPKI_OF(alg, key)	"30[" alg "03[ 00" key "] ]"
#define EC_SPKI		EC_SPKI_OF(EC_ALG, EC_POINT)
/* The contents of that certificate, which are 0x72 octets, and of one with a
 * serialNumber of 20 octets, which are 0x85: enough for the long form. */
#define EC_CERT_BODY	TBS(EC_SPKI) CERT_SIG
#define EC_CERT_BODY_L	"30[ a0[ 02 01 02 ] 02[ 01*20 ]" TBS_NAMES EC_SPKI "]" \
			CERT_SIG

/* For the RSA test key: rsaEncryption with NULL parameters, and RSAPublicKey
 * with the INTEGERs @ints (the modulus needs a sign octet). */
#define OID_RSA		"06 09 2a864886f70d010101"
#define RSA_ALG		"30[" OID_RSA "05 00 ]"
#define RSA_N_INT	"02[ 00" RSA_N "]"
#define RSA_INTS	RSA_N_INT "02[ 010001 ]"
#define RSA_SPKI_OF(alg, ints)	"30[" alg "03[ 00 30[" ints "] ] ]"

/* For the Ed25519 test key: id-Ed25519, and the key. */
#define ED_SPKI_OF(alg, key)	"30[ 30[" alg "] 03[ 00" key "] ]"
#define OID_ED25519	"06 03 2b6570"

#define RSA_KEY		"rsa_key_2048_pub.json"
#define ED_KEY		"eddsa_key_ed25519_pub.json"

/* Leaves that are built here. Each differs from one that is accepted, the
 * first of its group, in the one thing that @what names. */
static const struct {
	const char *what;
	const char *key;	/* see jwk_load() */
	const char *leaf;	/* see der() */
	const char *want;	/* see x5c_check() */
} stubs[] = {
	{ "EC: all that is needed", EC_JWK, CERT(EC_SPKI), NO_ERROR },
	{ "EC: the same with its length written out", EC_JWK,
	  "30 72" EC_CERT_BODY, NO_ERROR },
	{ "EC: version 1, which has no version", EC_JWK,
	  "30[ 30[ 02 01 01" TBS_NAMES EC_SPKI "]" CERT_SIG "]", NO_ERROR },
	{ "EC: unique IDs and extensions after the key", EC_JWK,
	  "30[ 30[" TBS_HEAD TBS_NAMES EC_SPKI
	  "81[ 00 ] 82[ 00 ] a3[ 30[] ] ]" CERT_SIG "]", NO_ERROR },
	{ "EC: the long form of a length, written out", EC_JWK,
	  "30 81 85" EC_CERT_BODY_L, NO_ERROR },
	{ "EC: a length that takes three octets", EC_JWK,
	  "30[" TBS(EC_SPKI) "30[] 03[ 00*70000 ] ]", NO_ERROR },

	/* Tag and length octets. */
	{ "one octet", EC_JWK, "30", MSG_NOT_CERT },
	{ "length octets that are not there", EC_JWK, "30 82 01",
	  MSG_NOT_CERT },
	{ "Certificate is a SET", EC_JWK, "31 72" EC_CERT_BODY, MSG_NOT_CERT },
	{ "indefinite length", EC_JWK, "30 80" EC_CERT_BODY "00 00",
	  MSG_NOT_CERT },
	{ "length that takes four octets", EC_JWK,
	  "30 84 01000072" EC_CERT_BODY, MSG_NOT_CERT },
	{ "length with a zero octet in front", EC_JWK,
	  "30 82 0085" EC_CERT_BODY_L, MSG_NOT_CERT },
	{ "long form for a length below 128", EC_JWK, "30 81 72" EC_CERT_BODY,
	  MSG_NOT_CERT },
	{ "length of one more than there is", EC_JWK, "30 73" EC_CERT_BODY,
	  MSG_NOT_CERT },

	/* Certificate and tbsCertificate. */
	{ "an octet after the certificate", EC_JWK, CERT(EC_SPKI) "00",
	  MSG_NOT_CERT },
	{ "two certificates", EC_JWK, CERT(EC_SPKI) CERT(EC_SPKI),
	  MSG_NOT_CERT },
	{ "tbsCertificate is a SET", EC_JWK,
	  "30[ 31[" TBS_HEAD TBS_NAMES EC_SPKI "]" CERT_SIG "]",
	  MSG_NOT_CERT },
	{ "no signatureAlgorithm", EC_JWK, "30[" TBS(EC_SPKI) "03[ 00 ] ]",
	  MSG_NOT_CERT },
	{ "no signatureValue", EC_JWK, "30[" TBS(EC_SPKI) "30[] ]",
	  MSG_NOT_CERT },
	{ "something after signatureValue", EC_JWK,
	  "30[" TBS(EC_SPKI) CERT_SIG "05 00 ]", MSG_NOT_CERT },
	{ "version longer than the tbsCertificate", EC_JWK,
	  "30[ 30[ a0 7f 02 01 02 02 01 01" TBS_NAMES EC_SPKI "]" CERT_SIG "]",
	  MSG_NOT_CERT },
	{ "no serialNumber", EC_JWK,
	  "30[ 30[ a0[ 02 01 02 ]" TBS_NAMES EC_SPKI "]" CERT_SIG "]",
	  MSG_NOT_CERT },
	{ "one field too few before the key", EC_JWK,
	  "30[ 30[" TBS_HEAD "30[] 30[] 30[]" EC_SPKI "]" CERT_SIG "]",
	  MSG_NOT_CERT },
	{ "one field too many before the key", EC_JWK,
	  "30[ 30[" TBS_HEAD TBS_NAMES "30[]" EC_SPKI "]" CERT_SIG "]",
	  MSG_NOT_CERT },

	/* The SubjectPublicKeyInfo length (0x59) runs past the end of the
	 * tbsCertificate, with no element after it to catch the overflow: only
	 * der_get()'s own "length fits what is left" check rejects it. The
	 * octets it would overrun into are a valid AlgorithmIdentifier and key
	 * (they also serve as the signatureAlgorithm and signatureValue), so
	 * dropping that check would read them and accept this as the JWK's key. */
	{ "SubjectPublicKeyInfo length overruns the tbsCertificate", EC_JWK,
	  "30[ 30[" TBS_HEAD TBS_NAMES "30 59 ] 30[" OID_EC
	  "06 08 2a8648ce3d030107 ] 03[ 00" EC_POINT "] ]", MSG_NOT_CERT },

	/* SubjectPublicKeyInfo. */
	{ "SubjectPublicKeyInfo is a SET", EC_JWK,
	  CERT("31[" EC_ALG "03[ 00" EC_POINT "] ]"), MSG_NOT_CERT },
	{ "algorithm is not a SEQUENCE", EC_JWK,
	  CERT("30[" OID_EC "03[ 00" EC_POINT "] ]"), MSG_NOT_CERT },
	{ "no subjectPublicKey", EC_JWK, CERT("30[" EC_ALG "]"),
	  MSG_NOT_CERT },
	{ "subjectPublicKey is an OCTET STRING", EC_JWK,
	  CERT("30[" EC_ALG "04[ 00" EC_POINT "] ]"), MSG_NOT_CERT },
	{ "something after subjectPublicKey", EC_JWK,
	  CERT("30[" EC_ALG "03[ 00" EC_POINT "] 05 00 ]"), MSG_NOT_CERT },
	{ "BIT STRING with unused bits", EC_JWK,
	  CERT("30[" EC_ALG "03[ 01" EC_POINT "] ]"), MSG_NOT_CERT },
	{ "BIT STRING of no octets", EC_JWK, CERT("30[" EC_ALG "03[] ]"),
	  MSG_NOT_CERT },
	{ "BIT STRING of no octets, and a zero octet after the key", EC_JWK,
	  "30[ 30[" TBS_HEAD TBS_NAMES "30[" EC_ALG "03[] ] 00 ]" CERT_SIG "]",
	  MSG_NOT_CERT },

	/* EC: the curve by name, and the point as it is. */
	{ "EC: X and Y the other way round", EC_JWK,
	  CERT(EC_SPKI_OF(EC_ALG, "04" EC_Y EC_X)), MSG_NO_MATCH },
	{ "EC: another X", EC_JWK,
	  CERT(EC_SPKI_OF(EC_ALG, "04" EC_Y EC_Y)), MSG_NO_MATCH },
	{ "EC: another Y", EC_JWK,
	  CERT(EC_SPKI_OF(EC_ALG, "04" EC_X EC_X)), MSG_NO_MATCH },
	{ "EC: X and Y with a zero octet in front of each", EC_JWK,
	  CERT(EC_SPKI_OF(EC_ALG, "04 00" EC_X "00" EC_Y)), MSG_NO_MATCH },
	{ "EC: compressed point", EC_JWK,
	  CERT(EC_SPKI_OF(EC_ALG, "03" EC_X)), MSG_NO_MATCH },
	{ "EC: hybrid point", EC_JWK,
	  CERT(EC_SPKI_OF(EC_ALG, "07" EC_X EC_Y)), MSG_NO_MATCH },
	{ "EC: the point on secp256k1", EC_JWK,
	  CERT(EC_SPKI_OF("30[" OID_EC "06 05 2b8104000a ]", EC_POINT)),
	  MSG_NO_MATCH },
	{ "EC: the point on prime192v1, an OID of the same length", EC_JWK,
	  CERT(EC_SPKI_OF("30[" OID_EC "06 08 2a8648ce3d030101 ]", EC_POINT)),
	  MSG_NO_MATCH },
	{ "EC: curve given by its parameters", EC_JWK,
	  CERT(EC_SPKI_OF("30[" OID_EC "30[ 02 01 01 ] ]", EC_POINT)),
	  MSG_NO_MATCH },
	{ "EC: no curve", EC_JWK,
	  CERT(EC_SPKI_OF("30[" OID_EC "]", EC_POINT)), MSG_NO_MATCH },

	/* RSA: either key OID, any parameters, and two INTEGERs. */
	{ "RSA: all that is needed", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, RSA_INTS)), NO_ERROR },
	{ "RSA: no parameters", RSA_KEY,
	  CERT(RSA_SPKI_OF("30[" OID_RSA "]", RSA_INTS)), NO_ERROR },
	{ "RSA: id-RSASSA-PSS with parameters", RSA_KEY,
	  CERT(RSA_SPKI_OF("30[ 06 09 2a864886f70d01010a"
			   "30[ a2[ 02 01 20 ] ] ]", RSA_INTS)), NO_ERROR },
	{ "RSA: id-RSAES-OAEP", RSA_KEY,
	  CERT(RSA_SPKI_OF("30[ 06 09 2a864886f70d010107 30[] ]", RSA_INTS)),
	  MSG_NO_MATCH },
	{ "RSA: an OID that differs before its last octet", RSA_KEY,
	  CERT(RSA_SPKI_OF("30[ 06 09 2a864886f70d010901 05 00 ]", RSA_INTS)),
	  MSG_NO_MATCH },
	{ "RSA: OID that is one octet short", RSA_KEY,
	  CERT(RSA_SPKI_OF("30[ 06 08 2a864886f70d0101 ]", RSA_INTS)),
	  MSG_NO_MATCH },
	{ "RSA: a certificate with an EC key", RSA_KEY, CERT(EC_SPKI),
	  MSG_NO_MATCH },
	{ "RSA: exponent 3", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, RSA_N_INT "02[ 03 ]")), MSG_NO_MATCH },
	{ "RSA: modulus and exponent the other way round", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, "02[ 010001 ]" RSA_N_INT)), MSG_NO_MATCH },
	{ "RSA: RSAPublicKey is a SET", RSA_KEY,
	  CERT("30[" RSA_ALG "03[ 00 31[" RSA_INTS "] ] ]"), MSG_NO_MATCH },
	{ "RSA: an octet after RSAPublicKey", RSA_KEY,
	  CERT("30[" RSA_ALG "03[ 00 30[" RSA_INTS "] 00 ] ]"), MSG_NO_MATCH },
	{ "RSA: modulus without its sign octet", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, "02[" RSA_N "] 02[ 010001 ]")),
	  MSG_NO_MATCH },
	{ "RSA: modulus with two zero octets in front", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, "02[ 0000" RSA_N "] 02[ 010001 ]")),
	  MSG_NO_MATCH },
	{ "RSA: exponent of no octets, for an \"e\" of zero",
	  "\"kty\":\"RSA\",\"n\":\"" RSA_JWK_N "\",\"e\":\"AA\"",
	  CERT(RSA_SPKI_OF(RSA_ALG, RSA_N_INT "02[]")), MSG_NO_MATCH },
	{ "RSA: modulus is an OCTET STRING", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, "04[ 00" RSA_N "] 02[ 010001 ]")),
	  MSG_NO_MATCH },
	{ "RSA: exponent with a zero octet in front", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, RSA_N_INT "02[ 00010001 ]")),
	  MSG_NO_MATCH },
	{ "RSA: no exponent", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, RSA_N_INT)), MSG_NO_MATCH },
	{ "RSA: a third INTEGER", RSA_KEY,
	  CERT(RSA_SPKI_OF(RSA_ALG, RSA_INTS "02 01 01")), MSG_NO_MATCH },

	/* OKP: the OID of the curve alone, and the key octet for octet. */
	{ "OKP: all that is needed", ED_KEY,
	  CERT(ED_SPKI_OF(OID_ED25519, ED_X)), NO_ERROR },
	{ "OKP: NULL parameters", ED_KEY,
	  CERT(ED_SPKI_OF(OID_ED25519 "05 00", ED_X)), MSG_NO_MATCH },
	{ "OKP: the same octets as an X25519 key", ED_KEY,
	  CERT(ED_SPKI_OF("06 03 2b656e", ED_X)), MSG_NO_MATCH },
	{ "OKP: another key", ED_KEY,
	  CERT(ED_SPKI_OF(OID_ED25519, EC_X)), MSG_NO_MATCH },
	{ "OKP: a key of 31 octets", ED_KEY,
	  CERT(ED_SPKI_OF(OID_ED25519, ED_X_31)), MSG_NO_MATCH },
	/* Not a number: where a backend takes an "x" of 31 octets (these are
	 * the last 31 of the test key), the key that has a zero octet in
	 * front of them is another one. */
	{ "OKP: \"x\" is the key without its first octet, which is zero",
	  "\"kty\":\"OKP\",\"crv\":\"Ed25519\","
	  "\"x\":\"SP7XiQ3o3iLmo1WR8SHAqIJ_61Ku9Eey1B21XxrlAw\"",
	  CERT(ED_SPKI_OF(OID_ED25519, "00" ED_X_31)), MSG_NO_MATCH },

	/* "oct": whatever the leaf is. */
	{ "oct: with a certificate", OCT_JWK, CERT(EC_SPKI), MSG_OCT },
	{ "oct: with something else", OCT_JWK, "30 00", MSG_OCT },
};

START_TEST(test_x5c_leaf_der)
{
	int loads = 0;
	size_t i;

	SET_OPS();

	for (i = 0; i < ARRAY_SIZE(stubs); i++)
		loads += leaf_check(stubs[i].what, stubs[i].key, stubs[i].leaf,
				    stubs[i].want);

	/* Every backend loads these keys, but for the "e" of zero and the
	 * "x" of 31 octets. */
	ck_assert_int_ge(loads, (int)ARRAY_SIZE(stubs) - 2);
}
END_TEST

/* Only the first certificate is compared with the key. The others are for the
 * application, which is the one to validate the chain. */
START_TEST(test_x5c_chain)
{
	const char *key = "ec_key_secp384r1_pub.json";
	const char *leaf = "ec_key_secp384r1.crt";
	const char *issuer = "ec_key_prime256v1.crt";
	const jwk_item_t *item;
	jwk_set_t *set;
	int loads;
	char *x5c;

	SET_OPS();

	x5c = x5c_array(leaf, issuer);
	loads = x5c_check("leaf, issuer", key, x5c, NO_ERROR);
	ck_assert_int_ne(loads, 0);

	set = jwk_load(key, x5c);
	item = jwks_item_get(set, 0);
	ck_assert_int_eq(jwks_item_error(item), 0);
	ck_assert_uint_eq(jwks_item_x5c_count(item), 2);
	jwks_free(set);
	free(x5c);

	x5c = x5c_array(issuer, leaf);
	x5c_check("issuer, leaf", key, x5c, MSG_NO_MATCH);
	free(x5c);

	/* What follows the leaf does not have to be a certificate. */
	x5c = x5c_array(leaf, "00");
	x5c_check("leaf, an octet", key, x5c, NO_ERROR);
	free(x5c);
}
END_TEST

/* An "x5c" without certificates is as it was: there is nothing to compare
 * and nothing for an application to trust. */
START_TEST(test_x5c_no_certs)
{
	const jwk_item_t *item;
	jwk_set_t *set;
	int loads;

	SET_OPS();

	loads = x5c_check("no certificates", EC_JWK, "[]", NO_ERROR);
	ck_assert_int_ne(loads, 0);
	loads = x5c_check("oct: no certificates", OCT_JWK, "[]", NO_ERROR);
	ck_assert_int_ne(loads, 0);

	set = jwk_load(EC_JWK, "[]");
	item = jwks_item_get(set, 0);
	ck_assert_int_eq(jwks_item_error(item), 0);
	ck_assert_uint_eq(jwks_item_x5c_count(item), 0);
	jwks_free(set);

	/* The leaf is looked at only where the chain could be decoded. */
	x5c_check("a string", EC_JWK, "\"MIIB\"",
		  "Invalid JWK: \"x5c\" is not an array");
	x5c_check("an entry that is not base64", EC_JWK, "[\"MIIB*\"]",
		  "Invalid JWK: \"x5c\" entry is not valid base64");
	x5c_check("oct: an entry that is not a string", OCT_JWK, "[5]",
		  "Invalid JWK: \"x5c\" entry is not a string");
}
END_TEST

/* What the rule is for. The tests from here on take the P-256 test key with
 * the certificate of another P-256 key (ec_other_prime256v1.crt, which is
 * what 3.6.2 had on this key as its valid fixture) and with its own. */
#define ERR_KEY		"Key is in error and cannot be used"
#define ERR_EMBEDDED	"Embedded JWK is missing or not confirmed"

/* An "x5t" as a JWK states it, and the "x5t#S256" of the two certificates. */
#define X5T		"\"x5t\":\"c3RhdGVkLXNoYTE\""
#define X5T_S256_OWN	"S23-TzVna_TRiaAXaiwjsDWj-AoDQU5q86As8iomcys"
#define X5T_S256_OTHER	"VfRPuC5FT0H8B2LTXMZQHh0g9qzP60IulYGJhZeCOJ8"

/* A Compact ES256 token signed with @key. @jwk (JSON), unless it is NULL, is
 * its "jwk" header. The caller frees it. */
static char *es256_token(const jwk_item_t *key, char *jwk)
{
	jwt_builder_auto_t *builder = jwt_builder_new();
	jwt_value_t val;
	char *token;

	ck_assert_ptr_nonnull(builder);
	ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_ES256, key), 0);
	if (jwk != NULL) {
		jwt_set_SET_JSON(&val, "jwk", jwk);
		ck_assert_int_eq(jwt_builder_header_set(builder, &val),
				 JWT_VALUE_ERR_NONE);
	}

	token = jwt_builder_generate(builder);
	ck_assert_msg(token != NULL, "%s", jwt_builder_error_msg(builder));

	return token;
}

/* A JWK whose leaf holds another key is in error like any other: nothing is
 * read from it and nothing uses it, although its key is the one that signed.
 * With its own certificate the same key does everything. */
START_TEST(test_x5c_other_key_unusable)
{
	static const unsigned char pt[] = "chain";
	jwk_set_auto_t *signer_set = NULL, *ok_set = NULL, *bad_set = NULL;
	jwk_set_auto_t *ring = NULL;
	char_auto *own = NULL, *other = NULL, *json = NULL, *token = NULL;
	char_auto *tp = NULL, *tp_ok = NULL, *jwe = NULL;
	const jwk_item_t *signer, *ok, *bad;
	size_t len = 99;

	SET_OPS();

	own = x5c_array("ec_key_prime256v1.crt", NULL);
	other = x5c_array("ec_other_prime256v1.crt", NULL);

	signer_set = jwk_load(EC_JWK "," EC_JWK_D, NULL);
	signer = jwks_item_get(signer_set, 0);
	ck_assert_int_eq(jwks_item_error(signer), 0);
	tp = jwks_item_thumbprint(signer, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(tp);
	token = es256_token(signer, NULL);

	/* Each states the "x5t#S256" of the certificate it carries, so the
	 * key in the leaf is all that tells them apart. */
	ok_set = jwk_load(EC_JWK "," EC_JWK_D "," X5T ",\"x5t#S256\":\""
			  X5T_S256_OWN "\"", own);
	ok = jwks_item_get(ok_set, 0);
	ck_assert_msg(!jwks_item_error(ok), "%s", jwks_item_error_msg(ok));
	bad_set = jwk_load(EC_JWK "," EC_JWK_D "," X5T ",\"x5t#S256\":\""
			   X5T_S256_OTHER "\"", other);
	bad = jwks_item_get(bad_set, 0);
	ck_assert_int_ne(jwks_item_error(bad), 0);
	ck_assert_str_eq(jwks_item_error_msg(bad), MSG_NO_MATCH);

	/* No chain, no certificate thumbprint and no key thumbprint. */
	ck_assert_uint_eq(jwks_item_x5c_count(ok), 1);
	ck_assert_ptr_nonnull(jwks_item_x5c(ok, 0, &len));
	ck_assert_uint_gt(len, 99);
	ck_assert_str_eq(jwks_item_x5t(ok), "c3RhdGVkLXNoYTE");
	ck_assert_str_eq(jwks_item_x5t_s256(ok), X5T_S256_OWN);
	tp_ok = jwks_item_thumbprint(ok, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(tp_ok);
	ck_assert_str_eq(tp_ok, tp);
	ck_assert_ptr_eq(jwks_find_bythumbprint(ok_set, JWK_THUMBPRINT_SHA256,
						tp), ok);

	len = 99;
	ck_assert_uint_eq(jwks_item_x5c_count(bad), 0);
	ck_assert_ptr_null(jwks_item_x5c(bad, 0, &len));
	ck_assert_uint_eq(len, 99);
	ck_assert_ptr_null(jwks_item_x5t(bad));
	ck_assert_ptr_null(jwks_item_x5t_s256(bad));
	ck_assert_ptr_null(jwks_item_thumbprint(bad, JWK_THUMBPRINT_SHA256));
	ck_assert_ptr_null(jwks_item_thumbprint_uri(bad,
						    JWK_THUMBPRINT_SHA256));
	ck_assert_ptr_null(jwks_find_bythumbprint(bad_set,
						  JWK_THUMBPRINT_SHA256, tp));

	/* A checker and a builder refuse it. */
	{
		jwt_checker_auto_t *checker = jwt_checker_new();
		jwt_builder_auto_t *builder = jwt_builder_new();

		ck_assert_ptr_nonnull(checker);
		ck_assert_ptr_nonnull(builder);

		ck_assert_int_ne(jwt_checker_setkey(checker, JWT_ALG_ES256,
						    bad), 0);
		ck_assert_str_eq(jwt_checker_error_msg(checker), ERR_KEY);
		ck_assert_int_ne(jwt_builder_setkey(builder, JWT_ALG_ES256,
						    bad), 0);
		ck_assert_str_eq(jwt_builder_error_msg(builder), ERR_KEY);

		jwt_checker_error_clear(checker);
		jwt_builder_error_clear(builder);
		ck_assert_int_eq(jwt_checker_setkey(checker, JWT_ALG_ES256,
						    ok), 0);
		ck_assert_int_eq(jwt_checker_verify(checker, token), 0);
		ck_assert_int_eq(jwt_builder_setkey(builder, JWT_ALG_ES256,
						    ok), 0);
	}

	/* A keyring skips it, and goes on to the next key. */
	{
		jwt_checker_auto_t *checker = jwt_checker_new();

		ck_assert_ptr_nonnull(checker);
		ck_assert_int_eq(jwt_checker_setkeyring(checker, bad_set,
					JWT_VERIFY_POLICY_ANY), 0);
		ck_assert_int_ne(jwt_checker_verify(checker, token), 0);
		/* #354: the errored key is skipped, leaving no compatible key;
		 * the reason names the algorithm rather than only the count. */
		ck_assert_str_eq(jwt_checker_error_msg(checker),
				 "No keyring key can verify \"ES256\"");

		ck_assert_int_gt(asprintf(&json, "{\"keys\":[{" EC_JWK
				 ",\"x5c\":%s},{" EC_JWK ",\"x5c\":%s}]}",
				 other, own), 0);
		ring = jwks_create(json);
		ck_assert_ptr_nonnull(ring);
		ck_assert_int_eq(jwks_error_any(ring), 1);
		ck_assert_int_ne(jwks_item_error(jwks_item_get(ring, 0)), 0);

		ck_assert_int_eq(jwt_checker_setkeyring(checker, ring,
					JWT_VERIFY_POLICY_ANY), 0);
		ck_assert_int_eq(jwt_checker_verify(checker, token), 0);
		ck_assert_ptr_eq(jwt_checker_sig_key(checker, 0),
				 jwks_item_get(ring, 1));
	}

	/* JWE refuses it, to encrypt to and to decrypt with. */
	{
		jwe_builder_auto_t *builder = jwe_builder_new();
		jwe_checker_auto_t *checker = jwe_checker_new();
		unsigned char *out;

		ck_assert_ptr_nonnull(builder);
		ck_assert_ptr_nonnull(checker);

		ck_assert_int_ne(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					JWE_ENC_A256GCM, bad), 0);
		ck_assert_str_eq(jwe_builder_error_msg(builder),
				 ERR_KEY " for JWE");
		jwe_builder_error_clear(builder);
		ck_assert_ptr_null(jwe_builder_add_recipient(builder,
					JWE_ALG_ECDH_ES_A256KW, bad));
		ck_assert_str_eq(jwe_builder_error_msg(builder),
				 ERR_KEY " for JWE");
		ck_assert_int_ne(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					JWE_ENC_A256GCM, bad), 0);
		ck_assert_str_eq(jwe_checker_error_msg(checker),
				 ERR_KEY " for JWE");

		jwe_builder_error_clear(builder);
		jwe_checker_error_clear(checker);
		ck_assert_int_eq(jwe_builder_setkey(builder, JWE_ALG_ECDH_ES,
					JWE_ENC_A256GCM, ok), 0);
		jwe = jwe_builder_generate(builder, pt, sizeof(pt));
		ck_assert_msg(jwe != NULL, "%s",
			      jwe_builder_error_msg(builder));
		ck_assert_int_eq(jwe_checker_setkey(checker, JWE_ALG_ECDH_ES,
					JWE_ENC_A256GCM, ok), 0);
		out = jwe_checker_decrypt(checker, jwe, &len);
		ck_assert_msg(out != NULL, "%s",
			      jwe_checker_error_msg(checker));
		ck_assert_uint_eq(len, sizeof(pt));
		ck_assert_mem_eq(out, pt, len);
		free(out);
	}
}
END_TEST

/* Embedded-JWK verification takes its key from the token and hands it to the
 * application (jwt_checker_sig_key()). A header key with the chain of another
 * key is in error, so the token is rejected, by pin and by allow-list, although
 * the key itself is the trusted one and did sign: its chain would be somebody
 * else's. With its own certificate the token passes and the chain is there. */
START_TEST(test_x5c_embedded_jwk)
{
	jwk_set_auto_t *signer_set = NULL;
	char_auto *own = NULL, *other = NULL, *jkt = NULL;
	char_auto *hdr_ok = NULL, *hdr_bad = NULL;
	char_auto *token_ok = NULL, *token_bad = NULL;
	const jwk_item_t *signer, *key;
	int by_list;

	SET_OPS();

	own = x5c_array("ec_key_prime256v1.crt", NULL);
	other = x5c_array("ec_other_prime256v1.crt", NULL);

	signer_set = jwk_load(EC_JWK "," EC_JWK_D, NULL);
	signer = jwks_item_get(signer_set, 0);
	ck_assert_int_eq(jwks_item_error(signer), 0);
	jkt = jwks_item_thumbprint(signer, JWK_THUMBPRINT_SHA256);
	ck_assert_ptr_nonnull(jkt);

	ck_assert_int_gt(asprintf(&hdr_ok, "{" EC_JWK ",\"x5c\":%s}", own), 0);
	ck_assert_int_gt(asprintf(&hdr_bad, "{" EC_JWK ",\"x5c\":%s}", other),
			 0);
	token_ok = es256_token(signer, hdr_ok);
	token_bad = es256_token(signer, hdr_bad);

	for (by_list = 0; by_list < 2; by_list++) {
		jwt_checker_auto_t *checker = jwt_checker_new();
		int ret;

		ck_assert_ptr_nonnull(checker);
		if (by_list)
			ret = jwt_checker_enable_embedded_jwk_keyring(checker,
					JWK_THUMBPRINT_SHA256, signer_set);
		else
			ret = jwt_checker_enable_embedded_jwk(checker,
					JWK_THUMBPRINT_SHA256, jkt);
		ck_assert_int_eq(ret, 0);

		ck_assert_int_ne(jwt_checker_verify(checker, token_bad), 0);
		ck_assert_str_eq(jwt_checker_error_msg(checker), ERR_EMBEDDED);
		ck_assert_uint_eq(jwt_checker_sig_count(checker), 0);
		ck_assert_ptr_null(jwt_checker_sig_key(checker, 0));

		ret = jwt_checker_verify(checker, token_ok);
		ck_assert_msg(ret == 0, "%s", jwt_checker_error_msg(checker));
		key = jwt_checker_sig_key(checker, 0);
		ck_assert_ptr_nonnull(key);
		ck_assert_int_eq(jwks_item_error(key), 0);
		ck_assert_uint_eq(jwks_item_x5c_count(key), 1);
		ck_assert_ptr_nonnull(jwks_item_x5c(key, 0, NULL));
	}
}
END_TEST

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;
	int i = ARRAY_SIZE(jwt_test_ops);

	s = suite_create(title);
	tc_core = tcase_create("jwt_x509");

	tcase_add_loop_test(tc_core, test_x5c_parse, 0, i);
	tcase_add_loop_test(tc_core, test_x5t_mismatch, 0, i);
	tcase_add_loop_test(tc_core, test_x5c_of_errored_key, 0, i);
	tcase_add_loop_test(tc_core, test_no_x5c, 0, i);
	tcase_add_loop_test(tc_core, test_x5c_leaf_key, 0, i);
	tcase_add_loop_test(tc_core, test_x5c_leaf_der, 0, i);
	tcase_add_loop_test(tc_core, test_x5c_chain, 0, i);
	tcase_add_loop_test(tc_core, test_x5c_no_certs, 0, i);
	tcase_add_loop_test(tc_core, test_x5c_other_key_unusable, 0, i);
	tcase_add_loop_test(tc_core, test_x5c_embedded_jwk, 0, i);

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	JWT_TEST_MAIN("LibJWT X.509 JWK params x5c/x5t/x5t#S256 (#314)");
}
