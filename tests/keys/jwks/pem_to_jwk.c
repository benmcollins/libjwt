/* Copyright (C) 2024 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* XXX BIG FAT WARNING: There's not much error checking here. */

/* XXX: Also, requires OpenSSL v3. I wont accept patches for lower versions. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <jansson.h>

#include <jwt.h>
#include "jwt-private.h"

static int ec_count, rsa_count, eddsa_count, rsa_pss_count;

static void print_openssl_errors_and_exit()
{
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

static const char *uuidv4(void)
{
	uint8_t uuid_bytes[16];
	static char uuid[37];

	// Generate 16 random bytes
	if (RAND_bytes(uuid_bytes, sizeof(uuid_bytes)) != 1) {
		fprintf(stderr, "Error: Failed to generate random bytes.\n");
		return NULL;
	}

	// Set the version to 4 (0100 in binary)
	uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;

	// Set the variant to RFC 4122 (10xx in binary)
	uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;

	// Format the UUID as a string
	snprintf(uuid, sizeof(uuid),
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
		uuid_bytes[4], uuid_bytes[5], uuid_bytes[6], uuid_bytes[7],
		uuid_bytes[8], uuid_bytes[9], uuid_bytes[10], uuid_bytes[11],
		uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]);

	return uuid;
}

/* Get the number of bits of an EC key and return the JWT alg type based
 * on the result. */
static const char *ec_alg_type(EVP_PKEY *pkey)
{
	int degree, curve_nid;
	EC_GROUP *group;
	char curve_name[256];

	EVP_PKEY_get_group_name(pkey, curve_name, sizeof(curve_name), NULL);

	curve_nid = OBJ_txt2nid(curve_name);

	/* Short circuit this special case. */
	if (curve_nid == NID_secp256k1)
		return "ES256K";

	group = EC_GROUP_new_by_curve_name(curve_nid);

	degree = EC_GROUP_get_degree(group);
	EC_GROUP_free(group);

	switch (degree) {
	case 256:
		return "ES256";
	case 384:
		return "ES384";
	case 521:
		return "ES512";
	}

	/* Just guess at this point */
	fprintf(stderr, "Unexpected EC degree [%d], defaulting to ES256\n", degree);
	return "ES256";
}

/* Retrieves and b64url-encodes a single OSSL BIGNUM param and adds it to
 * the JSON object as a string. */
static void get_one_bn(EVP_PKEY *pkey, const char *ossl_param,
		       json_t *jwk, const char *name)
{
	/* Get param */
	BIGNUM *bn = NULL;
	EVP_PKEY_get_bn_param(pkey, ossl_param, &bn);

	/* Extract data */
	int len = BN_num_bytes(bn);
	unsigned char *bin = OPENSSL_malloc(len);
	BN_bn2bin(bn, bin);
	BN_free(bn);

	/* Encode */
	char *b64;
	jwt_base64uri_encode(&b64, (char *)bin, len);
	OPENSSL_free(bin);
	json_object_set_new(jwk, name, json_string(b64));
	jwt_freemem(b64);
}

/* Retrieves a single OSSL string param and adds it to the  JSON object. */
static void get_one_string(EVP_PKEY *pkey, const char *ossl_param,
			   json_t *jwk, const char *name)
{
	char buf[256];
	size_t len = sizeof(buf);
	EVP_PKEY_get_utf8_string_param(pkey, ossl_param, buf, len, NULL);
	json_object_set_new(jwk, name, json_string(buf));
}

/* Retrieves and b64url-encodes a single OSSL octet param and adds it to
 * the JSON object as a string. */
static void get_one_octet(EVP_PKEY *pkey, const char *ossl_param,
                          json_t *jwk, const char *name)
{
	unsigned char buf[256];
	size_t len;
	EVP_PKEY_get_octet_string_param(pkey, ossl_param, buf, sizeof(buf), &len);
        char *b64;
	jwt_base64uri_encode(&b64, (char *)buf, len);
	json_object_set_new(jwk, name, json_string(b64));
        jwt_freemem(b64);
}

/* For ECC Keys (ES256, ES384, ES512) */
static void process_ec_key(EVP_PKEY *pkey, int priv, json_t *jwk)
{
	const char *alg_type = ec_alg_type(pkey);

	json_object_set_new(jwk, "alg", json_string(alg_type));

	get_one_string(pkey, OSSL_PKEY_PARAM_GROUP_NAME, jwk, "crv");

	get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_X, jwk, "x");
	get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, jwk, "y");
	if (priv)
		get_one_bn(pkey, OSSL_PKEY_PARAM_PRIV_KEY, jwk, "d");
}

/* For EdDSA keys (EDDSA) */
static void process_eddsa_key(EVP_PKEY *pkey, int priv, json_t *jwk)
{
	if (priv)
		get_one_octet(pkey, OSSL_PKEY_PARAM_PRIV_KEY, jwk, "d");
	else
		get_one_octet(pkey, OSSL_PKEY_PARAM_PUB_KEY, jwk, "x");
}

/* For RSA keys (RS256, RS384, RS512). Also works for RSA-PSS
 * (PS256, PS384, PS512) */
static void process_rsa_key(EVP_PKEY *pkey, int priv, json_t *jwk)
{
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_N, jwk, "n");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_E, jwk, "e");

	if (!priv)
		return;

	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_D, jwk, "d");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, jwk, "p");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, jwk, "q");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, jwk, "dp");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, jwk, "dq");
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, jwk, "qi");
}

static json_t *parse_one_file(const char *file)
{
	int priv = 0;
	FILE *fp;
	EVP_PKEY *pkey;
	json_t *jwk, *ops;

	fp = fopen(file, "r");
	if (!fp) {
		perror("Error opening PEM file");
		exit(EXIT_FAILURE);
	}

	/* Try public key first */
	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	if (pkey == NULL) {
		/* Retry with private key type */
		rewind(fp);
		pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		priv = 1;
	}
	fclose(fp);

	if (pkey == NULL) {
		fprintf(stderr, "Error parsing key file\n");
		print_openssl_errors_and_exit();
	}

	/* Setup json object */
	jwk = json_object();
	json_object_set_new(jwk, "use", json_string("sig"));

	/* Add key ops */
	ops = json_array();
	json_array_append_new(ops, json_string("verify"));
	if (priv)
		json_array_append_new(ops, json_string("sign"));
	json_object_set_new(jwk, "key_ops", ops);

	/* Use uuidv4 for "kid" */
	json_object_set_new(jwk, "kid", json_string(uuidv4()));

	/* Process per key type params */
	switch (EVP_PKEY_get_base_id(pkey)) {
	case EVP_PKEY_RSA:
		json_object_set_new(jwk, "kty", json_string("RSA"));
		process_rsa_key(pkey, priv, jwk);
		rsa_count++;
		break;

	case EVP_PKEY_EC:
		json_object_set_new(jwk, "kty", json_string("EC"));
		process_ec_key(pkey, priv, jwk);
		ec_count++;
		break;

	case EVP_PKEY_ED25519:
		json_object_set_new(jwk, "kty", json_string("OKP"));
		json_object_set_new(jwk, "crv", json_string("Ed25519"));
		json_object_set_new(jwk, "alg", json_string("EDDSA"));
		process_eddsa_key(pkey, priv, jwk);
		eddsa_count++;
		break;

	case EVP_PKEY_RSA_PSS:
		/* XXX We need a way to designate this for PS alg only ???
		 * For now, default to PS256. */
		json_object_set_new(jwk, "kty", json_string("RSA"));
		json_object_set_new(jwk, "alg", json_string("PS256"));
		process_rsa_key(pkey, priv, jwk);
		rsa_pss_count++;
		break;

	default:
		fprintf(stderr, "Skipped unknown key type: %s\n", file);
	}

	EVP_PKEY_free(pkey);

	return jwk;
}

int main(int argc, char **argv)
{
	json_t *jwk_set, *jwk_array, *jwk;
	char *jwk_str;
	int i;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <PEM file(s)>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Parsing %d files (", argc - 1);

	jwk_array = json_array();

	for (i = 1; i < argc; i++) {
		jwk = parse_one_file(argv[i]);
		json_array_append_new(jwk_array, jwk);
		fprintf(stderr, ".");
	}
	fprintf(stderr, ") done\n");

	fprintf(stderr, "Parse results:\n");
	if (ec_count)
		fprintf(stderr, "  EC     : %d\n", ec_count);
	if (rsa_count)
		fprintf(stderr, "  RSA    : %d\n", rsa_count);
	if (rsa_pss_count)
		fprintf(stderr, "  RSA-PSS: %d\n", rsa_pss_count);
	if (eddsa_count)
		fprintf(stderr, "  EdDSA  : %d\n", eddsa_count);
	fprintf(stderr, "\n");

	fprintf(stderr, "Generating JWKS...\n");

	jwk_set = json_object();
	json_object_set_new(jwk_set, "keys", jwk_array);

	jwk_str = json_dumps(jwk_set, JSON_INDENT(2));
	printf("%s\n", jwk_str);

	free(jwk_str);

	exit(EXIT_SUCCESS);
}
