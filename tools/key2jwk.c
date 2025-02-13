/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* XXX BIG FAT WARNING: There's not much error checking here. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>

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

#include "jwt-util.h"

/* We make use of some LibJWT internals. Soon, this code will move into LibJWT
 * so it can be used to important PEM/DER keys into a JWK keyring. Until then,
 * we hack around it here. */
#include "jwt-private.h"

static int ec_count, rsa_count, eddsa_count, rsa_pss_count, hmac_count;

static void print_openssl_errors_and_exit()
{
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

static int with_kid = 1;
static int do_not_assume_hmac = 0;

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

/* Set the alg and crv for an EC key */
static void ec_alg_type(EVP_PKEY *pkey, char crv[32], char alg[32])
{
	char __named_crv[32];
	char *__alg = NULL, *__crv = NULL;
	size_t bits;

	crv[0] = alg[0] = '\0';

	EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_BITS,
				  &bits);

	EVP_PKEY_get_group_name(pkey, __named_crv, sizeof(__named_crv), NULL);

	switch (bits) {
	case 256:
		if (!strcmp(__named_crv, "secp256k1")) {
			__alg = "ES256K";
			__crv = "secp256k1";
		} else {
			__alg = "ES256";
			__crv = "P-256";
		}
		break;

	case 384:
		__alg = "ES384";
		__crv = "P-384";
		break;

	case 521:
		__alg = "ES512";
		__crv = "P-521";
		break;
	}

	if (!__alg || !__crv) {
		fprintf(stderr, "EC: Unknown curve %s with %d bits\n",
			__named_crv, (int)bits);
		return;
	}

	strcpy(crv, __crv);
	strcpy(alg, __alg);
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
	char alg_type[32], crv[32];

	ec_alg_type(pkey, crv, alg_type);

	json_object_set_new(jwk, "alg", json_string(alg_type));
	json_object_set_new(jwk, "crv", json_string(crv));

	get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_X, jwk, "x");
	get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, jwk, "y");
	if (priv)
		get_one_bn(pkey, OSSL_PKEY_PARAM_PRIV_KEY, jwk, "d");
}

/* For EdDSA keys */
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

static void process_hmac_key(json_t *jwk, const unsigned char *key, size_t len)
{
	char *b64;

	json_object_set_new(jwk, "kty", json_string("oct"));

	jwt_base64uri_encode(&b64, (char *)key, len);
	json_object_set_new(jwk, "k", json_string(b64));
	jwt_freemem(b64);

	if (len >= 32 && len < 48)
		json_object_set_new(jwk, "alg", json_string("HS256"));
	else if (len >= 48 && len < 64)
		json_object_set_new(jwk, "alg", json_string("HS384"));
	else if (len >= 64)
		json_object_set_new(jwk, "alg", json_string("HS512"));

	hmac_count++;
}

static json_t *parse_one_file(const char *file)
{
	int priv = 0;
	FILE *fp;
	EVP_PKEY *pkey;
	json_t *jwk, *ops;
	size_t len = 0;
	unsigned char file_buf[BUFSIZ];

	fp = fopen(file, "r");
	if (!fp) {
		perror("Error opening file");
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

	if (pkey == NULL) {
		/* Check length to see if it can be HMAC */
		fseek(fp, 0, SEEK_END);
		len = ftell(fp);
		if (do_not_assume_hmac || len < 32 || len > sizeof(file_buf)) {
			fprintf(stderr, "Error parsing key file\n");
			print_openssl_errors_and_exit();
		}

		rewind(fp);
		len = fread(file_buf, 1, len, fp);
		priv = 1;
	}

	fclose(fp);

	/* Setup json object */
	jwk = json_object();
	if (!priv) {
		/* Key use */
		json_object_set_new(jwk, "use", json_string("sig"));
	} else {
		/* Key ops */
		ops = json_array();
		json_array_append_new(ops, json_string("sign"));
		json_object_set_new(jwk, "key_ops", ops);
	}

	/* Use uuidv4 for "kid" */
	if (with_kid)
		json_object_set_new(jwk, "kid", json_string(uuidv4()));

	if (len) {
		process_hmac_key(jwk, file_buf, len);
		return jwk;
	}

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
		json_object_set_new(jwk, "alg", json_string("EdDSA"));
		process_eddsa_key(pkey, priv, jwk);
		eddsa_count++;
		break;

	case EVP_PKEY_ED448:
		json_object_set_new(jwk, "kty", json_string("OKP"));
		json_object_set_new(jwk, "crv", json_string("Ed448"));
		json_object_set_new(jwk, "alg", json_string("EdDSA"));
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

_Noreturn static void usage(const char *error, int exit_state)
{
	if (error)
		fprintf(stderr, "ERROR: %s\n\n", error);

	fprintf(stderr, "\
Usage: %s [OPTIONS] <FILE> [FILE]...\n\
\n\
Parse PEM/DER file(s) into JSON Web Key format.\n\
\n\
  -h, --help            This help information\n\
  -q, --quiet           No output other than JWKS file\n\
  -l, --list            List supported algorithms and exit\n\
  -k, --disable-kid     Disable generating \"kid\" attribute\n\
  -m, --disable-hmac    Disable fallback to HMAC\n\
  -o, --output=FILE     File to write JWKS to\n\
\n\
This program will parse PEM/DER key files (public and private) into JSON Web\n\
Keys and output a JWK Set. Note that HMAC keys are \"guessed\" based on them\n\
not being parsed by OpenSSL. This may cause some issues. You can disable\n\
this with the -m option.\n\
\n\
You can use '-' as the argument to the -o option to write to stdout.\n\
\n\
RSA keys will not have an algorithm set as they are valid for RS256, RS384,\n\
and RS512. RSA keys must be at least 1024 bits.\n\
\n\
RSA-PSS keys will be set to PS256, otherwise they will look no different\n\
than an RSA key.\n\
\n\
All keys will get a generated randomized uuidv4 \"kid\" attribute unless you\n\
use the -k option..\n", get_progname());

	exit(exit_state);
}

int main(int argc, char **argv)
{
	json_t *jwk_set, *jwk_array, *jwk;
	time_t now;
	char *time_str;
	char comment[256];
	jwt_alg_t alg;
	int quiet = 0;
	char *jwk_str;
	FILE *outfp = NULL;
	FILE *msg = stdout;
	int i, oc;

	char *optstr = "hlqo:km";
	struct option opttbl[] = {
		{ "help",		no_argument,		NULL, 'h' },
		{ "list",		no_argument,		NULL, 'l' },
		{ "quiet",		no_argument,		NULL, 'q' },
		{ "output",		required_argument,	NULL, 'o' },
		{ "disable-kid",	no_argument,		NULL, 'k' },
		{ "disable-hmac",	no_argument,		NULL, 'm' },
		{ NULL, 0, 0, 0 },
	};

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		switch (oc) {
		case 'h':
			usage(NULL, EXIT_SUCCESS);

		case 'l':
			printf("Algorithms supported:\n");
			for (alg = JWT_ALG_NONE; alg < JWT_ALG_INVAL; alg++)
				printf("    %s\n", jwt_alg_str(alg));
			exit(EXIT_SUCCESS);
			break;

		case 'q':
			quiet = 1;
			break;

		case 'k':
			with_kid = 0;
			break;

		case 'm':
			do_not_assume_hmac = 1;
			break;

		case 'o':
			if (optarg[0] == '-') {
				outfp = stdout;
				msg = stderr;
			} else {
				outfp = fopen(optarg, "wx");
				if (outfp == NULL)
					perror(optarg);
			}
			break;
		default: /* '?' */
			usage("Unknown option", EXIT_FAILURE);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage("No key(s) given", EXIT_FAILURE);

	if (outfp == NULL)
		usage("The --output argument is required", EXIT_FAILURE);


	if (!quiet)
		fprintf(msg, "Parsing %d files (", argc);

	jwk_array = json_array();

	for (i = 0; i < argc; i++) {
		jwk = parse_one_file(argv[i]);
		json_array_append_new(jwk_array, jwk);
		if (!quiet)
			fprintf(msg, ".");
	}
	if (!quiet) {
		fprintf(msg, ") done\n");

		fprintf(msg, "Parse results:\n");
		if (ec_count)
			fprintf(msg, "  EC     : %d\n", ec_count);
		if (rsa_count)
			fprintf(msg, "  RSA    : %d\n", rsa_count);
		if (rsa_pss_count)
			fprintf(msg, "  RSA-PSS: %d\n", rsa_pss_count);
		if (eddsa_count)
			fprintf(msg, "  EdDSA  : %d\n", eddsa_count);
		if (hmac_count)
			fprintf(msg, "  HMAC   : %d\n", hmac_count);
		fprintf(msg, "\n");

		fprintf(msg, "Generating JWKS...\n");
	}

	jwk_set = json_object();
	snprintf(comment, sizeof(comment), "Generated by LibJWT %s",
		 JWT_VERSION_STRING);
	comment[sizeof(comment) - 1] = '\0';
	json_object_set_new(jwk_set, "libjwt.io:comment", json_string(comment));

	now = time(NULL);
	time_str = ctime(&now);
	time_str[strlen(time_str) - 1] = '\0';
	json_object_set_new(jwk_set, "libjwt.io:date", json_string(time_str));

#ifdef _WIN32
	DWORD hostnamesize = sizeof(comment);
	GetComputerNameA(comment, &hostnamesize);
#else
	gethostname(comment, sizeof(comment));
#endif
	comment[sizeof(comment) - 1] = '\0';
	json_object_set_new(jwk_set, "libjwt.io:hostname",
			    json_string(comment));

	json_object_set_new(jwk_set, "keys", jwk_array);

	jwk_str = json_dumps(jwk_set, JSON_INDENT(2));
	fprintf(outfp, "%s\n", jwk_str);

	free(jwk_str);

	exit(EXIT_SUCCESS);
}
