/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <stdlib.h>
#include <jwt.h>
#include <getopt.h>
#include <string.h>

#include "jwt-util.h"

_Noreturn static void usage(const char *error, int exit_state)
{
	if (error)
		fprintf(stderr, "ERROR: %s\n\n", error);

	fprintf(stderr, "\
Usage: %s [OPTIONS]\n\
\n\
Encrypt content into a JSON Web Encryption (JWE) compact token\n\
\n\
  -h, --help            This help information\n\
  -k, --key=FILE        Filename containing a JSON Web Key (required)\n\
  -a, --algorithm=ALG   JWE key management algorithm (e.g. RSA-OAEP-256)\n\
  -e, --enc=ENC         JWE content encryption algorithm (e.g. A256GCM)\n\
  -j, --json=STRING     The plaintext to encrypt. If omitted, read from stdin.\n\
\n\
Supported key management (--algorithm):\n\
  dir, A128KW, A192KW, A256KW, RSA-OAEP, RSA-OAEP-256\n\
\n\
Supported content encryption (--enc):\n\
  A128GCM, A192GCM, A256GCM,\n\
  A128CBC-HS256, A192CBC-HS384, A256CBC-HS512\n\
\n\
The token is written to stdout. See key2jwk(1) to convert a PEM/DER key\n\
to JWK format.\n", get_progname());

	exit(exit_state);
}

int main(int argc, char *argv[])
{
	jwe_builder_auto_t *builder = NULL;
	jwk_set_auto_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	char *key_file = NULL, *json = NULL, *token = NULL;
	jwe_key_alg_t alg = JWE_ALG_NONE;
	jwe_enc_t enc = JWE_ENC_NONE;
	char *plaintext = NULL;
	size_t pt_len = 0;
	int oc;

	char *optstr = "hk:a:e:j:";
	struct option opttbl[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "key",	required_argument,	NULL, 'k' },
		{ "algorithm",	required_argument,	NULL, 'a' },
		{ "enc",	required_argument,	NULL, 'e' },
		{ "json",	required_argument,	NULL, 'j' },
		{ NULL, 0, NULL, 0 },
	};

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		switch (oc) {
		case 'k':
			key_file = optarg;
			break;
		case 'a':
			alg = jwe_str_alg(optarg);
			if (alg == JWE_ALG_INVAL)
				usage("Unknown key management algorithm", EXIT_FAILURE);
			break;
		case 'e':
			enc = jwe_str_enc(optarg);
			if (enc == JWE_ENC_INVAL)
				usage("Unknown content encryption algorithm", EXIT_FAILURE);
			break;
		case 'j':
			json = optarg;
			break;
		case 'h':
			usage(NULL, EXIT_SUCCESS);
		default: /* '?' */
			usage("Unknown argument", EXIT_FAILURE);
		}
	}

	if (key_file == NULL)
		usage("A key file is required (-k)", EXIT_FAILURE);
	if (alg == JWE_ALG_NONE)
		usage("A key management algorithm is required (-a)", EXIT_FAILURE);
	if (enc == JWE_ENC_NONE)
		usage("A content encryption algorithm is required (-e)", EXIT_FAILURE);

	jwk_set = jwks_create_fromfile(key_file);
	if (jwk_set == NULL || jwks_error(jwk_set)) {
		fprintf(stderr, "ERROR: Could not load key: %s\n",
			jwk_set ? jwks_error_msg(jwk_set) : "(unknown)");
		exit(EXIT_FAILURE);
	}
	item = jwks_item_get(jwk_set, 0);
	if (item == NULL) {
		fprintf(stderr, "ERROR: No key found in file\n");
		exit(EXIT_FAILURE);
	}

	/* Plaintext from -j or stdin. */
	if (json) {
		plaintext = json;
		pt_len = strlen(json);
	} else {
		size_t cap = 4096, len = 0;
		int c;

		plaintext = malloc(cap);
		if (plaintext == NULL)
			exit(EXIT_FAILURE);
		while ((c = fgetc(stdin)) != EOF) {
			if (len + 1 >= cap) {
				cap *= 2;
				plaintext = realloc(plaintext, cap);
				if (plaintext == NULL)
					exit(EXIT_FAILURE);
			}
			plaintext[len++] = (char)c;
		}
		pt_len = len;
	}

	builder = jwe_builder_new();
	if (builder == NULL)
		exit(EXIT_FAILURE);

	if (jwe_builder_setkey(builder, alg, enc, item)) {
		fprintf(stderr, "ERROR: %s\n", jwe_builder_error_msg(builder));
		exit(EXIT_FAILURE);
	}

	token = jwe_builder_generate(builder, (const unsigned char *)plaintext,
				     pt_len);
	if (token == NULL) {
		fprintf(stderr, "ERROR: %s\n", jwe_builder_error_msg(builder));
		exit(EXIT_FAILURE);
	}

	printf("%s\n", token);

	free(token);
	if (json == NULL)
		free(plaintext);

	exit(EXIT_SUCCESS);
}
