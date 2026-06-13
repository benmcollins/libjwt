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
Usage: %s [OPTIONS] [TOKEN]\n\
\n\
Decrypt and authenticate a JSON Web Encryption (JWE) compact token\n\
\n\
  -h, --help            This help information\n\
  -k, --key=FILE        Filename containing a JSON Web Key (required)\n\
  -a, --algorithm=ALG   Expected JWE key management algorithm\n\
  -e, --enc=ENC         Expected JWE content encryption algorithm\n\
\n\
The token may be given as the final argument or, if omitted, read from\n\
stdin. The configured --algorithm and --enc act as an allow-list: a token\n\
whose header does not match is rejected. On success the decrypted\n\
plaintext is written to stdout.\n", get_progname());

	exit(exit_state);
}

int main(int argc, char *argv[])
{
	jwe_checker_auto_t *checker = NULL;
	jwk_set_auto_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	char *key_file = NULL, *token = NULL, *tokbuf = NULL;
	jwe_key_alg_t alg = JWE_ALG_NONE;
	jwe_enc_t enc = JWE_ENC_NONE;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	int oc;

	char *optstr = "hk:a:e:";
	struct option opttbl[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "key",	required_argument,	NULL, 'k' },
		{ "algorithm",	required_argument,	NULL, 'a' },
		{ "enc",	required_argument,	NULL, 'e' },
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

	/* Token from argv or stdin. */
	if (optind < argc) {
		token = argv[optind];
	} else {
		size_t cap = 4096, len = 0;
		int c;

		tokbuf = malloc(cap);
		if (tokbuf == NULL)
			exit(EXIT_FAILURE);
		while ((c = fgetc(stdin)) != EOF) {
			if (c == '\n' || c == '\r')
				continue;
			if (len + 1 >= cap) {
				cap *= 2;
				tokbuf = realloc(tokbuf, cap);
				if (tokbuf == NULL)
					exit(EXIT_FAILURE);
			}
			tokbuf[len++] = (char)c;
		}
		tokbuf[len] = '\0';
		token = tokbuf;
	}

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

	checker = jwe_checker_new();
	if (checker == NULL)
		exit(EXIT_FAILURE);

	if (jwe_checker_setkey(checker, alg, enc, item)) {
		fprintf(stderr, "ERROR: %s\n", jwe_checker_error_msg(checker));
		exit(EXIT_FAILURE);
	}

	pt = jwe_checker_decrypt(checker, token, &pt_len);
	if (pt == NULL) {
		fprintf(stderr, "ERROR: %s\n", jwe_checker_error_msg(checker));
		exit(EXIT_FAILURE);
	}

	fwrite(pt, 1, pt_len, stdout);
	fputc('\n', stdout);

	free(pt);
	free(tokbuf);

	exit(EXIT_SUCCESS);
}
