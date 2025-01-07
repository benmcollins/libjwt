/* Copyright (C) 2019 Jeremy Thien <jeremy.thien@gmail.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <stdlib.h>
#include <jwt.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>

void usage(const char *name)
{
	printf("%s --key example.json --token eyJhb...\n", name);
	printf("Options:\n"
			"  -k --key   KEY    A file in JWK (JSON) format containing the key\n"
			"  -a --alg   ALG    The algorithm used (not needed if contained in JWK)\n"
			"  -t --token TOKEN  A JSON Web Token\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	char *key_file = NULL, *token = NULL;
	jwt_alg_t opt_alg = JWT_ALG_NONE;
	JWT_CONFIG_DECLARE(config);
	jwt_auto_t *jwt = NULL;
	jwk_set_auto_t *jwk_set = NULL;
	jwk_item_t *item = NULL;
	FILE *key_fp = NULL;
	char key_data[BUFSIZ];
	int key_len;
	char oc, ret;

	char *optstr = "hk:t:a";
	struct option opttbl[] = {
		{ "help",         no_argument,        NULL, 'h'         },
		{ "key",          required_argument,  NULL, 'k'         },
		{ "token",        required_argument,  NULL, 't'         },
		{ "alg",          required_argument,  NULL, 'a'         },
		{ NULL, 0, 0, 0 },
	};

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		switch (oc) {
		case 'k':
			key_file = optarg;
			break;

		case 't':
			token = optarg;
			break;

		case 'a':
			opt_alg = jwt_str_alg(optarg);
			if (opt_alg >= JWT_ALG_INVAL) {
				fprintf(stderr, "%s is not a supported algorithm\n",
					optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'h':
			usage(basename(argv[0]));
			return 0;

		default: /* '?' */
			usage(basename(argv[0]));
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (token == NULL) {
		fprintf(stderr, "--token is required\n");
		exit(EXIT_FAILURE);
	}

	if (key_file == NULL && opt_alg != JWT_ALG_NONE) {
		fprintf(stderr, "Cannot verify without a --key file if alg "
			"is not none\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "JWT verification:\n"
			"  Token    : %s\n"
			"  Key File : %s\n"
			"  Algorithm: %s\n\n",
			token, key_file ?: "no key needed",
			jwt_alg_str(opt_alg));

	/* Load JWK key */
	if (key_file) {
		key_fp = fopen(key_file, "r");
		if (key_fp == NULL) {
			perror(key_file);
			exit(EXIT_FAILURE);
		}
		key_len = fread(key_data, 1, sizeof(key_data), key_fp);
		fclose(key_fp);
		key_data[key_len] = '\0';

		/* Setup JWK Set */
		jwk_set = jwks_create(NULL, key_data);
		if (jwk_set == NULL || jwks_error(jwk_set)) {
			fprintf(stderr, "ERR: Could not read JWK: %s\n",
				jwks_error_msg(jwk_set));
			exit(EXIT_FAILURE);
		}
		/* Get the first key */
		item = jwks_item_get(jwk_set, 0);
		if (item->error) {
			fprintf(stderr, "ERR: Could not read JWK: %s\n",
				item->error_msg);
			exit(EXIT_FAILURE);
		}

		if (item->alg == JWT_ALG_NONE && opt_alg == JWT_ALG_NONE) {
			fprintf(stderr, "Cannot find a valid algorithm in the "
				" JWK. You need to set it with --alg\n");
			exit(EXIT_FAILURE);
		}

		if (item->alg != JWT_ALG_NONE && opt_alg != JWT_ALG_NONE &&
		    item->alg != opt_alg) {
			fprintf(stderr, "Key algorithm does not match --alg argument\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Decode jwt */
	config.jw_key = item;
	config.alg = opt_alg;
	ret = jwt_verify(&jwt, token, &config);
	if (ret != 0 || jwt == NULL) {
		fprintf(stderr, "JWT could not be verified\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "JWT %s successfully!\n",
		token ? "verified" : "decoded");

	jwt_dump_fp(jwt, stdout, 1);

	exit(EXIT_SUCCESS);
}

