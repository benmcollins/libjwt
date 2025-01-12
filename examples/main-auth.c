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

static void usage(const char *name)
{
	printf("%s --key example.json --token eyJhb...\n", name);
	printf("Options:\n"
			"  -k --key   KEY    A file in JWK (JSON) format containing the key\n"
			"  -a --alg   ALG    The algorithm used (not needed if contained in JWK)\n"
			"  -t --token TOKEN  A JSON Web Token\n");
	exit(0);
}

static int __verify_wcb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t jval;
	int ret;

	if (config == NULL)
		return 1;

	jwt_set_GET_JSON(&jval, NULL);
	jval.pretty = 1;
	ret = jwt_header_get(jwt, &jval);
	if (!ret) {
		fprintf(stderr, "HEADER:\n%s\n", jval.json_val);
		free(jval.json_val);
	}

	jwt_set_GET_JSON(&jval, NULL);
	jval.pretty = 1;
	ret = jwt_grant_get(jwt, &jval);
	if (!ret) {
		fprintf(stderr, "PAYLOAD:\n%s\n", jval.json_val);
		free(jval.json_val);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	jwt_checker_auto_t *checker = NULL;
	char *key_file = NULL, *token = NULL;
	jwt_alg_t opt_alg = JWT_ALG_NONE;
	jwk_set_auto_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	int oc;

	checker = jwt_checker_new();
	if (checker == NULL) {
		fprintf(stderr, "Could not allocate checker context\n");
		exit(EXIT_FAILURE);
	}

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
		jwk_set = jwks_create_fromfile(key_file);
                if (jwk_set == NULL || jwks_error(jwk_set)) {
                        fprintf(stderr, "ERR: Could not read JWK: %s\n",
                                jwks_error_msg(jwk_set));
                        exit(EXIT_FAILURE);
                }

                /* Get the first key */
                item = jwks_item_get(jwk_set, 0);
                if (jwks_item_error(item)) {
                        fprintf(stderr, "ERR: Could not read JWK: %s\n",
                                jwks_item_error_msg(item));
                        exit(EXIT_FAILURE);
                }

                if (jwt_checker_setkey(checker, opt_alg, item)) {
                        fprintf(stderr, "ERR Loading key: %s\n",
                                jwt_checker_error_msg(checker));
                        exit(EXIT_FAILURE);
                }
	}

	if (jwt_checker_setcb(checker, __verify_wcb, NULL)) {
		fprintf(stderr, "ERR setting callback: %s\n",
			jwt_checker_error_msg(checker));
		exit(EXIT_FAILURE);
	}

	if (jwt_checker_verify(checker, token)) {
		fprintf(stderr, "ERR verifyiung token: %s\n",
			jwt_checker_error_msg(checker));
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "JWT verfified successfully\n");

	exit(EXIT_SUCCESS);
}

