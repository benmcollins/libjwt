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
#include <time.h>
#include <string.h>
#include <libgen.h>

extern const char *__progname;

_Noreturn static void usage(const char *error, int exit_state)
{
	if (error)
		fprintf(stderr, "ERROR: %s\n\n", error);

	fprintf(stderr, "Usage: %s [OPTIONS]\n\n", __progname);
	fprintf(stderr, "Generate and (optionally) sign a JSON Web Token\n\n");
	fprintf(stderr, "  -h, --help            This help information\n");
	fprintf(stderr, "  -l, --list            List supported algorithms and exit\n");
        fprintf(stderr, "  -a, --algorithm=ALG   JWT algorithm to use (e.g. ES256). Only needed if the key\n");
        fprintf(stderr, "                        provided with -k does not have an \"alg\" attribute\n");
	fprintf(stderr, "  -k, --key=FILE        Filename containing a JSON Web Key\n");
	fprintf(stderr, "  -c, --claim=t:k=v     Add a claim to the JWT\n");
	fprintf(stderr, "      t                 One of i, s, or b for integer, string or boolean\n");
	fprintf(stderr, "      k                 The key for this claim\n");
	fprintf(stderr, "      v                 The value of the claim. For integer, must be parsable\n");
	fprintf(stderr, "                        by strtol(). For boolean, if the value starts with 'f',\n");
	fprintf(stderr, "                        'F', or '0' it is taken as false. Anything else is true.\n");
	fprintf(stderr, "  -j, --json=STRING     JSON string to be used as the body of the token\n");
	fprintf(stderr, "  -q, --quiet           No output other than the generated token\n");
        fprintf(stderr, "  -v, --verbose         Show encoded header and payload while verifying. Note that\n");
	fprintf(stderr, "                        the header will not who the 'tpy' and 'alg' attributes\n");
	fprintf(stderr, "                        they are not added until just before signing.\n");
	fprintf(stderr, "\nThis program will encode and sign a token in JWT format.\n");
        fprintf(stderr, "If you need to convert a key to JWT (e.g. from PEM or DER format) see key2jwk(1).\n");

	exit(exit_state);
}

static int __gen_wcb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t jval;
	int ret;

	if (config == NULL)
		return 1;

	jwt_set_GET_JSON(&jval, NULL);
	jval.pretty = 1;
	ret = jwt_header_get(jwt, &jval);
	if (!ret) {
		printf("\033[0;95m[HEADER]\033[0m\n\033[0;96m%s\033[0m\n",
			jval.json_val);
		free(jval.json_val);
	}

	jwt_set_GET_JSON(&jval, NULL);
	jval.pretty = 1;
	ret = jwt_grant_get(jwt, &jval);
	if (!ret) {
		printf("\033[0;95m[PAYLOAD]\033[0m\n\033[0;96m%s\033[0m\n",
			jval.json_val);
		free(jval.json_val);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char *t = NULL, *k = NULL, *v = NULL;
        jwk_set_auto_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	char* json = NULL;
	jwt_builder_auto_t *builder = NULL;
	jwt_value_t jval;
	char *token;
	char *key_file = NULL;
	jwt_alg_t alg = JWT_ALG_NONE;
	int oc = 0;
	int verbose = 0;
	int quiet = 0;

	char *optstr = "hk:a:c:j:lvq";
	struct option opttbl[] = {
		{ "help",       no_argument,		NULL, 'h' },
		{ "key",        required_argument,	NULL, 'k' },
		{ "algorithm",  required_argument,	NULL, 'a' },
		{ "claim",      required_argument,	NULL, 'c' },
		{ "json",       required_argument,	NULL, 'j' },
		{ "list",       no_argument,		NULL, 'l' },
		{ "verbose",    no_argument,		NULL, 'v' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ NULL, 0, 0, 0 },
	};

	builder = jwt_builder_new();
	if (builder == NULL) {
		fprintf(stderr, "Could not allocate builder context\n");
		exit(EXIT_FAILURE);
	}

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		switch (oc) {
		case 'q':
			if (verbose)
				usage("Using -q and -v makes no sense",
				      EXIT_FAILURE);
			quiet = 1;
			break;

		case 'v':
			if (quiet)
				usage("Using -q and -v makes no sense",
				      EXIT_FAILURE);
			verbose = 1;
			break;

		case 'l':
			printf("Algorithms supported:\n");
			for (alg = JWT_ALG_NONE; alg < JWT_ALG_INVAL; alg++)
				printf("    %s\n", jwt_alg_str(alg));
			exit(EXIT_SUCCESS);
			break;

		case 'k':
			key_file = optarg;
			break;

		case 'a':
			alg = jwt_str_alg(optarg);
			if (alg >= JWT_ALG_INVAL) {
				usage("Unknown algorithm (use -l to see a list of "
				      "supported algorithms)\n", EXIT_FAILURE);
			}
			break;

		case 'c':
			t = strtok(optarg, ":");
			if (t == NULL)
				usage("Invalid --claim format",
						EXIT_FAILURE);
			k = strtok(NULL, "=");
			if (k == NULL)
				usage("Invalid --claim format",
						EXIT_FAILURE);

			v = strtok(NULL, "=");
			if (v == NULL)
				usage("Invalid --claim format",
						EXIT_FAILURE);

			switch (t[0]) {
			case 's':
				jwt_set_ADD_STR(&jval, k, v);
				break;
			case 'i':
				jwt_set_ADD_INT(&jval, k, strtol(v, NULL, 0));
				break;
			case 'b':
				if (v[0] == 'f' || v[0] == 'F' || v[0] == '0')
					jwt_set_ADD_BOOL(&jval, k, 0);
				else
					jwt_set_ADD_BOOL(&jval, k, 1);
				break;
			default:
				usage("Invalid --claim format",
						EXIT_FAILURE);
			}
			if (jwt_builder_claim_add(builder, &jval)) {
				fprintf(stderr, "Error adding %s:%s=%s\n",
					t, k, v);
				exit(EXIT_FAILURE);
			}

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

	argc -= optind;
	argv += optind;

	if (argc)
		usage("Unknown extra arguments", EXIT_FAILURE);

	if (key_file == NULL && alg != JWT_ALG_NONE)
		usage("An algorithm other than 'none' requires a key",
		      EXIT_FAILURE);

	if (alg != JWT_ALG_NONE && key_file == NULL)
		usage("Algorithm requires --key",
				EXIT_FAILURE);

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

		if (jwks_item_alg(item) == JWT_ALG_NONE &&
		    alg == JWT_ALG_NONE) {
			usage("Key does not contain an \"alg\" attribute and no --alg given",
			      EXIT_FAILURE);
		}

		if (jwt_builder_setkey(builder, alg, item)) {
			fprintf(stderr, "ERR Loading key: %s\n",
				jwt_builder_error_msg(builder));
			exit(EXIT_FAILURE);
		}
	}

	if (json) {
		jwt_set_ADD_JSON(&jval, NULL, json);
		if (jwt_builder_claim_add(builder, &jval)) {
			fprintf(stderr, "Error adding json\n");
			exit(EXIT_FAILURE);
		}
	}

	if (verbose && jwt_builder_setcb(builder, __gen_wcb, NULL)) {
		fprintf(stderr, "ERR setting callback: %s\n",
			jwt_builder_error_msg(builder));
		exit(EXIT_FAILURE);
	}

	if (item && !quiet)
		printf("\xF0\x9F\x94\x91 \033[0;92m[KEY]\033[0m %s\n",
		       key_file);

	if (!quiet) {
		printf("\xF0\x9F\x93\x83 ");
		if (item && jwks_item_alg(item) != JWT_ALG_NONE) {
			printf("\033[0;92m[ALG]\033[0m %s (from key)",
			       jwt_alg_str(jwks_item_alg(item)));
			alg = jwks_item_alg(item);
		} else {
			printf("\033[0;91m[ALG]\033[0m %s", jwt_alg_str(alg));
		}
		printf("\n");
	}

	token = jwt_builder_generate(builder);
	if (token == NULL) {
		fprintf(stderr, "ERR Generating Token: %s\n",
			jwt_builder_error_msg(builder));
		exit(EXIT_FAILURE);
	}

	if (quiet) {
		printf("%s\n", token);
	} else {
		printf("%s %s[TOK]\033[0m %s\n", alg == JWT_ALG_NONE ?
			"\xF0\x9F\x94\x93" : "\xF0\x9F\x94\x90",
			alg == JWT_ALG_NONE ? "\033[0;93m" : "\033[0;92m",
			token);
	}

	free(token);

	return 0;
}
