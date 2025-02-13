/* Copyright (C) 2019 Jeremy Thien <jeremy.thien@gmail.com>
   Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
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

#include "jwt-util.h"

_Noreturn static void usage(const char *error, int exit_state)
{
	if (error)
		fprintf(stderr, "ERROR: %s\n\n", error);

	fprintf(stderr, "\
Usage: %1$s [OPTIONS] <token> [token(s)]\n\
       %1$s [OPTIONS] -\n\
\n\
Decode and (optionally) verify the signature for a JSON Web Token\n\
\n\
  -h, --help            This help information\n\
  -l, --list            List supported algorithms and exit\n\
  -a, --algorithm=ALG   JWT algorithm to use (e.g. ES256). Only needed if the key\n\
                        provided with -k does not have an \"alg\" attribute\n\
  -p, --print=CMD       When printing JSON, pipe through CMD\n\
  -k, --key=FILE        Filename containing a JSON Web Key\n\
  -q, --quiet           No output. Exit value is number of errors\n\
  -v, --verbose         Show decoded header and payload while verifying\n\
\nThis program will decode and validate each token on the command line.\n\
If - is given as the only argument to token, then tokens will be read\n\
from stdin, one per line.\n\
\n\
For the --print option, output will be piped to the command's stdin. This\n\
is useful if you wanted to use something like `jq -C` to colorize it or\n\
another program to validate it. The program will be called twice; once\n\
for the HEAD, and once for the PAYLOAD. A non-0 exit status will cause\n\
the verification to fail.\n\
\n\
If you need to convert a key to JWK (e.g. from PEM or DER format) see\n\
key2jwk(1).\n", get_progname());

	exit(exit_state);
}

static void print_token_trunc(const char *str, size_t max_len)
{
	size_t len = strlen(str);

	if (len <= max_len) {
		printf("%s\n", str);
	} else {
		size_t part_len = (max_len - 3) / 2;

		printf("%.*s...%.*s\n", (int)part_len, str,
		       (int)part_len, str + len - part_len);
	}
}

static int process_one(jwt_checker_t *checker, jwt_alg_t alg, const char *token,
		       int quiet)
{
	int err = 0;

	if (!quiet) {
		printf("\n%s %s[TOK]\033[0m ", alg == JWT_ALG_NONE ?
			"\xF0\x9F\x94\x93" : "\xF0\x9F\x94\x90",
			alg == JWT_ALG_NONE ? "\033[0;93m" : "\033[0;92m");
		print_token_trunc(token, 60);
	}

	if (jwt_checker_verify(checker, token)) {
		if (!quiet) {
			printf("\xF0\x9F\x91\x8E \033[0;91m[BAD]\033[0m %s\n",
				jwt_checker_error_msg(checker));
		}
		err = 1;
	} else if (!quiet) {
		printf("\xF0\x9F\x91\x8D \033[0;92m[YES]\033[0m Verified\n");
	}

	return err;
}

int main(int argc, char *argv[])
{
	jwt_checker_auto_t *checker = NULL;
	const char *key_file = NULL;
	jwt_alg_t alg = JWT_ALG_NONE;
	jwk_set_auto_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	int oc, err, verbose = 0;
	int quiet = 0;

	char *optstr = "hk:alvqp:";
	struct option opttbl[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "key",	required_argument,	NULL, 'k' },
		{ "algorithm",	required_argument,	NULL, 'a' },
		{ "print",	required_argument,	NULL, 'p' },
		{ "list",	no_argument,		NULL, 'l' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ NULL, 0, 0, 0 },
	};

	checker = jwt_checker_new();
	if (checker == NULL) {
		fprintf(stderr, "Could not allocate checker context\n");
		exit(EXIT_FAILURE);
	}

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

		case 'p':
			pipe_cmd = optarg;
			break;

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

		case 'k':
			key_file = optarg;
			break;

		case 'a':
			alg = jwt_str_alg(optarg);
			if (alg >= JWT_ALG_INVAL) {
				fprintf(stderr, "Unknown algorithm [%s]\nUse "
					"-l to see a list of supported "
					"algorithms)\n", optarg);
				exit(EXIT_FAILURE);
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
		usage("No token(s) given", EXIT_FAILURE);

	if (key_file == NULL && alg != JWT_ALG_NONE)
		usage("An algorithm other than 'none' requires a key",
		      EXIT_FAILURE);

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

		if (jwks_item_alg(item) == JWT_ALG_NONE &&
		    alg == JWT_ALG_NONE) {
			usage("Key does not contain an \"alg\" attribute and no --alg given",
			      EXIT_FAILURE);
		}

                if (jwt_checker_setkey(checker, alg, item)) {
                        fprintf(stderr, "ERR Loading key: %s\n",
                                jwt_checker_error_msg(checker));
                        exit(EXIT_FAILURE);
                }
	}

	if (verbose && jwt_checker_setcb(checker, __jwt_wcb, NULL)) {
		fprintf(stderr, "ERR setting callback: %s\n",
			jwt_checker_error_msg(checker));
		exit(EXIT_FAILURE);
	}

	if (item && !quiet) {
		printf("\xF0\x9F\x94\x91 \033[0;92m[KEY]\033[0m %s\n",
		       key_file);
	}

	if (!quiet)
		printf("\xF0\x9F\x93\x83 ");
	if (item && jwks_item_alg(item) != JWT_ALG_NONE) {
		if (!quiet) {
			printf("\033[0;92m[ALG]\033[0m %s (from key)",
			       jwt_alg_str(jwks_item_alg(item)));
		}
		alg = jwks_item_alg(item);
	} else if (!quiet){
		if (alg == JWT_ALG_NONE)
			printf("\033[0;91m[ALG]\033[0m %s (from options)",
			       jwt_alg_str(alg));
		else
			printf("\033[0;92m[ALG]\033[0m %s (from options)",
			       jwt_alg_str(alg));
	}
	if (!quiet)
		printf("\n");

	err = 0;

	if (!strcmp(argv[0], "-")) {
		char token[BUFSIZ];
		while (fgets(token, sizeof(token), stdin) != NULL) {
			token[strcspn(token, "\n")] = '\0';

			err += process_one(checker, alg, token, quiet);
		}
	} else {
		for (oc = 0; oc < argc; oc++) {
			const char *token = argv[oc];
			err += process_one(checker, alg, token, quiet);
		}
	}

	exit(err);
}

