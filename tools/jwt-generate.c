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

void usage(const char *name)
{
	printf("%s OPTIONS\n", name);
	printf("Options:\n"
			"  -k --key KEY  The private key to use for signing (JWT json)\n"
			"  -a --alg ALG  The algorithm to use for signing\n"
			"  -c --claim t:KEY=VALUE  A claim to add to JWT\n"
			"             where t is i, s, or b for integer, string, or boolean\n"
			"  -j --json '{key1:value1}'  A json to add to JWT\n"
			);
	exit(0);
}

static int __gen_wcb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t jval;
	int ret;

	if (config == NULL)
		return 1;

	jwt_set_GET_JSON(&jval, NULL);
	jval.pretty = 1;
	ret = jwt_grant_get(jwt, &jval);
	if (!ret) {
		printf("PAYLOAD:\n%s\n", jval.json_val);
		free(jval.json_val);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char *opt_key_name = NULL;
	jwt_alg_t opt_alg = JWT_ALG_NONE;

	int oc = 0;
	char *optstr = "hk:a:c:j:";
	struct option opttbl[] = {
		{ "help",         no_argument,        NULL, 'h'         },
		{ "key",          required_argument,  NULL, 'k'         },
		{ "alg",          required_argument,  NULL, 'a'         },
		{ "claim",        required_argument,  NULL, 'c'         },
		{ "json",         required_argument,  NULL, 'j'         },
		{ NULL, 0, 0, 0 },
	};

	char *t = NULL, *k = NULL, *v = NULL;
	jwk_set_auto_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	char* opt_json = NULL;
	jwt_builder_auto_t *builder = NULL;
	jwt_value_t jval;
	char *out;

	builder = jwt_builder_new();
	if (builder == NULL) {
		fprintf(stderr, "Could not allocate builder context\n");
		exit(EXIT_FAILURE);
	}

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		switch (oc) {
		case 'k':
			opt_key_name = optarg;
			break;

		case 'a':
			opt_alg = jwt_str_alg(optarg);
			if (opt_alg >= JWT_ALG_INVAL) {
				fprintf(stderr,
					"%s is not supported algorithm\n",
					optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'c':
			t = strtok(optarg, ":");
			if (t == NULL)
				usage(basename(argv[0]));
			k = strtok(NULL, "=");
			if (k == NULL)
				usage(basename(argv[0]));

			v = strtok(NULL, "=");
			if (v == NULL)
				usage(basename(argv[0]));

			switch (t[0]) {
			case 's':
				jwt_set_ADD_STR(&jval, k, v);
				break;
			case 'i':
				jwt_set_ADD_INT(&jval, k, strtol(v, NULL, 10));
				break;
			case 'b':
				if (v[0] == 'f' || v[0] == 'F' || v[0] == '0')
					jwt_set_ADD_BOOL(&jval, k, 0);
				else
					jwt_set_ADD_BOOL(&jval, k, 1);
				break;
			default:
				usage(basename(argv[0]));
			}
			if (jwt_builder_claim_add(builder, &jval)) {
				fprintf(stderr, "Error adding %s:%s=%s\n",
					t, k, v);
				exit(EXIT_FAILURE);
			}

			break;
		case 'j':
			if (optarg != NULL) {
				opt_json = strdup(optarg);
			}
			break;

		case 'h':
			usage(basename(argv[0]));
			return 0;

		default: /* '?' */
			usage(basename(argv[0]));
			exit(EXIT_FAILURE);
		}
	}

	printf("jwtgen: privkey %s algorithm %s\n",
		opt_key_name, jwt_alg_str(opt_alg));

	if (opt_alg != JWT_ALG_NONE && opt_key_name == NULL)
		usage(basename(argv[0]));

	if (opt_key_name) {
		jwk_set = jwks_create_fromfile(opt_key_name);
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

		if (jwt_builder_setkey(builder, opt_alg, item)) {
			fprintf(stderr, "ERR Loading key: %s\n",
				jwt_builder_error_msg(builder));
			exit(EXIT_FAILURE);
		}
	}

	if (opt_json) {
		jwt_set_ADD_JSON(&jval, NULL, opt_json);
		if (jwt_builder_claim_add(builder, &jval)) {
			fprintf(stderr, "Error adding json\n");
			exit(EXIT_FAILURE);
		}
	}

	if (jwt_builder_setcb(builder, __gen_wcb, NULL)) {
		fprintf(stderr, "ERR setting callback: %s\n",
			jwt_builder_error_msg(builder));
		exit(EXIT_FAILURE);
	}

	out = jwt_builder_generate(builder);
	if (out == NULL) {
		fprintf(stderr, "ERR Generating Token: %s\n",
			jwt_builder_error_msg(builder));
		exit(EXIT_FAILURE);
	}

	printf("jwt algo %s!\n", jwt_alg_str(opt_alg));

	printf("%s\n", out);

	free(out);

	return 0;
}
