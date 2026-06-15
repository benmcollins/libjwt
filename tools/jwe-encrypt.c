/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
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

/* An upper bound on -r recipients; generous for a CLI. */
#define MAX_RECIPIENTS 16

_Noreturn static void usage(const char *error, int exit_state)
{
	if (error)
		fprintf(stderr, "ERROR: %s\n\n", error);

	fprintf(stderr, "\
Usage: %s [OPTIONS]\n\
\n\
Encrypt content into a JSON Web Encryption (JWE) token\n\
\n\
  -h, --help            This help information\n\
  -k, --key=FILE        Filename containing a JSON Web Key (required)\n\
  -a, --algorithm=ALG   JWE key management algorithm (e.g. RSA-OAEP-256)\n\
  -e, --enc=ENC         JWE content encryption algorithm (e.g. A256GCM)\n\
  -f, --format=FORMAT   Serialization: compact (default), json-flat,\n\
                        or json-general\n\
  -r, --recipient=ALG:FILE  Add another recipient with key management\n\
                        algorithm ALG and the JWK in FILE. May be repeated;\n\
                        implies --format=json-general.\n\
  -A, --aad=FILE        File whose contents become the JWE AAD (JSON forms)\n\
  -j, --json=STRING     The plaintext to encrypt. If omitted, read from stdin.\n\
\n\
Supported key management (--algorithm, --recipient):\n\
  dir, A128KW, A192KW, A256KW, RSA-OAEP, RSA-OAEP-256,\n\
  ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW\n\
\n\
Supported content encryption (--enc):\n\
  A128GCM, A192GCM, A256GCM,\n\
  A128CBC-HS256, A192CBC-HS384, A256CBC-HS512\n\
\n\
The token is written to stdout. See key2jwk(1) to convert a PEM/DER key\n\
to JWK format.\n", get_progname());

	exit(exit_state);
}

/* Read the whole of @fp into a malloc'd buffer; *@len gets the byte count.
 * The buffer is NOT nil-terminated by length but has a trailing nil for
 * convenience. Exits on allocation failure. */
static char *slurp(FILE *fp, size_t *len)
{
	size_t cap = 4096, n = 0;
	char *buf = malloc(cap);
	int c;

	if (buf == NULL)
		exit(EXIT_FAILURE);
	while ((c = fgetc(fp)) != EOF) {
		if (n + 1 >= cap) {
			cap *= 2;
			buf = realloc(buf, cap);
			if (buf == NULL)
				exit(EXIT_FAILURE);
		}
		buf[n++] = (char)c;
	}
	buf[n] = '\0';
	*len = n;
	return buf;
}

int main(int argc, char *argv[])
{
	jwe_builder_auto_t *builder = NULL;
	jwk_set_auto_t *jwk_set = NULL;
	/* Key sets for -r recipients are kept alive until generate(). */
	jwk_set_t *rsets[MAX_RECIPIENTS] = { NULL };
	int n_rsets = 0;
	const jwk_item_t *item = NULL;
	char *key_file = NULL, *json = NULL, *token = NULL, *aad_file = NULL;
	jwe_key_alg_t alg = JWE_ALG_NONE;
	jwe_enc_t enc = JWE_ENC_NONE;
	jwe_serialization_t format = JWE_FORMAT_COMPACT;
	int have_format = 0;
	char *plaintext = NULL;
	size_t pt_len = 0;
	/* Deferred -r specs so they are applied after setkey. */
	char *recip_spec[MAX_RECIPIENTS];
	int n_recip = 0, i, oc, ret = EXIT_SUCCESS;

	char *optstr = "hk:a:e:f:r:A:j:";
	struct option opttbl[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "key",	required_argument,	NULL, 'k' },
		{ "algorithm",	required_argument,	NULL, 'a' },
		{ "enc",	required_argument,	NULL, 'e' },
		{ "format",	required_argument,	NULL, 'f' },
		{ "recipient",	required_argument,	NULL, 'r' },
		{ "aad",	required_argument,	NULL, 'A' },
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
		case 'f':
			if (!strcmp(optarg, "compact"))
				format = JWE_FORMAT_COMPACT;
			else if (!strcmp(optarg, "json-flat"))
				format = JWE_FORMAT_JSON_FLAT;
			else if (!strcmp(optarg, "json-general"))
				format = JWE_FORMAT_JSON_GENERAL;
			else
				usage("Unknown format (use compact, json-flat, "
				      "or json-general)", EXIT_FAILURE);
			have_format = 1;
			break;
		case 'r':
			if (n_recip >= MAX_RECIPIENTS)
				usage("Too many recipients", EXIT_FAILURE);
			recip_spec[n_recip++] = optarg;
			break;
		case 'A':
			aad_file = optarg;
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
		plaintext = slurp(stdin, &pt_len);
	}

	builder = jwe_builder_new();
	if (builder == NULL)
		exit(EXIT_FAILURE);

	if (jwe_builder_setkey(builder, alg, enc, item)) {
		fprintf(stderr, "ERROR: %s\n", jwe_builder_error_msg(builder));
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Additional recipients: each spec is "ALG:KEYFILE". */
	for (i = 0; i < n_recip; i++) {
		char *spec = recip_spec[i];
		char *colon = strchr(spec, ':');
		jwe_key_alg_t ralg;
		jwk_set_t *rset;

		if (colon == NULL) {
			fprintf(stderr, "ERROR: --recipient must be ALG:FILE\n");
			ret = EXIT_FAILURE;
			goto out;
		}
		*colon = '\0';
		ralg = jwe_str_alg(spec);
		if (ralg == JWE_ALG_INVAL || ralg == JWE_ALG_NONE) {
			fprintf(stderr, "ERROR: Unknown recipient algorithm: %s\n",
				spec);
			ret = EXIT_FAILURE;
			goto out;
		}

		rset = jwks_create_fromfile(colon + 1);
		if (rset == NULL || jwks_error(rset)) {
			fprintf(stderr, "ERROR: Could not load recipient key: %s\n",
				rset ? jwks_error_msg(rset) : "(unknown)");
			jwks_free(rset);
			ret = EXIT_FAILURE;
			goto out;
		}
		rsets[n_rsets++] = rset;

		if (jwe_builder_add_recipient(builder, ralg,
					      jwks_item_get(rset, 0)) == NULL) {
			fprintf(stderr, "ERROR: %s\n",
				jwe_builder_error_msg(builder));
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	/* An explicit --format overrides the json-general implied by -r. */
	if (have_format && jwe_builder_set_format(builder, format)) {
		fprintf(stderr, "ERROR: %s\n", jwe_builder_error_msg(builder));
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Optional AAD from a file. */
	if (aad_file != NULL) {
		size_t aad_len = 0;
		char *aad;
		FILE *fp = fopen(aad_file, "rb");

		if (fp == NULL) {
			fprintf(stderr, "ERROR: Could not open aad file: %s\n",
				aad_file);
			ret = EXIT_FAILURE;
			goto out;
		}
		aad = slurp(fp, &aad_len);
		fclose(fp);
		if (jwe_builder_set_aad(builder, (const unsigned char *)aad,
					aad_len)) {
			fprintf(stderr, "ERROR: %s\n",
				jwe_builder_error_msg(builder));
			free(aad);
			ret = EXIT_FAILURE;
			goto out;
		}
		free(aad);
	}

	token = jwe_builder_generate(builder, (const unsigned char *)plaintext,
				     pt_len);
	if (token == NULL) {
		fprintf(stderr, "ERROR: %s\n", jwe_builder_error_msg(builder));
		ret = EXIT_FAILURE;
		goto out;
	}

	printf("%s\n", token);
	free(token);

out:
	if (json == NULL)
		free(plaintext);
	for (i = 0; i < n_rsets; i++)
		jwks_free(rsets[i]);

	exit(ret);
}
