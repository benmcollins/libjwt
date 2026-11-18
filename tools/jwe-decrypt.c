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
#include <errno.h>

#include "jwt-util.h"

_Noreturn static void usage(const char *error, int exit_state)
{
	if (error)
		fprintf(stderr, "ERROR: %s\n\n", error);

	fprintf(stderr, "\
Usage: %s [OPTIONS] [TOKEN]\n\
\n\
Decrypt and authenticate a JSON Web Encryption (JWE) token\n\
\n\
  -h, --help            This help information\n\
  -k, --key=FILE        Filename containing a JSON Web Key (required)\n\
  -a, --algorithm=ALG   Expected JWE key management algorithm\n\
  -e, --enc=ENC         Expected JWE content encryption algorithm\n\
\n\
The serialization (Compact or JSON, Flattened or General) is detected\n\
automatically. For a General JSON token the recipient matching the given\n\
key and --algorithm is selected. The configured --algorithm and --enc act\n\
as an allow-list: a token whose header does not match is rejected. On\n\
success the decrypted plaintext is written to stdout.\n\
\n\
The token is the one argument or, with no argument, the whole of stdin.\n\
From stdin a trailing newline is dropped; a NUL byte anywhere, or (for a\n\
Compact token) a second token or a token split over lines, is an error. A\n\
JSON token may span lines. Empty stdin, or a read error, is an error.\n",
		get_progname());

	exit(exit_state);
}

/* The buffer for the one token read from stdin, so the token can be up to one
 * byte shorter. Generous for a CLI; a longer token is rejected whole. */
#define MAX_TOKEN_LEN (1024 * 1024)

/* Read the whole of stdin as the single token into @buf (NUL-terminated).
 * One trailing line end (LF, CRLF or a lone CR) is dropped. The serialization
 * is detected as the library does it, from the first non-space byte: a
 * Compact token is one line, so a CR or LF left in it -- a second token, or a
 * token split over lines -- is an error rather than being joined; a JSON
 * token ('{') may span lines and is left as read, so the parser rejects
 * anything after it. A NUL byte anywhere, a token too long for @buf, or a
 * read error rejects the whole input and nothing is decrypted. Returns 1 for
 * a token, 0 for empty stdin, -1 for a NUL byte, -4 for an over-long token,
 * -2 for a read error, and -3 for a CR or LF inside a Compact token. */
static int read_stdin_token(char *buf, size_t size)
{
	size_t len = 0;
	int c, nul = 0, toolong = 0;
	const char *p;

	while ((c = fgetc(stdin)) != EOF) {
		if (c == '\0')
			nul = 1;
		else if (len + 1 >= size)
			toolong = 1;
		else
			buf[len++] = (char)c;
	}

	if (ferror(stdin))
		return -2;
	if (nul)			/* a NUL takes priority over over-length */
		return -1;
	if (toolong)
		return -4;

	/* Drop one trailing line end, so a token with or without one both
	 * decrypt; anything else left in a Compact token is caught below. */
	if (len && buf[len - 1] == '\n')
		len--;
	if (len && buf[len - 1] == '\r')
		len--;
	buf[len] = '\0';

	if (len == 0)
		return 0;

	for (p = buf; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; p++)
		;
	if (*p != '{' && strcspn(buf, "\r\n") != len)
		return -3;

	return 1;
}

int main(int argc, char *argv[])
{
	jwe_checker_auto_t *checker = NULL;
	jwk_set_auto_t *jwk_set = NULL;
	const jwk_item_t *item = NULL;
	char *key_file = NULL, *token = NULL;
	jwe_key_alg_t alg = JWE_ALG_NONE;
	jwe_enc_t enc = JWE_ENC_NONE;
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	int oc, ret = EXIT_SUCCESS;

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

	/* The token is the one argument, or the whole of stdin. More than one
	 * argument used to decrypt the first and silently ignore the rest. */
	if (optind < argc) {
		if (argc - optind > 1)
			usage("Only one token argument is allowed", EXIT_FAILURE);
		token = argv[optind];
	} else {
		static char tokbuf[MAX_TOKEN_LEN];

		switch (read_stdin_token(tokbuf, sizeof(tokbuf))) {
		case 1:
			token = tokbuf;
			break;
		case 0:
			fprintf(stderr, "ERROR: No token read from stdin\n");
			return EXIT_FAILURE;
		case -2:
			fprintf(stderr, "ERROR: Could not read stdin: %s\n",
				strerror(errno));
			return EXIT_FAILURE;
		case -3:
			fprintf(stderr, "ERROR: stdin has more than one token "
				"(a second token, or a token split over "
				"lines)\n");
			return EXIT_FAILURE;
		case -4:
			fprintf(stderr, "ERROR: Token is too long\n");
			return EXIT_FAILURE;
		default: /* -1 */
			fprintf(stderr, "ERROR: Token has a NUL byte\n");
			return EXIT_FAILURE;
		}
	}

	jwk_set = jwks_create_fromfile(key_file);
	if (jwk_set == NULL || jwks_error(jwk_set)) {
		fprintf(stderr, "ERROR: Could not load key: %s\n",
			jwk_set ? jwks_error_msg(jwk_set) : "(unknown)");
		ret = EXIT_FAILURE;
		goto out;
	}
	item = jwks_item_get(jwk_set, 0);
	if (item == NULL) {
		fprintf(stderr, "ERROR: No key found in file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	checker = jwe_checker_new();
	if (checker == NULL) {
		// LCOV_EXCL_START
		ret = EXIT_FAILURE;
		goto out;
		// LCOV_EXCL_STOP
	}

	if (jwe_checker_setkey(checker, alg, enc, item)) {
		fprintf(stderr, "ERROR: %s\n", jwe_checker_error_msg(checker));
		ret = EXIT_FAILURE;
		goto out;
	}

	pt = jwe_checker_decrypt_all(checker, token, &pt_len);
	if (pt == NULL) {
		fprintf(stderr, "ERROR: %s\n", jwe_checker_error_msg(checker));
		ret = EXIT_FAILURE;
		goto out;
	}

	fwrite(pt, 1, pt_len, stdout);
	fputc('\n', stdout);

out:
	/* Return (not exit()) so the jwk_set_auto_t cleanup runs. The checker
	 * borrows item from jwk_set, so free it before the set it borrows. */
	jwe_checker_freep(&checker);
	free(pt);
	return ret;
}
