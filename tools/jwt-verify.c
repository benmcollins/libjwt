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

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include "jwt-util.h"

/* The buffer for one line of stdin, so a token read from there can be up to
 * one byte shorter. Generous for a CLI. A line that does not fit is rejected
 * whole. */
#define MAX_LINE_LEN (1024 * 1024)

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
                        provided with -k does not have an \"alg\" attribute. With\n\
                        no key, \"-a none\" accepts an unsigned (\"alg\":\"none\")\n\
                        token; without it such a token is rejected\n\
  -p, --print=CMD       When printing JSON, pipe through CMD (requires -v)\n\
  -k, --key=FILE        Filename containing a JSON Web Key\n\
  -r, --keyring=FILE    Filename containing a JWKS to verify against (RFC 7515),\n\
                        for Compact and (multi-signature) JSON tokens alike: a\n\
                        signature's kid selects that key, one without a kid is\n\
                        tried against every compatible key. Exclusive with --key\n\
  -P, --policy=POLICY   Multi-signature policy: any (default, accept if one\n\
                        signature verifies) or all (every signature must)\n\
  -q, --quiet           Only errors are printed. The exit status gives the result\n\
  -v, --verbose         Show decoded header and payload while verifying\n\
\nThis program will decode and validate each token on the command line.\n\
If - is given as the only argument to token, then tokens will be read\n\
from stdin, one per line.\n\
\n\
The exit status is 0 if every token was verified (its signature checked\n\
with -k or -r). With neither, a token is rejected unless it is unsigned and\n\
\"-a none\" was given, which decodes it without checking a signature. It is\n\
1 if any token failed, or if there was no token to verify.\n\
\n\
-h and -l verify nothing and exit 0 only when given alone. An argument that\n\
starts with - is read as an option unless it comes after --. To check a\n\
token from an untrusted source, pass it on stdin, or reject it first if it\n\
starts with -, which a real token never does.\n\
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

/* A token, or an error message (which can quote the token's "alg"), is
 * printed on stdout with write_escaped() from jwt-util.h, so that a UTF-8
 * terminal reads no control character from it. Each byte below 0x20, 0x7f,
 * each byte that does not start well-formed UTF-8 (RFC 3629: no overlong
 * form, no surrogate, nothing above U+10FFFF, nothing cut short) and both
 * bytes of a C1 control (U+0080 to U+009F, encoded C2 80 to C2 9F) are
 * printed as \xNN. Printable ASCII and all other well-formed UTF-8 are
 * printed as they are. On a UTF-8 terminal, a CR, an ESC or a CSI from a
 * token therefore cannot change the "[TOK]", "[BAD]" or "[YES]" lines. The
 * colour and emoji framing around the text is ours and is printed as is. */
static void print_escaped(const char *str, size_t len)
{
	write_escaped(stdout, str, len, 0);
}

static void print_token_trunc(const char *str, size_t max_len)
{
	size_t len = strlen(str);

	if (len <= max_len) {
		print_escaped(str, len);
	} else {
		size_t part_len = (max_len - 3) / 2;

		print_escaped(str, part_len);
		printf("...");
		print_escaped(str + len - part_len, part_len);
	}
	putchar('\n');
}

static int process_one(jwt_checker_t *checker, int signed_only,
		       const char *token, int quiet)
{
	int err = 0;

	if (!quiet) {
		printf("\n%s %s[TOK]\033[0m ", signed_only ?
			"\xF0\x9F\x94\x90" : "\xF0\x9F\x94\x93",
			signed_only ? "\033[0;92m" : "\033[0;93m");
		print_token_trunc(token, 60);
	}

	if (jwt_checker_verify(checker, token)) {
		if (!quiet) {
			const char *msg = jwt_checker_error_msg(checker);

			/* The message echoes the token's "alg" header, so it
			 * is escaped too. */
			printf("\xF0\x9F\x91\x8E \033[0;91m[BAD]\033[0m ");
			print_escaped(msg, strlen(msg));
			putchar('\n');
		}
		err = 1;
	} else if (!quiet) {
		printf("\xF0\x9F\x91\x8D \033[0;92m[YES]\033[0m Verified\n");
	}

	return err;
}

/* read_line() looks at every byte of a line so that a NUL byte, or a line
 * that does not fit, fails the whole line (GHSA-g7xw-4cjw-2247). Reading one
 * byte at a time with fgetc() takes the stdin lock once per byte, which on
 * macOS is most of the run time on bulk input (#373). getc_unlocked() inside
 * a single flockfile()/funlockfile() region takes the lock once per line and
 * reads the exact same bytes. These three names are POSIX; mingw-w64 declares
 * none of them, so the plain fgetc() loop (which locks per byte there) is kept
 * for _WIN32 -- the Windows build is not the one with the stdin-lock cost. */
#ifdef _WIN32
#define stdin_lock()	((void)0)
#define stdin_getc()	fgetc(stdin)
#define stdin_unlock()	((void)0)
#else
#define stdin_lock()	flockfile(stdin)
#define stdin_getc()	getc_unlocked(stdin)
#define stdin_unlock()	funlockfile(stdin)
#endif

/* Read one line of stdin into @buf, without its newline. Returns 1 for a
 * line (the last one needs no newline), 0 at the end of the input or on a
 * read error, and -1 for a line that does not fit in @buf or has a NUL byte
 * in it. Such a line is read to its end and is one failed token: no part of
 * it may be verified on its own, so @buf is left empty unless 1 is
 * returned. */
static int read_line(char *buf, size_t size)
{
	size_t len = 0;
	int c, ret = 1;

	/* One lock for the whole line, not one per byte. */
	stdin_lock();
	while ((c = stdin_getc()) != EOF && c != '\n') {
		if (c == '\0' || len + 1 >= size)
			ret = -1;
		else
			buf[len++] = (char)c;
	}
	stdin_unlock();

	/* The end of the input, or a read error: a line cut short by one is
	 * not a token either. */
	if (c == EOF && (ferror(stdin) || (len == 0 && ret > 0)))
		ret = 0;

	buf[ret > 0 ? len : 0] = '\0';

	return ret;
}

/* Verify every line of stdin as one token. Returns 0 only if there was at
 * least one and they all verified. */
static int process_stdin(jwt_checker_t *checker, int signed_only, int quiet)
{
	static char token[MAX_LINE_LEN];
	int ret, err = 0, seen = 0;

	while ((ret = read_line(token, sizeof(token))) != 0) {
		seen = 1;

		if (ret > 0) {
			err |= process_one(checker, signed_only, token, quiet);
			continue;
		}

		/* No part of this line is verified. */
		err = 1;
		if (!quiet)
			printf("\n\xF0\x9F\x91\x8E \033[0;91m[BAD]\033[0m "
			       "Line is too long or has a NUL byte\n");
	}

	/* Nothing to verify is not success, nor is a read error. */
	if (ferror(stdin)) {
		fprintf(stderr, "ERR: Could not read stdin: %s\n",
			strerror(errno));
		err = 1;
	} else if (!seen) {
		fprintf(stderr, "ERR: No token(s) read from stdin\n");
		err = 1;
	}

	return err;
}

int main(int argc, char *argv[])
{
	jwt_checker_auto_t *checker = NULL;
	const char *key_file = NULL;
	const char *keyring_file = NULL;
	jwt_alg_t alg = JWT_ALG_NONE;
	int alg_given = 0;
	jwt_verify_policy_t policy = JWT_VERIFY_POLICY_ANY;
	jwk_set_auto_t *jwk_set = NULL;
	jwk_set_auto_t *keyring = NULL;
	const jwk_item_t *item = NULL;
	int oc, err, verbose = 0;
	int quiet = 0;
	int signed_only;
	int want_help = 0, want_list = 0, nopts = 0;

	char *optstr = "hk:r:P:a:lvqp:";
	struct option opttbl[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "key",	required_argument,	NULL, 'k' },
		{ "keyring",	required_argument,	NULL, 'r' },
		{ "policy",	required_argument,	NULL, 'P' },
		{ "algorithm",	required_argument,	NULL, 'a' },
		{ "print",	required_argument,	NULL, 'p' },
		{ "list",	no_argument,		NULL, 'l' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ NULL, 0, 0, 0 },
	};

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		nopts++;
		switch (oc) {
		case 'h':
			want_help = 1;
			break;

		case 'l':
			want_list = 1;
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

		case 'r':
			keyring_file = optarg;
			break;

		case 'P':
			if (!strcmp(optarg, "any"))
				policy = JWT_VERIFY_POLICY_ANY;
			else if (!strcmp(optarg, "all"))
				policy = JWT_VERIFY_POLICY_ALL;
			else
				usage("Unknown --policy (any|all)", EXIT_FAILURE);
			break;

		case 'a':
			alg = jwt_str_alg(optarg);
			if (alg >= JWT_ALG_INVAL) {
				fprintf(stderr, "Unknown algorithm [%s]\nUse "
					"-l to see a list of supported "
					"algorithms)\n", optarg);
				exit(EXIT_FAILURE);
			}
			alg_given = 1;
			break;

		default: /* '?' */
			usage("Unknown option", EXIT_FAILURE);
			break;
		}
	}

	/* -h/-l print and exit 0 only when they are the sole argument and the
	 * only option in it. Given with a token (or a key, or any other option)
	 * they would otherwise exit 0 while the tokens went unverified
	 * (GHSA-g7xw-4cjw-2247), so that is now a usage error. argc != 2 catches
	 * a separate argument (a token, or -h -v); nopts != 1 catches options
	 * clustered into the one argument (getopt reads -hv as -h -v), which
	 * leave argc at 2. A later bad option still fails first. */
	if (want_help || want_list) {
		if (argc != 2 || nopts != 1)
			usage("--help and --list take no other arguments",
			      EXIT_FAILURE);
		if (want_help)
			usage(NULL, EXIT_SUCCESS);
		printf("Algorithms supported:\n");
		for (alg = JWT_ALG_NONE; alg < JWT_ALG_INVAL; alg++) {
			const char *name = jwt_alg_str(alg);
			/* An alg compiled out of this build (e.g. ML-DSA
			 * without WITH_ML_DSA) has no name. */
			if (name != NULL)
				printf("    %s\n", name);
		}
		exit(EXIT_SUCCESS);
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage("No token(s) given", EXIT_FAILURE);

	/* Tokens given after a - would never be verified. */
	if (argc > 1 && !strcmp(argv[0], "-"))
		usage("- must be the only token argument", EXIT_FAILURE);

	/* A keyring's keys decide the algorithm of each signature. */
	if (keyring_file && alg_given)
		usage("--algorithm cannot be used with --keyring",
		      EXIT_FAILURE);

	if (key_file == NULL && alg != JWT_ALG_NONE)
		usage("An algorithm other than 'none' requires a key",
		      EXIT_FAILURE);

	if (key_file && keyring_file)
		usage("--key and --keyring are mutually exclusive",
		      EXIT_FAILURE);

	/* --print runs its command only with --verbose; without it the command
	 * would be silently skipped and a token pass on its signature alone. */
	if (pipe_cmd && !verbose)
		usage("--print requires --verbose", EXIT_FAILURE);

	/* Allocate the checker only now, after all option parsing and the
	 * usage() checks above, so those exit() paths leave nothing allocated
	 * (allocate after option parsing, as the jwe-* tools do). Every error
	 * path from here returns (not exit()) so the *_auto_t cleanups for the
	 * checker, jwk_set and keyring run. */
	checker = jwt_checker_new();
	if (checker == NULL) {
		// LCOV_EXCL_START
		fprintf(stderr, "Could not allocate checker context\n");
		return EXIT_FAILURE;
		// LCOV_EXCL_STOP
	}

	/* Load a keyring (a JWKS) for multi-signature verification. */
	if (keyring_file) {
		keyring = jwks_create_fromfile(keyring_file);
		if (keyring == NULL || jwks_error(keyring)) {
			fprintf(stderr, "ERR: Could not read keyring: %s\n",
				jwks_error_msg(keyring));
			return EXIT_FAILURE;
		}
		if (jwt_checker_setkeyring(checker, keyring, policy)) {
			// LCOV_EXCL_START - defensive: a keyring that read
			// cleanly but setkeyring then rejects
			fprintf(stderr, "ERR setting keyring: %s\n",
				jwt_checker_error_msg(checker));
			return EXIT_FAILURE;
			// LCOV_EXCL_STOP
		}
		if (!quiet)
			printf("\xF0\x9F\x94\x91 \033[0;92m[RING]\033[0m %s "
			       "(policy=%s)\n", keyring_file,
			       policy == JWT_VERIFY_POLICY_ALL ? "all" : "any");
	}

	/* Load JWK key */
	if (key_file) {
		jwk_set = jwks_create_fromfile(key_file);
                if (jwk_set == NULL || jwks_error(jwk_set)) {
                        fprintf(stderr, "ERR: Could not read JWK: %s\n",
                                jwks_error_msg(jwk_set));
                        return EXIT_FAILURE;
                }

                /* Get the first key */
                item = jwks_item_get(jwk_set, 0);
                if (item == NULL) {
                        fprintf(stderr, "ERR: No key found in %s\n", key_file);
                        return EXIT_FAILURE;
                }
                if (jwks_item_error(item)) {
                        fprintf(stderr, "ERR: Could not read JWK: %s\n",
                                jwks_item_error_msg(item));
                        return EXIT_FAILURE;
                }

		if (jwks_item_alg(item) == JWT_ALG_NONE &&
		    alg == JWT_ALG_NONE) {
			fprintf(stderr, "ERR: Key does not contain an \"alg\" "
				"attribute and no --algorithm given\n");
			return EXIT_FAILURE;
		}

                if (jwt_checker_setkey(checker, alg, item)) {
                        fprintf(stderr, "ERR Loading key: %s\n",
                                jwt_checker_error_msg(checker));
                        return EXIT_FAILURE;
                }
	}

	/* With neither a key nor a keyring the checker is keyless and, by
	 * default, rejects every token -- an unsigned ("alg":"none") one
	 * included (RFC 8725 §3.2). An explicit "-a none" is how the caller
	 * opts in to unsigned tokens, the one thing a keyless checker still
	 * accepts (it only decodes them). Wire it to the allowlist so the
	 * library applies the policy. */
	if (key_file == NULL && keyring_file == NULL && alg_given &&
	    alg == JWT_ALG_NONE) {
		const jwt_alg_t none_alg[] = { JWT_ALG_NONE };

		if (jwt_checker_setalgs(checker, none_alg, 1)) {
			// LCOV_EXCL_START - defensive: setalgs with a valid
			// algorithm on a fresh checker does not fail
			fprintf(stderr, "ERR allowing unsigned tokens: %s\n",
				jwt_checker_error_msg(checker));
			return EXIT_FAILURE;
			// LCOV_EXCL_STOP
		}
	}

	if (verbose && jwt_checker_setcb(checker, __jwt_wcb, NULL)) {
		// LCOV_EXCL_START - defensive: setting our own static callback
		// does not fail in practice
		fprintf(stderr, "ERR setting callback: %s\n",
			jwt_checker_error_msg(checker));
		return EXIT_FAILURE;
		// LCOV_EXCL_STOP
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
	} else if (keyring && !quiet) {
		/* Each signature's ring key (the one its kid names, or any
		 * compatible key) decides its algorithm. */
		printf("\033[0;92m[ALG]\033[0m per key (from keyring)");
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

	/* Show a token as signed whenever a key or keyring checks it. */
	signed_only = keyring != NULL || alg != JWT_ALG_NONE;

	if (!strcmp(argv[0], "-")) {
#ifdef _WIN32
		/* Read stdin as binary, so a 0x1A (Ctrl-Z) byte does not end
		 * the input and leave later lines unverified. */
		_setmode(_fileno(stdin), _O_BINARY);
#endif
		err = process_stdin(checker, signed_only, quiet);
	} else {
		for (oc = 0; oc < argc; oc++) {
			const char *token = argv[oc];
			err |= process_one(checker, signed_only, token, quiet);
		}
	}

	/* Not the number of failures: an exit status keeps only 8 bits.
	 * Return (not exit()) so the checker/key-set auto_t cleanups run. */
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

