/* Copyright (C) 2024-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include <jwt.h>

#include "jwt-util.h"

static char *out_dir;
static int retry;

/* Reject path components that could cause directory traversal */
static int is_safe_filename_part(const char *s)
{
	if (s == NULL || s[0] == '\0')
		return 0;
	if (strstr(s, ".."))
		return 0;
	if (strchr(s, '/') || strchr(s, '\\'))
		return 0;
	return 1;
}

/* A human-readable tag for one key in a file: the input file and the key's
 * position in it, plus its "kid" when it has one, so every per-key message
 * names which key it is about. */
static void key_label(char *buf, size_t len, const char *file, int idx,
		      const jwk_item_t *item)
{
	const char *kid = jwks_item_kid(item);

	if (kid != NULL)
		snprintf(buf, len, "%s: key %d (kid \"%s\")", file, idx, kid);
	else
		snprintf(buf, len, "%s: key %d", file, idx);
}

/* Write one key to its own file. Returns 0 on success, 1 if the key was not
 * written (it did not load, was skipped, or its file could not be created or
 * fully written) with a message naming the file and the key. */
static int write_key_file(const jwk_item_t *item, const char *file, int idx)
{
	const char *pre, *name, *pem, *reason = "write failed";
	int priv = jwks_item_is_private(item);
	char file_name[BUFSIZ];
	char label[BUFSIZ];
	char *ext = ".pem";
	char bits[8];
	int werr = 0;
	FILE *fp;
	int i;

	key_label(label, sizeof(label), file, idx, item);

	/* A key the backend could not load (e.g. an ML-DSA key under a backend
	 * without ML-DSA, or a malformed key) carries its own reason. */
	if (jwks_item_error(item)) {
		fprintf(stderr, "%s: %s\n", label, jwks_item_error_msg(item));
		return 1;
	}

	switch (jwks_item_kty(item)) {
	case JWK_KEY_TYPE_OCT:
		pre = "oct";
		ext = ".bin";
		snprintf(bits, sizeof(bits), "%d", jwks_item_key_bits(item));
		name = bits;
		break;
	case JWK_KEY_TYPE_EC:
		pre = "ec";
		name = jwks_item_curve(item);
		break;
	case JWK_KEY_TYPE_RSA:
		snprintf(bits, sizeof(bits), "%d", jwks_item_key_bits(item));
		name = bits;
		switch (jwks_item_alg(item)) {
		case JWT_ALG_PS256:
		case JWT_ALG_PS384:
		case JWT_ALG_PS512:
			pre = "rsa_pss";
			break;
		default:
			pre = "rsa";
		}
		break;
	case JWK_KEY_TYPE_OKP:
		pre = "eddsa";
		name = "ED25519";
		break;
#ifdef LIBJWT_HAVE_ML_DSA
	case JWK_KEY_TYPE_AKP:
		pre = "mldsa";
		switch (jwks_item_alg(item)) {
		case JWT_ALG_ML_DSA_44:
			name = "44";
			break;
		case JWT_ALG_ML_DSA_65:
			name = "65";
			break;
		case JWT_ALG_ML_DSA_87:
			name = "87";
			break;
		default:
			name = "unknown";
		}
		break;
#endif
	default:
		// LCOV_EXCL_START - a key that loaded (no item error, checked
		// above) always has a kty this switch handles.
		fprintf(stderr, "%s: unsupported key type\n", label);
		return 1;
		// LCOV_EXCL_STOP
	}

	if (!is_safe_filename_part(name)) {
		// LCOV_EXCL_START - name is the key type, curve or bit length,
		// which never carries a path separator or "..".
		fprintf(stderr, "%s: unsafe key name \"%s\"\n", label,
			name ? name : "(null)");
		return 1;
		// LCOV_EXCL_STOP
	}

	{
		const char *kid = jwks_item_kid(item);
		char *tp = NULL;
		const char *id = kid;

		/* Name files by a stable per-key id: the "kid" if present, else
		 * the deterministic RFC 7638 thumbprint. This disambiguates
		 * multiple keys of the same type that carry no "kid" (which would
		 * otherwise collide on the same file name). */
		if (id == NULL) {
			tp = jwks_item_thumbprint(item, JWK_THUMBPRINT_SHA256);
			id = tp;
		}

		if (id != NULL && !is_safe_filename_part(id)) {
			fprintf(stderr, "%s: unsafe key id, refusing to write\n",
				label);
			free(tp);
			return 1;
		}

		if (id == NULL)
			snprintf(file_name, sizeof(file_name), "%s/%s_%s%s%s",
				 out_dir, pre, name, priv ? "" : "_pub", ext);
		else
			snprintf(file_name, sizeof(file_name), "%s/%s_%s_%s%s%s",
				 out_dir, pre, name, id, priv ? "" : "_pub", ext);

		free(tp);
	}

	for (i = 0; i < 10; i++) {
		char *p;

		fp = fopen(file_name, "wx");

		if (fp || !retry || errno != EEXIST || i >= 9)
			break;

		p = file_name + strlen(file_name) - strlen(ext);
		if (i == 0) {
			*p++ = '-';
			*p++ = '1';
			snprintf(p, file_name + sizeof(file_name) - p, "%s", ext);
		} else {
			p = p - 1;
			*p = '1' + i;
		}
	}

	if (fp == NULL) {
		fprintf(stderr, "%s: cannot create %s: %s\n", label, file_name,
			strerror(errno));
		return 1;
	}

	if (jwks_item_kty(item) == JWK_KEY_TYPE_OCT) {
		const unsigned char *buf;
		size_t len;

		if (jwks_item_key_oct(item, &buf, &len) == 0) {
			fwrite(buf, 1, len, fp);
		} else {
			// LCOV_EXCL_START - a loaded oct key always has octets.
			reason = "no key material";
			werr = 1;
			// LCOV_EXCL_STOP
		}
	} else {
		/* PEM is a backend-dependent convenience and can be absent
		 * (e.g. MbedTLS has no PEM for an OKP/Ed25519 key): never pass
		 * a NULL to fputs(), which crashes on glibc. */
		pem = jwks_item_pem(item);
		if (pem == NULL) {
			reason = "no PEM available for this key "
				 "(the active backend cannot export it)";
			werr = 1;
		} else {
			fputs(pem, fp);
		}
	}

	/* A buffered write (small keys) is only flushed at fclose(), so a
	 * write error (a full disk, or an RLIMIT_FSIZE hit with SIGXFSZ
	 * ignored) can surface at the write itself (ferror) or at fclose().
	 * Both are always evaluated so neither becomes an untested branch. */
	werr |= (ferror(fp) != 0);
	werr |= (fclose(fp) != 0);

	if (werr) {
		fprintf(stderr, "%s: %s\n", label, reason);
		unlink(file_name);
		return 1;
	}

	return 0;
}

static int check_directory(const char *path)
{
	struct stat info;

	/* It must exist, be a directory (S_ISDIR(), not merely have the
	 * S_IFDIR bit, which a socket's mode also ANDs to), and be readable,
	 * writable and searchable so that key files can be created in it. */
	if (stat(path, &info) != 0 || !S_ISDIR(info.st_mode) ||
	    access(path, R_OK | W_OK | X_OK) != 0)
		return 0;

	return 1;
}


_Noreturn static void usage(const char *error, int exit_state)
{
	if (error)
		fprintf(stderr, "ERROR: %s\n\n", error);

	fprintf(stderr, "\
Usage: %s [OPTIONS] <FILE> [FILE]...\n\
\n\
Parse JSON Web Key format and write out individual key files\n\
\n\
  -h, --help            This help information\n\
  -r, --retry           Retry if output file exists\n\
  -d, --dir=DIR         Directory to write key files to\n\
\n\
This program will parse a JSON Web Key or Set and write out the individual\n\
files to DIR (by default '.'). Output directory must exist. You should make\n\
sure the permissions on the output directory are such that they cannot be\n\
accessed by others.\n\
\n\
JWK files must be listed after any options. A '-' will be interpreted as\n\
stdin.\n\
\n\
All RSA key types will be written as plain RSA keys, including RSASSA-PSS\n\
keys, unless it has a PS256, PS384, or PS512 'alg' attribute.\n\
\n\
All keys are written in PKCS8 PEM format, except key type 'OCT', which is\n\
written as a binary file (.bin extension).\n\
\n\
By default, existing files will not be overwritten. If you use the --retry\n\
option, an attempt will be made to add -X to the file name, up to -9, in\n\
an attempt to create the file.\n\
\n\
Exit status is 0 only when every key was written. It is 1 if any input file\n\
could not be read or parsed or held no keys, or if any key was skipped, did\n\
not load, or could not be created or fully written. The keys that do convert\n\
are written whatever the status.\n", get_progname());

        exit(exit_state);
}

int main(int argc, char **argv)
{
	int i, oc, ret = EXIT_SUCCESS;

	char *optstr = "hd:r";
        struct option opttbl[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "dir",	required_argument,	NULL, 'd' },
		{ "retry",	no_argument,		NULL, 'r' },
		{ NULL, 0, 0, 0 },
        };

	while ((oc = getopt_long(argc, argv, optstr, opttbl, NULL)) != -1) {
		switch (oc) {
		case 'h':
			usage(NULL, EXIT_SUCCESS);

		case 'd':
			out_dir = optarg;
			break;

		case 'r':
			retry = 1;
			break;

		default: /* '?' */
			usage("Unknown option", EXIT_FAILURE);
			break;
		}
	}

	argc -= optind;
        argv += optind;

	if (argc == 0)
		usage("No files to read", EXIT_FAILURE);

	if (out_dir == NULL || out_dir[0] == '\0')
		out_dir = ".";

	/* The output directory has to be usable before anything is read. */
	if (!check_directory(out_dir)) {
		fprintf(stderr, "%s: not an existing writable directory\n",
			out_dir);
		return EXIT_FAILURE;
	}

	/* Load each file into its own set, so a file that fails to load never
	 * taints the next one's error, and every key can be named with the
	 * file it came from. */
	for (i = 0; i < argc; i++) {
		jwk_set_auto_t *jwk_set = NULL;
		const jwk_item_t *item;
		char *file = argv[i];
		int j;

		if (file[0] == '-' && file[1] == '\0') {
			file = "(stdin)";
			jwk_set = jwks_load_fromfp(NULL, stdin);
		} else {
			jwk_set = jwks_load_fromfile(NULL, file);
		}

		if (jwk_set == NULL) {
			// LCOV_EXCL_START - only on an allocation failure.
			fprintf(stderr, "Error reading %s: out of memory\n",
				file);
			ret = EXIT_FAILURE;
			continue;
			// LCOV_EXCL_STOP
		}

		if (jwks_error(jwk_set)) {
			fprintf(stderr, "Error reading %s: %s\n", file,
				jwks_error_msg(jwk_set));
			ret = EXIT_FAILURE;
			continue;
		}

		if (jwks_item_count(jwk_set) == 0) {
			fprintf(stderr, "%s: No keys found\n", file);
			ret = EXIT_FAILURE;
			continue;
		}

		for (j = 0; (item = jwks_item_get(jwk_set, j)); j++) {
			if (write_key_file(item, file, j))
				ret = EXIT_FAILURE;
		}

		/* jwk_set is freed by its jwk_set_auto_t cleanup at the end of
		 * each iteration (so exit() is avoided; see #364). */
	}

	return ret;
}
