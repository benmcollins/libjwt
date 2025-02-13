/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
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

static void write_key_file(const jwk_item_t *item)
{
	const char *pre, *name;
	int priv = jwks_item_is_private(item);
	char file_name[BUFSIZ];
	char *ext = ".pem";
	char bits[8];
	FILE *fp;
	int i;

	if (jwks_item_error(item))
		return;

	switch (jwks_item_kty(item)) {
	case JWK_KEY_TYPE_OCT:
		pre = "oct";
		ext = ".bin";
		sprintf(bits, "%d", jwks_item_key_bits(item));
		name = bits;
		break;
	case JWK_KEY_TYPE_EC:
		pre = "ec";
		name = jwks_item_curve(item);
		break;
	case JWK_KEY_TYPE_RSA:
		sprintf(bits, "%d", jwks_item_key_bits(item));
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
	default:
		fprintf(stderr, "Unknown kty\n");
		return;
	}

	if (jwks_item_kid(item) == NULL) {
		snprintf(file_name, sizeof(file_name), "%s/%s_%s%s%s",
			 out_dir, pre, name, priv ? "" : "_pub", ext);
	} else {
		snprintf(file_name, sizeof(file_name), "%s/%s_%s_%s%s%s",
			 out_dir, pre, name, jwks_item_kid(item),
			 priv ? "" : "_pub", ext);
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
			strcpy(p, ext);
		} else {
			p = p - 1;
			*p = '1' + i;
		}
	}

	if (fp == NULL) {
		perror(file_name);
		return;
	}

	if (jwks_item_kty(item) == JWK_KEY_TYPE_OCT) {
		const unsigned char *buf;
		size_t len;

		jwks_item_key_oct(item, &buf, &len);
		fwrite(buf, 1, len, fp);
	} else {
		fputs(jwks_item_pem(item), fp);
	}

	fclose(fp);
}

static int check_directory(const char *path)
{
	struct stat info;

	if (stat(path, &info) != 0)
		return 0;

	if (!(info.st_mode & S_IFDIR))
		return 0;

	if (access(path, R_OK | X_OK) != 0)
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
an attempt to create the file.\n", get_progname());

        exit(exit_state);
}

int main(int argc, char **argv)
{
	jwk_set_t *jwk_set = NULL;
	const jwk_item_t *item;
	int i, oc;

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

	if (!check_directory(out_dir)) {
		fprintf(stderr, "%s: doesn't exist or no access\n",
			out_dir);
	}

	jwk_set = jwks_create(NULL);
	if (jwk_set == NULL) {
		perror("Failed to create JWKS");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < argc; i++) {
		char *file = argv[i];

		if (file[0] == '-' && file[1] == '\0')
			jwks_load_fromfp(jwk_set, stdin);
		else
			jwks_load_fromfile(jwk_set, file);

		if (jwks_error(jwk_set)) {
			fprintf(stderr, "Error reading %s: %s\n", file,
				jwks_error_msg(jwk_set));
		}
	}

	for (i = 0; (item = jwks_item_get(jwk_set, i)); i++)
		write_key_file(item);

	exit(EXIT_SUCCESS);
}
