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

#include <jwt.h>

static void write_key_file(jwk_item_t *item)
{
	const char *pre, *name;
	int priv = item->is_private_key;;
	char file_name[BUFSIZ];
	FILE *fp;

	if (item->error || !item->pem)
		return;

	switch (item->kty) {
	case JWK_KEY_TYPE_EC:
		pre = "ec";
		name = item->curve;
		break;
	case JWK_KEY_TYPE_RSA:
		switch (item->alg) {
		case JWT_ALG_PS256:
		case JWT_ALG_PS384:
		case JWT_ALG_PS512:
			pre = "rsa-pss";
			name = "BITS";
			break;
		default:
			pre = "rsa";
			name = "BITS";
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

	if (item->kid == NULL) {
		snprintf(file_name, sizeof(file_name), "pems/%s_%s%s.pem",
			 pre, name, priv ? "" : "_pub");
	} else {
		snprintf(file_name, sizeof(file_name), "pems/%s_%s_%s%s.pem",
			 pre, name, item->kid, priv ? "" : "_pub");
	}

	fp = fopen(file_name, "wx");
	if (fp == NULL) {
		fprintf(stderr, "Could not overwrite '%s'\n", file_name);
		return;
	}

	fputs(item->pem, fp);
	fclose(fp);
}

int main(int argc, char **argv)
{
	jwk_set_t *jwk_set = NULL;
	jwk_item_t *item;
	char *json_str;
	char *file;
	FILE *fp;
	size_t len;
	int i;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <JWK(S) file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	file = argv[1];

	mkdir("pems", 0755);

	fp = fopen(file, "r");
	if (fp == NULL) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}

	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	json_str = malloc(len + 1);
	rewind(fp);
	len = fread(json_str, 1, len, fp);
	fclose(fp);
	json_str[len] = '\0';

	jwk_set = jwks_create(json_str);
	free(json_str);
	if (jwk_set == NULL) {
		perror("Failed to load JWKS");
		exit(EXIT_FAILURE);
	}

	for (i = 0; (item = jwks_item_get(jwk_set, i)); i++)
		write_key_file(item);

	exit(EXIT_SUCCESS);
}
