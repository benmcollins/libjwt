/* Copyright (C) 2019 Thorsten Alteholz <debian@alteholz.de>
   Copyright (C) 2024 Ben Collins <bcollins@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string.h>

#include <b64/cencode.h>
#include <b64/cdecode.h>

int jwt_Base64encode(char *coded_dst, const char *plain_src, int len_plain_src)
{
	base64_encodestate state;
	int count, i, len;
	char *rp = coded_dst, *wp = coded_dst;

	base64_init_encodestate(&state);
	count = base64_encode_block(plain_src, len_plain_src, coded_dst, &state);
	count += base64_encode_blockend(coded_dst + count, &state);

	/*
	 * the b64 library might insert \n after some chars,
	 * these must be removed again
	 * (at least in order to pass the tests)
	 */
	len = count;
	for (i = 0; i < len; i++) {
		if (*rp != '\n')
			*wp++ = *rp;
		else
			count--;
		rp++;
	}
	coded_dst[count] = 0;

	return count;
}

int jwt_Base64decode(char *plain_dst, const char *coded_src)
{
	base64_decodestate state;
	int count = 0;

	base64_init_decodestate(&state);
	count = base64_decode_block(coded_src, strlen(coded_src), plain_dst, &state);

	return count;
}
