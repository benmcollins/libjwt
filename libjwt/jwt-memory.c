/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <jwt.h>

#include "jwt-private.h"

static jwt_malloc_t pfn_malloc;
static jwt_free_t pfn_free;

void *jwt_malloc(size_t size)
{
	if (pfn_malloc)
		return pfn_malloc(size);

	return malloc(size);
}

int jwt_set_alloc(jwt_malloc_t pmalloc, jwt_free_t pfree)
{
	/* Set allocator functions for LibJWT. */
	pfn_malloc = pmalloc;
	pfn_free = pfree;

	/* Set same allocator functions for Jansson. */
	json_set_alloc_funcs(jwt_malloc, __jwt_freemem);

	return 0;
}

void jwt_get_alloc(jwt_malloc_t *pmalloc, jwt_free_t *pfree)
{
	if (pmalloc)
		*pmalloc = pfn_malloc;

	if (pfree)
		*pfree = pfn_free;
}

/* Should call the macros instead */
void __jwt_freemem(void *ptr)
{
	if (pfn_free)
		pfn_free(ptr);
	else
		free(ptr);
}

/* A time-safe strcmp function */
int jwt_strcmp(const char *str1, const char *str2)
{
	/* Get the LONGEST length */
	int len1 = strlen(str1);
	int len2 = strlen(str2);
	int len_max = len1 >= len2 ? len1 : len2;

	int i, ret = 0;

	/* Iterate the entire longest string no matter what. Only testing
	 * the shortest string would still allow attacks for
	 * "a" == "aKJSDHkjashaaHJASJ", adding a character each time one
	 * is found. */
	for (i = 0; i < len_max; i++) {
		char c1, c2;

		c1 = (i < len1) ? str1[i] : 0;
		c2 = (i < len2) ? str2[i] : 0;

		ret |= c1 ^ c2;
	}

	/* Don't forget to check length */
	ret |= len1 ^ len2;

	return ret;
}
