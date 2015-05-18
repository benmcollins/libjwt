/* Copyright (C) 2015 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <jwt.h>

/* Singly linked list of key and value pairs. */
struct jwt_grant {
	char *key;
	char *val;
	struct jwt_grant *next;
};

struct jwt {
	struct jwt_grant *grants;
};

int jwt_new(jwt_t **jwt)
{
	if (!jwt)
		return EINVAL;

	*jwt = malloc(sizeof(jwt_t));

	return *jwt ? 0 : ENOMEM;
}

void jwt_free(jwt_t *jwt)
{
	struct jwt_grant *jlist, *side;

	if (!jwt)
		return;

	jlist = jwt->grants;
	while (jlist) {
		side = jlist;
		jlist = side->next;

		free(side->key);
		free(side->val);
		free(side);
	}

	free(jwt);
}

const char *jwt_get_grant(jwt_t *jwt, const char *grant)
{
	struct jwt_grant *jlist;

	if (!grant || !strlen(grant))
		return NULL;

	for (jlist = jwt->grants; jlist; jlist = jlist->next) {
		if (!strcmp(jlist->key, grant))
			return jlist->val;
	}

	return NULL;
}

int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val)
{
	struct jwt_grant *jlist;

	/* Allow the value to be empty. */
	if (!grant || !strlen(grant) || !val)
		return EINVAL;

	if (jwt_get_grant(jwt, grant) != NULL)
		return EEXIST;

	jlist = malloc(sizeof(*jlist));
	if (!jlist)
		return ENOMEM;

	memset(jlist, 0, sizeof(*jlist));
	jlist->key = strdup(grant);
	jlist->val = strdup(val);
	jlist->next = jwt->grants;
	jwt->grants = jlist;

	return 0;
}

int jwt_del_grant(jwt_t *jwt, const char *grant)
{
	struct jwt_grant *jlist, *side = NULL;

	if (!grant || !strlen(grant))
		return EINVAL;

	for (jlist = jwt->grants; jlist; jlist = jlist->next) {
		if (!strcmp(jlist->key, grant))
			break;
		/* Track the last one. */
		side = jlist;
	}

	/* If it ain't here, then we ok wit dat. */
	if (!jlist)
		return 0;

	if (side)
		side->next = jlist->next;
	else
		jwt->grants = jlist->next;

	free(jlist->key);
	free(jlist->val);
	free(jlist);

	return 0;
}

void jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
	struct jwt_grant *jlist;

	putc('{', fp);

	if (pretty)
		putc('\n', fp);

	for (jlist = jwt->grants; jlist; jlist = jlist->next) {
		if (pretty)
			fputs("    ", fp);

		fprintf(fp, "\"%s\":\"%s\"", jlist->key, jlist->val);

		if (jlist->next)
			putc(',', fp);

		if (pretty)
			putc('\n', fp);
	}

	fputs("}\n", fp);
}
