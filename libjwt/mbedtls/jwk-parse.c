/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <jwt.h>

#include "jwt-private.h"

static const char not_implemented[] = "MBedTLS does not yet implement JWK";

JWT_NO_EXPORT
int mbedtls_process_eddsa(json_t *jwk, jwk_item_t *item)
{
	jwt_write_error(item, not_implemented);
	return -1;
}

JWT_NO_EXPORT
int mbedtls_process_rsa(json_t *jwk, jwk_item_t *item)
{
	jwt_write_error(item, not_implemented);
	return -1;
}

JWT_NO_EXPORT
int mbedtls_process_ec(json_t *jwk, jwk_item_t *item)
{
	jwt_write_error(item, not_implemented);
	return -1;
}

JWT_NO_EXPORT
void mbedtls_process_item_free(jwk_item_t *item)
{
	return;
}
