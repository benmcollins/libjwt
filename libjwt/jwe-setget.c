/* Copyright (C) 2015-2026 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <jwt.h>

#include "jwt-private.h"

/* @rfc{7518,4.1} JWE key management ("alg") <-> string. */
const char *jwe_alg_str(jwe_key_alg_t alg)
{
	switch (alg) {
	case JWE_ALG_DIR:
		return "dir";
	case JWE_ALG_A128KW:
		return "A128KW";
	case JWE_ALG_A192KW:
		return "A192KW";
	case JWE_ALG_A256KW:
		return "A256KW";
	case JWE_ALG_RSA_OAEP:
		return "RSA-OAEP";
	case JWE_ALG_RSA_OAEP_256:
		return "RSA-OAEP-256";
	case JWE_ALG_ECDH_ES:
		return "ECDH-ES";
	case JWE_ALG_ECDH_ES_A128KW:
		return "ECDH-ES+A128KW";
	case JWE_ALG_ECDH_ES_A192KW:
		return "ECDH-ES+A192KW";
	case JWE_ALG_ECDH_ES_A256KW:
		return "ECDH-ES+A256KW";
	default:
		return NULL;
	}
}

jwe_key_alg_t jwe_str_alg(const char *alg)
{
	if (alg == NULL)
		return JWE_ALG_INVAL;

	if (!strcmp(alg, "dir"))
		return JWE_ALG_DIR;
	else if (!strcmp(alg, "A128KW"))
		return JWE_ALG_A128KW;
	else if (!strcmp(alg, "A192KW"))
		return JWE_ALG_A192KW;
	else if (!strcmp(alg, "A256KW"))
		return JWE_ALG_A256KW;
	else if (!strcmp(alg, "RSA-OAEP"))
		return JWE_ALG_RSA_OAEP;
	else if (!strcmp(alg, "RSA-OAEP-256"))
		return JWE_ALG_RSA_OAEP_256;
	else if (!strcmp(alg, "ECDH-ES"))
		return JWE_ALG_ECDH_ES;
	else if (!strcmp(alg, "ECDH-ES+A128KW"))
		return JWE_ALG_ECDH_ES_A128KW;
	else if (!strcmp(alg, "ECDH-ES+A192KW"))
		return JWE_ALG_ECDH_ES_A192KW;
	else if (!strcmp(alg, "ECDH-ES+A256KW"))
		return JWE_ALG_ECDH_ES_A256KW;

	return JWE_ALG_INVAL;
}

/* @rfc{7518,5.1} JWE content encryption ("enc") <-> string. */
const char *jwe_enc_str(jwe_enc_t enc)
{
	switch (enc) {
	case JWE_ENC_A128GCM:
		return "A128GCM";
	case JWE_ENC_A192GCM:
		return "A192GCM";
	case JWE_ENC_A256GCM:
		return "A256GCM";
	case JWE_ENC_A128CBC_HS256:
		return "A128CBC-HS256";
	case JWE_ENC_A192CBC_HS384:
		return "A192CBC-HS384";
	case JWE_ENC_A256CBC_HS512:
		return "A256CBC-HS512";
	default:
		return NULL;
	}
}

jwe_enc_t jwe_str_enc(const char *enc)
{
	if (enc == NULL)
		return JWE_ENC_INVAL;

	if (!strcmp(enc, "A128GCM"))
		return JWE_ENC_A128GCM;
	else if (!strcmp(enc, "A192GCM"))
		return JWE_ENC_A192GCM;
	else if (!strcmp(enc, "A256GCM"))
		return JWE_ENC_A256GCM;
	else if (!strcmp(enc, "A128CBC-HS256"))
		return JWE_ENC_A128CBC_HS256;
	else if (!strcmp(enc, "A192CBC-HS384"))
		return JWE_ENC_A192CBC_HS384;
	else if (!strcmp(enc, "A256CBC-HS512"))
		return JWE_ENC_A256CBC_HS512;

	return JWE_ENC_INVAL;
}
