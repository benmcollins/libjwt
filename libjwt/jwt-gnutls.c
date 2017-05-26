/* Copyright (C) 2017 Nicolas Mora <mail@babelouest.org>
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
   License along with the JWT Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <jansson.h>

#include <jwt.h>

#include "jwt-private.h"
#include "b64.h"
#include "config.h"

int _gnutls_encode_ber_rs_raw(gnutls_datum_t * sig_value, const gnutls_datum_t * r, const gnutls_datum_t * s);
int _gnutls_decode_ber_rs_raw(const gnutls_datum_t * sig_value, gnutls_datum_t * r, gnutls_datum_t * s);

/**
 * libjwt encryption/decryption function definitions
 */
int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len, const char *str) {
	int alg;
	
	switch (jwt->alg) {
	case JWT_ALG_HS256:
		alg = GNUTLS_DIG_SHA256;
		break;
	case JWT_ALG_HS384:
		alg = GNUTLS_DIG_SHA384;
		break;
	case JWT_ALG_HS512:
		alg = GNUTLS_DIG_SHA512;
		break;
	default:
		return EINVAL;
	}
	
	*len = gnutls_hmac_get_len(alg);
	(*out) = malloc(*len);
	if (*out == NULL) {
		return ENOMEM;
	}
	
	return !gnutls_hmac_fast(alg, jwt->key, jwt->key_len, str, strlen(str), (*out))?0:EINVAL;
}

int jwt_verify_sha_hmac(jwt_t *jwt, const char *head, const char *sig) {
	char * sig_check, * buf = NULL;
	unsigned int len;
	int res, buf_len;
	base64_encodestate state;
	
	if (!jwt_sign_sha_hmac(jwt, &sig_check, &len, head)) {
		buf = alloca(len * 2);
		jwt_base64_init_encodestate(&state);
		buf_len = jwt_base64_encode_block(sig_check, len, buf, &state);
		buf_len += jwt_base64_encode_blockend(buf + buf_len, &state);
		buf[buf_len] = '\0';

		jwt_base64uri_encode(buf);
		res = !strcmp(sig, buf)?0:EINVAL;
		free(sig_check);
	} else {
		res = EINVAL;
	}
	return res;
}

int jwt_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len, const char *str) {
	gnutls_x509_privkey_t key;
	gnutls_privkey_t privkey;
	gnutls_datum_t key_dat = {(void *) jwt->key, jwt->key_len}, body_dat = {(void*) str, strlen(str)}, sig_dat;
	int res = 0, pk_alg;
	int alg;
	
	switch (jwt->alg) {
	case JWT_ALG_RS256:
		alg = GNUTLS_DIG_SHA256;
		pk_alg = GNUTLS_PK_RSA;
		break;
	case JWT_ALG_RS384:
		alg = GNUTLS_DIG_SHA384;
		pk_alg = GNUTLS_PK_RSA;
		break;
	case JWT_ALG_RS512:
		alg = GNUTLS_DIG_SHA512;
		pk_alg = GNUTLS_PK_RSA;
		break;
	case JWT_ALG_ES256:
		alg = GNUTLS_DIG_SHA256;
		pk_alg = GNUTLS_PK_EC;
		break;
	case JWT_ALG_ES384:
		alg = GNUTLS_DIG_SHA384;
		pk_alg = GNUTLS_PK_EC;
		break;
	case JWT_ALG_ES512:
		alg = GNUTLS_DIG_SHA512;
		pk_alg = GNUTLS_PK_EC;
		break;
	default:
		return EINVAL;
	}
	
	/* Initialize signature process data */
	if (gnutls_x509_privkey_init(&key)) {
		res = ENOMEM;
		goto CLEAN_NONE;
	}
	
	if (gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM)) {
		res = EINVAL;
		goto CLEAN_KEY;
	}
	
	if (gnutls_privkey_init(&privkey)) {
		res = ENOMEM;
		goto CLEAN_KEY;
	}
	
	if (gnutls_privkey_import_x509(privkey, key, 0)) {
		res = EINVAL;
		goto CLEAN_PRIVKEY;
	}
	
	if (pk_alg != gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
		res = EINVAL;
		goto CLEAN_PRIVKEY;
	}
	
	/* Sign data */
	if (gnutls_privkey_sign_data(privkey, alg, 0, &body_dat, &sig_dat)) {
		res = EINVAL;
		goto CLEAN_PRIVKEY;
	}
	
  if (pk_alg == GNUTLS_PK_RSA) {
    (*out) = malloc(sig_dat.size);
    if (*out == NULL) {
      res = ENOMEM;
      goto CLEAN_PRIVKEY;
    }
    
    /* copy signature to out */
    memcpy((*out), sig_dat.data, sig_dat.size);
    *len = sig_dat.size;
  } else {
    gnutls_datum_t r, s;
    int r_padding = 0, s_padding = 0;
		size_t out_size;
		
    if ((res = _gnutls_decode_ber_rs_raw(&sig_dat, &r, &s))) {
      res = EINVAL;
      goto CLEAN_PRIVKEY;
    }
    
    // Check r and s size
    if (jwt->alg == JWT_ALG_ES256) {
			if (r.size > 32) {
				r_padding = r.size - 32;
			}
			if (s.size > 32) {
				s_padding = s.size - 32;
			}
			out_size = 64;
    }
    if (jwt->alg == JWT_ALG_ES384) {
			if (r.size > 48) {
				r_padding = r.size - 48;
			}
			if (s.size > 48) {
				s_padding = s.size - 48;
			}
			out_size = 96;
    }
    if (jwt->alg == JWT_ALG_ES512) {
			if (r.size > 66) {
				r_padding = r.size - 66;
			}
			if (s.size > 66) {
				s_padding = s.size - 66;
			}
			out_size = 132;
    }
    
    (*out) = malloc(out_size);
    if (*out == NULL) {
      res = ENOMEM;
      goto CLEAN_PRIVKEY;
    }
		memset(*out, 0, out_size);
    
    memcpy((*out), r.data + r_padding, (r.size - r_padding));
    memcpy((*out) + (r.size - r_padding), s.data + s_padding, (s.size - s_padding));
    *len = (r.size - r_padding) + (s.size - s_padding);
    gnutls_free(r.data);
    gnutls_free(s.data);
  }

	/* Clean and exit */
	gnutls_free(sig_dat.data);

CLEAN_PRIVKEY:
	gnutls_privkey_deinit(privkey);

CLEAN_KEY:
	gnutls_x509_privkey_deinit(key);

CLEAN_NONE:
	return res;
}

int jwt_verify_sha_pem(jwt_t *jwt, const char *head, const char *sig_b64) {
	char * sig;
	gnutls_datum_t sig_dat, cert_dat = {(void*)jwt->key, jwt->key_len}, data = {(void*)head, strlen(head)}, r, s;
	gnutls_pubkey_t pubkey;
	int alg, res, sig_len;
	
	switch (jwt->alg) {
	case JWT_ALG_RS256:
		alg = GNUTLS_DIG_SHA256;
		break;
	case JWT_ALG_RS384:
		alg = GNUTLS_DIG_SHA384;
		break;
	case JWT_ALG_RS512:
		alg = GNUTLS_DIG_SHA512;
		break;
	case JWT_ALG_ES256:
		alg = GNUTLS_DIG_SHA256;
		break;
	case JWT_ALG_ES384:
		alg = GNUTLS_DIG_SHA384;
		break;
	case JWT_ALG_ES512:
		alg = GNUTLS_DIG_SHA512;
		break;
	default:
		return EINVAL;
	}
  
  sig = jwt_b64_decode(sig_b64, &sig_len);

  if (sig == NULL) {
		return EINVAL;
  }
  
  sig_dat.size = sig_len;
  sig_dat.data = (void*)sig;
	
	if (gnutls_pubkey_init(&pubkey)) {
		res = EINVAL;
    goto CLEAN_SIG;
	}
	if (!gnutls_pubkey_import(pubkey, &cert_dat, GNUTLS_X509_FMT_PEM)) {
    // Rebuild signature using r and s extracted from sig when jwt->alg is ESxxx
    if (jwt->alg == JWT_ALG_ES256 && sig_len == 64) {
      r.size = 32;
      r.data = sig_dat.data;
      s.size = 32;
      s.data = sig_dat.data + 32;
      
      if (_gnutls_encode_ber_rs_raw(&sig_dat, &r, &s)) {
        res = EINVAL;
        gnutls_free(sig_dat.data);
        goto CLEAN_PUBKEY;
      }
      res = !gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat)?0:EINVAL;
      gnutls_free(sig_dat.data);
    } else if (jwt->alg == JWT_ALG_ES384 && sig_len == 96) {
      r.size = 48;
      r.data = sig_dat.data;
      s.size = 48;
      s.data = sig_dat.data + 48;
      
      if (_gnutls_encode_ber_rs_raw(&sig_dat, &r, &s)) {
        res = EINVAL;
        gnutls_free(sig_dat.data);
        goto CLEAN_PUBKEY;
      }
      res = !gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat)?0:EINVAL;
      gnutls_free(sig_dat.data);
    } else if (jwt->alg == JWT_ALG_ES512 && sig_len == 132) {
      r.size = 66;
      r.data = sig_dat.data;
      s.size = 66;
      s.data = sig_dat.data + 66;
      
      if (_gnutls_encode_ber_rs_raw(&sig_dat, &r, &s)) {
        res = EINVAL;
        gnutls_free(sig_dat.data);
        goto CLEAN_PUBKEY;
      }
      res = !gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat)?0:EINVAL;
      gnutls_free(sig_dat.data);
    } else {
      // Use good old RSA signature verification
      res = !gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat)?0:EINVAL;
    }
	} else {
		res = EINVAL;
	}
CLEAN_PUBKEY:
	gnutls_pubkey_deinit(pubkey);
	
CLEAN_SIG:
	free(sig);
	return res;
}
