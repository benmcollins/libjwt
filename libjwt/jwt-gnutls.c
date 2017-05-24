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
      alg = GNUTLS_DIG_NULL;
      break;
  }
  
  if (alg != GNUTLS_DIG_NULL) {
    *len = gnutls_hmac_get_len(alg);
    (*out) = malloc(*len);
    if (*out != NULL) {
      if (!gnutls_hmac_fast(alg, jwt->key, jwt->key_len, str, strlen(str), (*out))) {
        return 0;
      } else {
        return EINVAL;
      }
    } else {
      return ENOMEM;
    }
  } else {
    return EINVAL;
  }
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
  int res, pk_alg;
  int alg;
  gnutls_x509_crt_fmt_t format;
  
  switch (jwt->alg) {
    case JWT_ALG_RS256:
      alg = GNUTLS_DIG_SHA256;
      pk_alg = GNUTLS_PK_RSA;
      format = GNUTLS_X509_FMT_PEM;
      break;
    case JWT_ALG_RS384:
      alg = GNUTLS_DIG_SHA384;
      pk_alg = GNUTLS_PK_RSA;
      format = GNUTLS_X509_FMT_PEM;
      break;
    case JWT_ALG_RS512:
      alg = GNUTLS_DIG_SHA512;
      pk_alg = GNUTLS_PK_RSA;
      format = GNUTLS_X509_FMT_PEM;
      break;
    case JWT_ALG_ES256:
      alg = GNUTLS_DIG_SHA256;
      pk_alg = GNUTLS_PK_EC;
      format = GNUTLS_X509_FMT_PEM;
      break;
    case JWT_ALG_ES384:
      alg = GNUTLS_DIG_SHA384;
      pk_alg = GNUTLS_PK_EC;
      format = GNUTLS_X509_FMT_PEM;
      break;
    case JWT_ALG_ES512:
      alg = GNUTLS_DIG_SHA512;
      pk_alg = GNUTLS_PK_EC;
      format = GNUTLS_X509_FMT_PEM;
      break;
    default:
      alg = GNUTLS_DIG_NULL;
      pk_alg = GNUTLS_PK_UNKNOWN;
      format = GNUTLS_X509_FMT_PEM;
      break;
  }
  
  if (alg != GNUTLS_DIG_NULL) {
    if (!gnutls_x509_privkey_init(&key)) {
      if (!gnutls_x509_privkey_import(key, &key_dat, format)) {
        if (!gnutls_privkey_init(&privkey)) {
          if (!gnutls_privkey_import_x509(privkey, key, 0)) {
            if (pk_alg == gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
              if (!gnutls_privkey_sign_data(privkey, alg, 0, &body_dat, &sig_dat)) {
                (*out) = malloc(sig_dat.size);
                if (*out != NULL) {
                  memcpy((*out), sig_dat.data, sig_dat.size);
                  *len = sig_dat.size;
                  res = 0;
                } else {
                  res = ENOMEM;
                }
              } else {
                res = EINVAL;
              }
            } else {
              res = EINVAL;
            }
          } else {
            res = EINVAL;
          }
        } else {
          res = ENOMEM;
        }
        gnutls_privkey_deinit(privkey);
      } else {
        res = EINVAL;
      }
    } else {
      res = ENOMEM;
    }
    gnutls_x509_privkey_deinit(key);
    return res;
  } else {
    return EINVAL;
  }
}

int jwt_verify_sha_pem(jwt_t *jwt, const char *head, const char *sig_b64) {
  int sig_len;
  char * sig = jwt_b64_decode(sig_b64, &sig_len);
  gnutls_datum_t sig_dat = {(void*)sig, sig_len}, cert_dat = {(void*)jwt->key, jwt->key_len}, data = {(void*)head, strlen(head)};
  gnutls_pubkey_t pubkey;
  int alg;
  int res;
  
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
      alg = GNUTLS_DIG_NULL;
      break;
  }
  
  if (alg != GNUTLS_DIG_NULL) {
    if (!gnutls_pubkey_init(&pubkey)) {
      if (!gnutls_pubkey_import(pubkey, &cert_dat, GNUTLS_X509_FMT_PEM)) {
        res = !gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat)?0:EINVAL;
      } else {
        res = EINVAL;
      }
    } else {
      res = EINVAL;
    }
    gnutls_pubkey_deinit(pubkey);
  } else {
    res = EINVAL;
  }
  
  free(sig);
  return res;
}
