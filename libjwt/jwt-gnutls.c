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

static void base64uri_encode(char *str) {
  int len = strlen(str);
  int i, t;

  for (i = t = 0; i < len; i++) {
    switch (str[i]) {
    case '+':
      str[t++] = '-';
      break;
    case '/':
      str[t++] = '_';
      break;
    case '=':
      break;
    default:
      str[t++] = str[i];
    }
  }

  str[t] = '\0';
}

char * base64uri_decode(char * b64) {
  int i, z;
  size_t len;
  char * new = malloc(strlen(b64)+4);
  
  if (b64 != NULL) {
    len = strlen(b64);
    for (i = 0; i < len; i++) {
      switch (b64[i]) {
      case '-':
        new[i] = '+';
        break;
      case '_':
        new[i] = '/';
        break;
      default:
        new[i] = b64[i];
      }
    }
    z = 4 - (i % 4);
    if (z < 4) {
      while (z--)
        new[i++] = '=';
    }
    new[i] = '\0';
  }
  return new;
}

char * jwt_generate_signature_ec(jwt_t *jwt, const char * b64_header, const char * b64_payload) {
  char * b64_sig = NULL, * body_full;
  size_t body_full_len, b64_len;
  gnutls_x509_privkey_t key;
  gnutls_privkey_t privkey;
  gnutls_datum_t key_dat = {(void *) jwt->key, jwt->key_len}, body_dat, sig_dat;
  gnutls_digest_algorithm_t hash = GNUTLS_DIG_NULL;
  
  body_full_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
  body_full = malloc((body_full_len+1)*sizeof(char));
  if (body_full != NULL) {
    snprintf(body_full, (body_full_len + 1), "%s.%s", b64_header, b64_payload);
    body_dat.data = (void*)body_full;
    body_dat.size = strlen(body_full);
    if (jwt != NULL) {
      if (jwt->alg == JWT_ALG_ES256) {
        hash = GNUTLS_DIG_SHA256;
      } else if (jwt->alg == JWT_ALG_ES384) {
        hash = GNUTLS_DIG_SHA384;
      } else if (jwt->alg == JWT_ALG_ES512) {
        hash = GNUTLS_DIG_SHA512;
      }
      if (hash != GNUTLS_DIG_NULL) {
        if (!gnutls_x509_privkey_init(&key)) {
          if (!gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM)) {
            if (!gnutls_privkey_init(&privkey)) {
              if (!gnutls_privkey_import_x509(privkey, key, 0)) {
                if (GNUTLS_PK_EC == gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
                  if (!gnutls_privkey_sign_data(privkey, hash, 0, &body_dat, &sig_dat)) {
                    b64_sig = malloc(2*sig_dat.size*sizeof(char));
                    if (b64_sig != NULL) {
                      if (base64_encode((unsigned char *)sig_dat.data, sig_dat.size, (unsigned char *)b64_sig, &b64_len)) {
                        base64uri_encode(b64_sig);
                      } else {
                        free(b64_sig);
                        b64_sig = NULL;
                      }
                    }
                  }
                }
              }
            }
            gnutls_privkey_deinit(privkey);
          }
        }
        gnutls_x509_privkey_deinit(key);
      }
    }
  }
  free(body_full);
  return b64_sig;
}

char * jwt_generate_signature_rsa(jwt_t *jwt, const char * b64_header, const char * b64_payload) {
  char * b64_sig = NULL, * body_full;
  size_t body_full_len, b64_len;
  gnutls_x509_privkey_t key;
  gnutls_privkey_t privkey;
  gnutls_datum_t key_dat = {(void *) jwt->key, jwt->key_len}, body_dat, sig_dat;
  gnutls_digest_algorithm_t hash = GNUTLS_DIG_NULL;
  
  body_full_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
  body_full = malloc((body_full_len+1)*sizeof(char));
  if (body_full != NULL) {
    snprintf(body_full, (body_full_len + 1), "%s.%s", b64_header, b64_payload);
    body_dat.data = (void*)body_full;
    body_dat.size = strlen(body_full);
    if (jwt != NULL) {
      if (jwt->alg == JWT_ALG_RS256) {
        hash = GNUTLS_DIG_SHA256;
      } else if (jwt->alg == JWT_ALG_RS384) {
        hash = GNUTLS_DIG_SHA384;
      } else if (jwt->alg == JWT_ALG_RS512) {
        hash = GNUTLS_DIG_SHA512;
      }
      if (hash != GNUTLS_DIG_NULL) {
        if (!gnutls_x509_privkey_init(&key)) {
          if (!gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM)) {
            if (!gnutls_privkey_init(&privkey)) {
              if (!gnutls_privkey_import_x509(privkey, key, 0)) {
                if (GNUTLS_PK_RSA == gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
                  if (!gnutls_privkey_sign_data(privkey, hash, 0, &body_dat, &sig_dat)) {
                    b64_sig = malloc(2*sig_dat.size*sizeof(char));
                    if (b64_sig != NULL) {
                      if (base64_encode((unsigned char *)sig_dat.data, sig_dat.size, (unsigned char *)b64_sig, &b64_len)) {
                        base64uri_encode(b64_sig);
                      } else {
                        free(b64_sig);
                        b64_sig = NULL;
                      }
                    }
                  }
                }
              }
            }
            gnutls_privkey_deinit(privkey);
          }
        }
        gnutls_x509_privkey_deinit(key);
      }
    }
  }
  free(body_full);
  return b64_sig;
}

char * jwt_generate_signature(jwt_t *jwt, const int pretty, const char * encoded_header, const char * encoded_payload) {
  char * str_header = NULL, * str_payload = NULL, * b64_header = NULL, * b64_payload = NULL, * str_sig = NULL, * b64_sig = NULL, * tmp = NULL;
  size_t b64_header_len, b64_payload_len, b64_sig_len, tmp_s;
  int keep = 1;
  
  if (encoded_header == NULL) {
    str_header = dump_head(jwt, pretty);
    if (str_header != NULL) {
      b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
      if (b64_header != NULL) {
        if (base64_encode((unsigned char *)str_header, strlen(str_header), (unsigned char *)b64_header, &b64_header_len)) {
          base64uri_encode(b64_header);
        } else {
          keep = 0;
        }
      } else {
        keep = 0;
      }
    } else {
      keep = 0;
    }
    free(str_header);
  } else {
    b64_header = strdup(encoded_header);
    if (b64_header == NULL) {
      keep = 0;
    }
  }
  
  if (keep && jwt != NULL) {
    if (encoded_payload == NULL) {
      str_payload = json_dumps(jwt->grants, (pretty?JSON_INDENT(2):JSON_COMPACT) | JSON_SORT_KEYS);
      if (str_payload != NULL) {
        b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
        if (b64_payload != NULL) {
          if (base64_encode((unsigned char *)str_payload, strlen(str_payload), (unsigned char *)b64_payload, &b64_payload_len)) {
            base64uri_encode(b64_payload);
          } else {
            keep = 0;
          }
        } else {
          keep = 0;
        }
      } else {
        keep = 0;
      }
      free(str_payload);
    } else {
      b64_payload = strdup(encoded_payload);
      if (b64_payload == NULL) {
        keep = 0;
      }
    }
    if (keep) {
      if (jwt->alg == JWT_ALG_NONE) {
        b64_sig = strdup("");
        b64_sig_len = 0;
      } else if (jwt->alg == JWT_ALG_ES256) {
        b64_sig = jwt_generate_signature_ec(jwt, b64_header, b64_payload);
      } else if (jwt->alg == JWT_ALG_ES384) {
        b64_sig = jwt_generate_signature_ec(jwt, b64_header, b64_payload);
      } else if (jwt->alg == JWT_ALG_ES512) {
        b64_sig = jwt_generate_signature_ec(jwt, b64_header, b64_payload);
      } else if (jwt->alg == JWT_ALG_RS256) {
        b64_sig = jwt_generate_signature_rsa(jwt, b64_header, b64_payload);
      } else if (jwt->alg == JWT_ALG_RS384) {
        b64_sig = jwt_generate_signature_rsa(jwt, b64_header, b64_payload);
      } else if (jwt->alg == JWT_ALG_RS512) {
        b64_sig = jwt_generate_signature_rsa(jwt, b64_header, b64_payload);
      } else if (jwt->alg == JWT_ALG_HS256) {
        tmp_s = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
        tmp = malloc((tmp_s+1)*sizeof(char));
        if (tmp != NULL) {
          snprintf(tmp, (tmp_s+1), "%s.%s", b64_header, b64_payload);
          str_sig = malloc(gnutls_hmac_get_len(GNUTLS_DIG_SHA256)*sizeof(char));
          if (str_sig != NULL) {
            if (!gnutls_hmac_fast(GNUTLS_DIG_SHA256, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig)) {
              b64_sig = malloc(2*gnutls_hmac_get_len(GNUTLS_DIG_SHA256)*sizeof(char));
              if (b64_sig != NULL) {
                if (base64_encode((unsigned char *)str_sig, gnutls_hmac_get_len(GNUTLS_DIG_SHA256), (unsigned char *)b64_sig, &b64_sig_len)) {
                  base64uri_encode(b64_sig);
                }
              }
            }
          }
          free(str_sig);
        }
        free(tmp);
      } else if (jwt->alg == JWT_ALG_HS384) {
        tmp_s = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
        tmp = malloc((tmp_s+1)*sizeof(char));
        if (tmp != NULL) {
          snprintf(tmp, (tmp_s+1), "%s.%s", b64_header, b64_payload);
          str_sig = malloc(gnutls_hmac_get_len(GNUTLS_DIG_SHA384)*sizeof(char));
          if (str_sig != NULL) {
            if (!gnutls_hmac_fast(GNUTLS_DIG_SHA384, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig)) {
              b64_sig = malloc(2*gnutls_hmac_get_len(GNUTLS_DIG_SHA384)*sizeof(char));
              if (b64_sig != NULL) {
                if (base64_encode((unsigned char *)str_sig, gnutls_hmac_get_len(GNUTLS_DIG_SHA384), (unsigned char *)b64_sig, &b64_sig_len)) {
                  base64uri_encode(b64_sig);
                }
              }
            }
          }
          free(str_sig);
        }
        free(tmp);
      } else if (jwt->alg == JWT_ALG_HS512) {
        tmp_s = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
        tmp = malloc((tmp_s+1)*sizeof(char));
        if (tmp != NULL) {
          snprintf(tmp, (tmp_s+1), "%s.%s", b64_header, b64_payload);
          str_sig = malloc(gnutls_hmac_get_len(GNUTLS_DIG_SHA512)*sizeof(char));
          if (str_sig != NULL) {
            if (!gnutls_hmac_fast(GNUTLS_DIG_SHA512, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig)) {
              b64_sig = malloc(2*gnutls_hmac_get_len(GNUTLS_DIG_SHA512)*sizeof(char));
              if (b64_sig != NULL) {
                if (base64_encode((unsigned char *)str_sig, gnutls_hmac_get_len(GNUTLS_DIG_SHA512), (unsigned char *)b64_sig, &b64_sig_len)) {
                  base64uri_encode(b64_sig);
                }
              }
            }
          }
          free(str_sig);
        }
        free(tmp);
      }
    }
  }
  
  free(b64_header);
  free(b64_payload);
  return b64_sig;
}

static int jwt_verify_sha_pem(jwt_t *jwt, const gnutls_digest_algorithm_t alg, const char *head, const char *sig_b64) {
  char * tmp = NULL, * sig_b64_dup, * sig_dec, * str_header, * b64_header, * str_payload, * b64_payload;
  size_t tmp_len = 0, sig_len, b64_payload_len, b64_header_len;
  int res = EINVAL;
  gnutls_pubkey_t pubkey;
  gnutls_datum_t cert_dat, data, sig;
  
  if (jwt != NULL && sig_b64 != NULL) {
    cert_dat.data = (void *) jwt->key;
    cert_dat.size = jwt->key_len;
    sig_b64_dup = strdup(sig_b64);
    if (sig_b64_dup != NULL) {
      sig_b64_dup = base64uri_decode(sig_b64_dup);
      sig_dec = malloc(strlen(sig_b64_dup));
      if (sig_dec != NULL) {
        base64_decode((unsigned char *)sig_b64_dup, strlen(sig_b64_dup), (unsigned char *)sig_dec, &sig_len);
        sig.data = (void*)sig_dec;
        sig.size = sig_len;
        
        if (head != NULL) {
          tmp = strdup(head);
          if (tmp != NULL) {
            tmp_len = strlen(tmp);
          } else {
            res = ENOMEM;
          }
        } else if (jwt != NULL) {
          str_header = dump_head(jwt, 0);
          if (str_header != NULL) {
            b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
            if (b64_header != NULL) {
              if (base64_encode((unsigned char *)str_header, strlen(str_header), (unsigned char *)b64_header, &b64_header_len)) {
                base64uri_encode(b64_header);
                str_payload = json_dumps(jwt->grants, JSON_COMPACT | JSON_SORT_KEYS);
                if (str_payload != NULL) {
                  b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
                  if (b64_payload != NULL) {
                    if (base64_encode((unsigned char *)str_payload, strlen(str_payload), (unsigned char *)b64_payload, &b64_payload_len)) {
                      base64uri_encode(b64_payload);
                      tmp_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
                      tmp = malloc((tmp_len + 1)*sizeof(char));
                      if (tmp != NULL) {
                        snprintf(tmp, (tmp_len + 1), "%s.%s", b64_header, b64_payload);
                      } else {
                        res = ENOMEM;
                      }
                    } else {
                      res = EINVAL;
                    }
                  } else {
                    res = ENOMEM;
                  }
                  free(b64_payload);
                } else {
                  res = EINVAL;
                }
                free(str_payload);
              } else {
                res = EINVAL;
              }
            } else {
              res = ENOMEM;
            }
            free(b64_header);
          } else {
            res = EINVAL;
          }
          free(str_header);
        } else {
          res = EINVAL;
        }
        if (tmp != NULL) {
          data.data = (void*)tmp;
          data.size = tmp_len;
          if (!gnutls_pubkey_init(&pubkey)) {
            if (!gnutls_pubkey_import(pubkey, &cert_dat, GNUTLS_X509_FMT_PEM)) {
              res = !gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig)?0:EINVAL;
            } else {
              res = EINVAL;
            }
          } else {
            res = EINVAL;
          }
          gnutls_pubkey_deinit(pubkey);
        }
        free(tmp);
      } else {
        res = ENOMEM;
      }
      free(sig_dec);
      free(sig_b64_dup);
    } else {
      res = ENOMEM;
    }
  } else {
    res = EINVAL;
  }
  return res;
}

static int jwt_verify_sha_hmac(jwt_t *jwt, const gnutls_digest_algorithm_t alg, const char *head, const char *sig_check) {
  char * tmp = NULL, * str_sig, * b64_sig, * str_header, * b64_header, * str_payload, * b64_payload;
  size_t  b64_sig_len, tmp_len, b64_payload_len, b64_header_len;
  int res = EINVAL;
  
  if (head != NULL) {
    tmp = strdup(head);
  } else if (jwt != NULL) {
    str_header = dump_head(jwt, 0);
    if (str_header != NULL) {
      b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
      if (b64_header != NULL) {
        if (base64_encode((unsigned char *)str_header, strlen(str_header), (unsigned char *)b64_header, &b64_header_len)) {
          base64uri_encode(b64_header);
          str_payload = json_dumps(jwt->grants, JSON_COMPACT | JSON_SORT_KEYS);
          if (str_payload != NULL) {
            b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
            if (b64_payload != NULL) {
              if (base64_encode((unsigned char *)str_payload, strlen(str_payload), (unsigned char *)b64_payload, &b64_payload_len)) {
                base64uri_encode(b64_payload);
                tmp_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
                tmp = malloc((tmp_len + 1)*sizeof(char));
                snprintf(tmp, (tmp_len + 1), "%s.%s", b64_header, b64_payload);
              } else {
                res = EINVAL;
              }
              free(b64_payload);
            } else {
              res = ENOMEM;
            }
            free(str_payload);
          } else {
            res = ENOMEM;
          }
        } else {
          res = EINVAL;
        }
        free(b64_header);
      } else {
        res = ENOMEM;
      }
      free(str_header);
    } else {
      res = ENOMEM;
    }
  } else {
    res = EINVAL;
  }
  
  if (tmp != NULL) {
    str_sig = malloc(gnutls_hmac_get_len(alg)*sizeof(char));
    if (str_sig != NULL) {
      if ((res = gnutls_hmac_fast(alg, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig)) == 0) {
        b64_sig = malloc(2*gnutls_hmac_get_len(alg)*sizeof(char));
        if (b64_sig != NULL) {
          if (base64_encode((unsigned char *)str_sig, gnutls_hmac_get_len(alg)*sizeof(char), (unsigned char *)b64_sig, &b64_sig_len)) {
            base64uri_encode(b64_sig);
            res = !strcmp(b64_sig, sig_check)?0:EINVAL;
          } else {
            res = EINVAL;
          }
          free(b64_sig);
        } else {
          res = ENOMEM;
        }
      } else {
        res = EINVAL;
      }
      free(str_sig);
    } else {
      res = ENOMEM;
    }
    free(tmp);
  } else {
    res = EINVAL;
  }
  return res;
}

/**
 * libjwt encryption/decryption function definitions
 */
int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len, const char *str) {
  gnutls_mac_algorithm_t alg;
  char * str_sig;
  base64_encodestate state;
  int sig_len;
  
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
    sig_len = gnutls_hmac_get_len(alg);
    str_sig = alloca(sig_len);
    if (str_sig != NULL) {
      if (!gnutls_hmac_fast(alg, jwt->key, jwt->key_len, str, strlen(alg), str_sig)) {
        (*out) = malloc(2*sig_len);
        if (*out != NULL) {
          jwt_base64_init_encodestate(&state);
          (*len) = jwt_base64_encode_block(str_sig, sig_len, (*out), &state);
          (*len) += jwt_base64_encode_blockend((*out) + (*len), &state);
          (*out)[(*len)] = '\0';
          base64uri_encode((*out));
          return 0;
        } else {
          return ENOMEM;
        }
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
  char * sig_check;
  int len, res;
  if (!jwt_sign_sha_hmac(jwt, &sig_check, &len, head)) {
    res = !strcmp(sig, sig_check)?0:EINVAL;
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
  gnutls_digest_algorithm_t hash;
  char * str_sig;
  base64_encodestate state;
  int sig_len, sig_len_b64;
  int res, pk_alg;
  
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
    case JWT_ALG_ES256;
      alg = GNUTLS_DIG_SHA256;
      pk_alg = GNUTLS_PK_EC;
      break;
    case JWT_ALG_ES384;
      alg = GNUTLS_DIG_SHA384;
      pk_alg = GNUTLS_PK_EC;
      break;
    case JWT_ALG_ES512;
      alg = GNUTLS_DIG_SHA512;
      pk_alg = GNUTLS_PK_EC;
      break;
    default:
      hash = GNUTLS_DIG_NULL;
      pk_alg = GNUTLS_PK_UNKNOWN;
      break;
  }
  if (alg != GNUTLS_DIG_NULL) {
    if (!gnutls_x509_privkey_init(&key)) {
      if (!gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM)) {
        if (!gnutls_privkey_init(&privkey)) {
          if (!gnutls_privkey_import_x509(privkey, key, 0)) {
            if (pk_alg == gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
              if (!gnutls_privkey_sign_data(privkey, hash, 0, &body_dat, &sig_dat)) {
                (*out) = malloc(2*sig_dat.size);
                if (*out != NULL) {
                  jwt_base64_init_encodestate(&state);
                  (*len) = jwt_base64_encode_block(sig_dat.data, sig_dat.size, (*out), &state);
                  (*len) += jwt_base64_encode_blockend((*out) + (*len), &state);
                  (*out)[(*len)] = '\0';
                  base64uri_encode((*out));
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
  
}
