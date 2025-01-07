/* Copyright (C) 2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_GNUTLS_H
#define JWT_GNUTLS_H

/* Until we have our own routines, we rely on OpenSSL */
int openssl_process_eddsa(json_t *jwk, jwk_item_t *item);
int openssl_process_rsa(json_t *jwk, jwk_item_t *item);
int openssl_process_ec(json_t *jwk, jwk_item_t *item);
void openssl_process_item_free(jwk_item_t *item);

int gnutls_process_eddsa(json_t *jwk, jwk_item_t *item);
int gnutls_process_rsa(json_t *jwk, jwk_item_t *item);
int gnutls_process_ec(json_t *jwk, jwk_item_t *item);
void gnutls_process_item_free(jwk_item_t *item);

#endif /* JWT_GNUTLS_H */
