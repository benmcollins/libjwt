#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <jansson.h>

// Base64 URL encoding
static char *base64_url_encode(BIGNUM *input)
{
    /* Convert to data */
    int len = BN_num_bytes(input);
    unsigned char *bin = OPENSSL_malloc(len);
    BN_bn2bin(input, bin);

    /* Setup base64 encoding */
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    /* Write the BN data to the chain */
    BIO_write(b64, bin, len);
    BIO_flush(b64);

    OPENSSL_free(bin);

    /* Get the result */
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    char *output = OPENSSL_malloc(bptr->length + 1);
    memcpy(output, bptr->data, bptr->length);
    output[bptr->length] = '\0';

    BIO_free_all(b64);

    /* URL encoding */
    for (char *p = output; *p; p++) {
        if (*p == '+')
	    *p = '-';
        else if (*p == '/')
	    *p = '_';
    }

    /* Truncate at '=' */
    char *p = strchr(output, '=');
    if (p) *p = '\0';

    return output;
}

static void get_one_bn(EVP_PKEY *pkey, const char *ossl_param,
			  json_t *jwk, const char *name)
{
	BIGNUM *bn = NULL;
	EVP_PKEY_get_bn_param(pkey, ossl_param, &bn);
	char *b64 = base64_url_encode(bn);
	BN_free(bn);
	json_object_set_new(jwk, name, json_string(b64));
	OPENSSL_free(b64);
}

static void get_one_string(EVP_PKEY *pkey, const char *ossl_param,
			   json_t *jwk, const char *name)
{
	char buf[256];
	size_t len = sizeof(buf);
	EVP_PKEY_get_utf8_string_param(pkey, ossl_param, buf, len, NULL);
	json_object_set_new(jwk, name, json_string(buf));
}

static void process_ec_key(EVP_PKEY *pkey, int priv, json_t *jwk)
{
    get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_X, jwk, "x");
    get_one_bn(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, jwk, "y");
    get_one_string(pkey, OSSL_PKEY_PARAM_GROUP_NAME, jwk, "crv");
    if (priv)
	get_one_bn(pkey, OSSL_PKEY_PARAM_PRIV_KEY, jwk, "d");

#if 0
# define OSSL_PKEY_PARAM_EC_A "a"
# define OSSL_PKEY_PARAM_EC_B "b"
# define OSSL_PKEY_PARAM_EC_CHAR2_M "m"
# define OSSL_PKEY_PARAM_EC_CHAR2_PP_K1 "k1"
# define OSSL_PKEY_PARAM_EC_CHAR2_PP_K2 "k2"
# define OSSL_PKEY_PARAM_EC_CHAR2_PP_K3 "k3"
# define OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS "tp"
# define OSSL_PKEY_PARAM_EC_CHAR2_TYPE "basis-type"
# define OSSL_PKEY_PARAM_EC_COFACTOR "cofactor"
# define OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS "decoded-from-explicit"
# define OSSL_PKEY_PARAM_EC_ENCODING "encoding"
# define OSSL_PKEY_PARAM_EC_FIELD_TYPE "field-type"
# define OSSL_PKEY_PARAM_EC_GENERATOR "generator"
# define OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE "group-check"
# define OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC "include-public"
# define OSSL_PKEY_PARAM_EC_ORDER "order"
# define OSSL_PKEY_PARAM_EC_P "p"
# define OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT "point-format"
# define OSSL_PKEY_PARAM_EC_SEED "seed"
#endif
}

static void process_rsa_key(EVP_PKEY *pkey, int priv, json_t *jwk)
{
    get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_N, jwk, "n");
    get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_E, jwk, "e");
    if (priv) {
	get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_D, jwk, "d");
        get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, jwk, "p");
        get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, jwk, "q");
        get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, jwk, "dp");
        get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, jwk, "dq");
        get_one_bn(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, jwk, "qi");
    }
}

int main(int argc, char **argv) {
    int priv = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PEM file>\n", argv[0]);
        return 1;
    }

    const char *pem_file = argv[1];
    FILE *fp = fopen(pem_file, "r");
    if (!fp) {
        perror("Error opening PEM file");
        return 1;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (pkey == NULL) {
	rewind(fp);
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        priv = 1;
    }
    fclose(fp);

    if (pkey == NULL) {
        fprintf(stderr, "Error reading RSA key\n");
        return 1;
    }

    /* Setup json object */
    json_t *jwk = json_object();
    json_object_set_new(jwk, "use", json_string("sig"));

    json_t *ops = json_array();
    if (priv)
        json_array_append_new(ops, json_string("sign"));
    json_array_append_new(ops, json_string("verify"));
        json_object_set_new(jwk, "key_ops", ops);

    if (EVP_PKEY_get_base_id(pkey) == EVP_PKEY_RSA) {
	json_object_set_new(jwk, "kty", json_string("RSA"));
	process_rsa_key(pkey, priv, jwk);
    } else if (EVP_PKEY_get_base_id(pkey) == EVP_PKEY_EC) {
	json_object_set_new(jwk, "kty", json_string("EC"));
	process_ec_key(pkey, priv, jwk);
    }

    EVP_PKEY_free(pkey);

    char *jwk_str = json_dumps(jwk, JSON_INDENT(2));
    printf("%s\n", jwk_str);

    free(jwk_str);
    json_decref(jwk);

    return 0;
}
