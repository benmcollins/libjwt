#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <jansson.h>

// Base64 URL encoding
char *base64_url_encode(const unsigned char *input, int length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);

    // Do not add newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    // Create a null-terminated string
    char *output = malloc(bptr->length + 1);
    memcpy(output, bptr->data, bptr->length);
    output[bptr->length] = '\0';

    BIO_free_all(b64);

    // Replace '+' with '-', '/' with '_', and remove '='
    for (char *p = output; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    }

    char *p = strchr(output, '=');
    if (p) *p = '\0';

    return output;
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

    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if (!rsa) {
	rewind(fp);
	rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	priv = 1;
    }
    fclose(fp);

    if (!rsa) {
        fprintf(stderr, "Error reading RSA key\n");
        return 1;
    }

    // Get the modulus (n) and exponent (e)
    const BIGNUM *n, *e, *d, *p, *q, *dp, *dq, *qi;
    RSA_get0_key(rsa, &n, &e, &d);
    if (priv) {
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dp, &dq, &qi);
    }

    // Convert n and e to binary
    int n_len = BN_num_bytes(n);
    int e_len = BN_num_bytes(e);
    unsigned char *n_bin = malloc(n_len);
    unsigned char *e_bin = malloc(e_len);
    BN_bn2bin(n, n_bin);
    BN_bn2bin(e, e_bin);

    // Base64 URL encode the modulus and exponent
    char *n_b64 = base64_url_encode(n_bin, n_len);
    char *e_b64 = base64_url_encode(e_bin, e_len);

    free(n_bin);
    free(e_bin);

    // Create JWK JSON object
    json_t *jwk = json_object();
    json_object_set_new(jwk, "kty", json_string("RSA"));
    json_object_set_new(jwk, "use", json_string("sig"));

    json_t *ops = json_array();
    if (priv)
        json_array_append_new(ops, json_string("sign"));
    json_array_append_new(ops, json_string("verify"));
        json_object_set_new(jwk, "key_ops", ops);

    json_object_set_new(jwk, "n", json_string(n_b64));
    json_object_set_new(jwk, "e", json_string(e_b64));

    free(n_b64);
    free(e_b64);

    // Print the JWK
    char *jwk_str = json_dumps(jwk, JSON_INDENT(2));
    printf("%s\n", jwk_str);

    // Cleanup
    free(jwk_str);
    json_decref(jwk);
    RSA_free(rsa);

    return 0;
}
