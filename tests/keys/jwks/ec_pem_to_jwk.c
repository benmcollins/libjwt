#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <jansson.h>

static int uuid_v4_gen(char *buffer)
{
	union
	{
		struct
		{
			uint32_t time_low;
			uint16_t time_mid;
			uint16_t time_hi_and_version;
			uint8_t  clk_seq_hi_res;
			uint8_t  clk_seq_low;
			uint8_t  node[6];
		};
		uint8_t __rnd[16];
	} uuid;

	int rc = RAND_bytes(uuid.__rnd, sizeof(uuid));

	// Refer Section 4.2 of RFC-4122
	// https://tools.ietf.org/html/rfc4122#section-4.2
	uuid.clk_seq_hi_res = (uint8_t) ((uuid.clk_seq_hi_res & 0x3F) | 0x80);
	uuid.time_hi_and_version = (uint16_t) ((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

	snprintf(buffer, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
			uuid.clk_seq_hi_res, uuid.clk_seq_low,
			uuid.node[0], uuid.node[1], uuid.node[2],
			uuid.node[3], uuid.node[4], uuid.node[5]);

	return rc;
}

// Base64 URL encoding
static char *base64_url_encode(const unsigned char *input, int length) {
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
    char uuidv4[38];

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

    EC_KEY *ec_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    if (!ec_key) {
	rewind(fp);
	ec_key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
	if (!ec_key) {
	    fprintf(stderr, "Error reading EC key\n");
	    return 1;
	}
	priv = 1;
    }
    fclose(fp);

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *point = EC_KEY_get0_public_key(ec_key);

    if (!group || !point) {
        fprintf(stderr, "Error retrieving EC key components\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    // Extract public key components
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    const BIGNUM *d;

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)) {
        fprintf(stderr, "Error extracting EC public key coordinates\n");
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return 1;
    }

    if (priv)
	d = EC_KEY_get0_private_key(ec_key);

    // Convert x and y to binary
    int x_len = BN_num_bytes(x);
    int y_len = BN_num_bytes(y);
    int d_len;
    unsigned char *x_bin = malloc(x_len);
    unsigned char *y_bin = malloc(y_len);
    unsigned char *d_bin;
    BN_bn2bin(x, x_bin);
    BN_bn2bin(y, y_bin);

    if (priv) {
	d_len = BN_num_bytes(d);
	d_bin = malloc(d_len);
	BN_bn2bin(d, d_bin);
    }

    // Base64 URL encode the x and y coordinates
    char *x_b64 = base64_url_encode(x_bin, x_len);
    char *y_b64 = base64_url_encode(y_bin, y_len);
    char *d_b64;

    if (priv)
	d_b64 = base64_url_encode(d_bin, d_len);

    free(x_bin);
    free(y_bin);
    if (priv)
	free(d_bin);

    // Get curve name
    int nid = EC_GROUP_get_curve_name(group);
    const char *crv = OBJ_nid2sn(nid);

    if (!crv) {
        fprintf(stderr, "Unsupported curve\n");
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return 1;
    }

    json_t *jwk = json_object();
    json_object_set_new(jwk, "kty", json_string("EC"));
    json_object_set_new(jwk, "use", json_string("sig"));

    json_t *ops = json_array();
    if (priv)
	json_array_append_new(ops, json_string("sign"));
    json_array_append_new(ops, json_string("verify"));
        json_object_set_new(jwk, "key_ops", ops);

    json_object_set_new(jwk, "crv", json_string(crv));
    json_object_set_new(jwk, "x", json_string(x_b64));
    json_object_set_new(jwk, "y", json_string(y_b64));
    if (priv)
	json_object_set_new(jwk, "d", json_string(d_b64));

    free(x_b64);
    free(y_b64);
    if (priv)
	free(d_b64);

    // Print the JWK
    char *jwk_str = json_dumps(jwk, JSON_INDENT(2));
    printf("%s\n", jwk_str);

    // Cleanup
    free(jwk_str);
    json_decref(jwk);
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec_key);

    return 0;
}
