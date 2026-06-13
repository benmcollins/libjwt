% JWE-DECRYPT(1) jwe-decrypt User Manual | LibJWT C Library

# NAME

**jwe-decrypt** - Decrypt and authenticate a JSON Web Encryption (JWE) token

# SYNOPSIS

| **jwe-decrypt** **-k** _KEY_ **-a** _ALG_ **-e** _ENC_ **\[options]** **\[TOKEN]**

# DESCRIPTION

**jwe-decrypt** parses a JWE Compact Serialization token, recovers the
Content Encryption Key, and decrypts and authenticates the content.

The key is supplied as a JSON Web Key with **-k**. The expected key
management algorithm (**-a**) and content encryption algorithm (**-e**)
act as an allow-list: a token whose header does not match the configured
pair is rejected. This prevents a token from selecting an unexpected
algorithm.

The token may be given as the final argument or, if omitted, read from
standard input. On success the decrypted plaintext is written to standard
output. On any failure the program prints an error and exits non-zero.

# OPTIONS

-h, \--help
:   Show help and exit.

-k, \--key=_FILE_
:   File containing the JSON Web Key used to recover the CEK. Required.

-a, \--algorithm=_ALG_
:   The expected JWE key management algorithm. Required.

-e, \--enc=_ENC_
:   The expected JWE content encryption algorithm. Required.

# NOTES

A failure to recover the CEK (a wrong key, bad RSA padding, or a corrupted
wrapped key) is not distinguished from a failed content authentication
tag: per RFC 7516, the decrypter substitutes a random CEK and fails
uniformly at the tag, denying a padding oracle.

# SEE ALSO

jwe-encrypt(1), key2jwk(1), jwt-verify(1)
