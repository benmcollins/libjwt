% JWE-ENCRYPT(1) jwe-encrypt User Manual | LibJWT C Library

# NAME

**jwe-encrypt** - Encrypt content into a JSON Web Encryption (JWE) token

# SYNOPSIS

| **jwe-encrypt** **-k** _KEY_ **-a** _ALG_ **-e** _ENC_ **\[options]**

# DESCRIPTION

**jwe-encrypt** encrypts content into a JWE Compact Serialization token.

A JWE requires two algorithms: a key management algorithm (the **alg**
header, given with **-a**) that determines how the Content Encryption Key
(CEK) is produced for the recipient, and a content encryption algorithm
(the **enc** header, given with **-e**) that performs the authenticated
encryption of the plaintext.

The recipient key is supplied as a JSON Web Key with **-k**. See
key2jwk(1) to convert a PEM or DER key to JWK format.

The plaintext is taken from the **-j** option or, if not given, read from
standard input. The resulting token is written to standard output.

# OPTIONS

-h, \--help
:   Show help and exit.

-k, \--key=_FILE_
:   File containing the recipient JSON Web Key. Required.

-a, \--algorithm=_ALG_
:   The JWE key management algorithm. Required. One of: **dir**,
    **A128KW**, **A192KW**, **A256KW**, **RSA-OAEP**, **RSA-OAEP-256**.

-e, \--enc=_ENC_
:   The JWE content encryption algorithm. Required. One of: **A128GCM**,
    **A192GCM**, **A256GCM**, **A128CBC-HS256**, **A192CBC-HS384**,
    **A256CBC-HS512**.

-j, \--json=_STRING_
:   The plaintext to encrypt. If omitted, the plaintext is read from
    standard input.

# NOTES

For **dir**, the JWK must be a symmetric (**oct**) key whose length exactly
matches the CEK length required by the **enc** algorithm. For **A\*KW**,
the JWK must be an **oct** key of the matching size. For **RSA-OAEP** and
**RSA-OAEP-256**, the JWK must be an RSA public (or private) key.

The key must permit encryption use: a key marked **"use":"sig"** or whose
**key_ops** forbid the operation is rejected.

# SEE ALSO

jwe-decrypt(1), key2jwk(1), jwt-generate(1)
