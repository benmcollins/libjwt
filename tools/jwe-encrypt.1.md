% JWE-ENCRYPT(1) jwe-encrypt User Manual | LibJWT C Library

# NAME

**jwe-encrypt** - Encrypt content into a JSON Web Encryption (JWE) token

# SYNOPSIS

| **jwe-encrypt** **-k** _KEY_ **-a** _ALG_ **-e** _ENC_ **\[options]**

# DESCRIPTION

**jwe-encrypt** encrypts content into a JWE token. By default it produces
the Compact Serialization; **-f** selects a JSON Serialization instead.

A JWE requires two algorithms: a key management algorithm (the **alg**
header, given with **-a**) that determines how the Content Encryption Key
(CEK) is produced for the recipient, and a content encryption algorithm
(the **enc** header, given with **-e**) that performs the authenticated
encryption of the plaintext.

The recipient key is supplied as a JSON Web Key with **-k**. See
key2jwk(1) to convert a PEM or DER key to JWK format.

The plaintext is encrypted once with a single CEK. Additional recipients
may be added with **-r**: each independently wraps that same CEK with its
own algorithm and key, and any one recipient's key can later decrypt the
token. More than one recipient requires (and implies) the General JSON
Serialization.

The plaintext is taken from the **-j** option or, if not given, read from
standard input. The resulting token is written to standard output.

# OPTIONS

-h, \--help
:   Show help and exit.

-k, \--key=_FILE_
:   File containing the recipient JSON Web Key. Required.

-a, \--algorithm=_ALG_
:   The JWE key management algorithm. Required. One of: **dir**,
    **A128KW**, **A192KW**, **A256KW**, **RSA-OAEP**, **RSA-OAEP-256**,
    **ECDH-ES**, **ECDH-ES+A128KW**, **ECDH-ES+A192KW**,
    **ECDH-ES+A256KW**.

-e, \--enc=_ENC_
:   The JWE content encryption algorithm. Required. One of: **A128GCM**,
    **A192GCM**, **A256GCM**, **A128CBC-HS256**, **A192CBC-HS384**,
    **A256CBC-HS512**.

-f, \--format=_FORMAT_
:   The serialization to produce: **compact** (the default five-part
    string), **json-flat** (the Flattened JSON Serialization), or
    **json-general** (the General JSON Serialization). The Compact and
    Flattened forms carry exactly one recipient.

-r, \--recipient=_ALG_:_FILE_
:   Add another recipient: key management algorithm _ALG_ with the JWK in
    _FILE_. May be given more than once. Each recipient wraps the shared
    CEK independently. Using **-r** implies **\--format=json-general**.
    **dir** and **ECDH-ES** (Direct) constrain the CEK and cannot be
    combined with other recipients.

-A, \--aad=_FILE_
:   File whose raw contents become the JWE Additional Authenticated Data
    (the **aad** member). It is authenticated but not encrypted, and is
    only available in the JSON serializations.

-j, \--json=_STRING_
:   The plaintext to encrypt. If omitted, the plaintext is read from
    standard input.

# NOTES

For **dir**, the JWK must be a symmetric (**oct**) key whose length exactly
matches the CEK length required by the **enc** algorithm. For **A\*KW**,
the JWK must be an **oct** key of the matching size. For **RSA-OAEP** and
**RSA-OAEP-256**, the JWK must be an RSA public (or private) key. For
**ECDH-ES** and its **+A\*KW** variants, the JWK must be an EC key
(P-256/384/521) or an OKP X-curve key (X25519/X448).

The key must permit encryption use: a key marked **"use":"sig"** or whose
**key_ops** forbid the operation is rejected.

For the JSON serializations, the same header parameter name must not appear
in more than one of the protected, shared-unprotected, or per-recipient
headers; **jwe-encrypt** rejects a configuration that would violate this.

# SEE ALSO

jwe-decrypt(1), key2jwk(1), jwt-generate(1)
