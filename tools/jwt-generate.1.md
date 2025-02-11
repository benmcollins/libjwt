% JWT-GENERATE(1) jwt-generate User Manual | LibJWT C Library

# NAME

**jwt-generate** - Generate a JSON Web Token

# SYNOPSIS

| **jwt-generate**  **\[options]**

# DESCRIPTION

**jwt-generate** Generates and (optionally) signs a JSON Web Token.

By default this will simply encode a JWT. If you want a signature, then
you must give a JWK key with the **-k** option. Generating a signature
requires specifying the algorithm, so it must either be in the key file
(as the **alg** attribute), or passed on the command line with the
**-a** argument.

If **-a** is specified and the key has an **alg** attribute, they must
match.

One token will be generated for each call. You can specify claims using the
**-c** option. By default, **jwt-generate** will add the **iat** claim, which
is **Issued At** and is the time in seconds since the *Unix Epcoch*.

When using the **\-\-verbose** option, **jwt-generate** will print the JSON
_HEADER_ and _PAYLOAD_ to **stdout**.

If used in conjunction with **\-\-print**, the JSON will be piped to the
command's **stdin**. It will be called twice: once for _HEAD_ and once for
_PAYLOAD_.

One use is to pass it through **jq -C** for indenting and colorization. Another
would be to use an external program to inspect the _PAYLOAD_ contents. A non-0
exit status from the program will cause generating the token to fail.

## Options

**\-h**, **\-\-help**
  ~ Show common options and quit.

**\-l**, **\-\-list**
  ~ List all supported algorithms that can be passed to the **-a** option
  and quit.

**\-v**, **\-\-verbose**
  ~ Show the contents of the _HEADER_ and _PAYLOAD_ of the JWT in addition
  to generating the token. **NOTE** the header will not show the **typ** or
  **alg** attributes since they do not get added until the final step.

**\-q**, **\-\-quiet**
  ~ Do not output anything except for hard errors. On success you will only
  see the token generared.

**\-n**, **\-\-no-iat**
  ~ Do not add the iat (Issued-At) time to the token. Useful for a slightly
  smaller token, and for reproducible output.

**\-a** _ALG_, **\-\-algorithm**=_ALG_
  ~ Specify the algorithm to be used when signing the token.

**\-k** _FILE_, **\-\-key**=_FILE_
  ~ Path to a file containing a key in JSON Web Key format. If your keys are
  in PEM or DER (or some other common format that _OpenSSL_ understands), then
  you can convert it to a JWK with the **key2jwk(1)** tool.

**\-c** _CLAIM_, **\-\-claim**=_CLAIM_
  ~ Add a claim to the JWT. The format of _CLAIM_ is **t**:**key**=**value**
  Where **t** is the type and is one of **i** for integer, **s** for string,
  or **b** for boolean. The value for integer must be parseable my **strtol(3)**.
  For boolean, any value starting with **0**, **f**, or **F** will be interpreted
  as **false*. Anything else will be considered **true**. They **key** is any
  *ASCII* string.

**\-j** _JSON_, **\-\-json**=_JSON_
  ~ Use JSON string as the payload of the token. This will not replace, but be added
  to the payload. The string must be in valid JSON, meaning either a **{}** object
  or a **[]** array.

# BUGS

See GitHub Issues: <https://github.com/benmcollins/libjwt/issues>

# AUTHOR

**jwt-generate** was originally written by Jeremy Thien. Major rewriting and man
page by Ben Collins <bcollins@libjwt.io>.

# SEE ALSO

**jwt-verify(1)**, **key2jwk(1)**, **jwk2key(1)**
