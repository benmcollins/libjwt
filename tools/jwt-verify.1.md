% JWT-VERIFY(1) jwt-verify User Manual | LibJWT C Library

# NAME

**jwt-verify** - Verify a JSON Web Token

# SYNOPSIS

| **jwt-verify**  **\[options]** _token_ ...
| **jwt-verify**  **\[options]** - < _token_

# DESCRIPTION

**jwt-verify** Decodes and (optionally) verifies the signature
of a JSON Web Token.

By default, the token(s) will be decoded and verified. If there is a
signature block on the JWT, then you must give a JWK key with the
**-k** option. Verifying a signature requires specifying the algorithm,
so it must either be in the key file (as the **alg** attribute), or
passed on the command line with the **-a** argument.

**jwt-verify** will not assume the algorithm from the JWT itself (for
security reasons), however, the algorithm in the JWT must match what
you provide to **jwt-verify**.

Tokens may be passed on the command line, after any options, separated
by spaces, or passed via **stdin**, one per line. To use **stdin**, you
must pass **-** as the last and only argument after any options.

When using the **\-\-verbose** option, **jwt-verify** will print the JSON
_HEADER_ and _PAYLOAD_ to **stdout**.

If used in conjunction with **\-\-print**, the JSON will be piped to the
command's **stdin**. It will be called twice: once for _HEAD_ and once for
_PAYLOAD_.

One use is to pass it through **jq -C** for indenting and colorization. Another
would be to use an external program to validate the _PAYLOAD_ contents. A non-0
exit status from the program will cause verification to fail.

## Options

**\-h**, **\-\-help**
  ~ Show common options and quit.

**\-l**, **\-\-list**
  ~ List all supported algorithms that can be passed to the **-a** option
  and quit.

**\-v**, **\-\-verbose**
  ~ Show the contents of the _HEADER_ and _PAYLOAD_ of the JWT in addition
  to verifying the token.

**\-q**, **\-\-quiet**
  ~ Do not output anything except for hard errors. The exit value will be the
  number of token validation failures.

**\-a** _ALG_, **\-\-algorithm**=_ALG_
  ~ Specify the algorithm to be used when verifying the signature block of
  any tokens passed to the program. See **-l** for values of _ALG_.

**\-k** _FILE_, **\-\-key**=_FILE_
  ~ Path to a file containing a key in JSON Web Key format. If your keys are
  in PEM or DER (or some other common format that _OpenSSL_ understands), then
  you can convert it to a JWK with the **key2jwk(1)** tool.

**\-p** _CMD_, **\-\-print**=_CMD_
  ~ Pipe JSON of header and payload to _CMD_ through its **stdin**. This option
  only makes sense with **\-\-verbose**.

# BUGS

See GitHub Issues: <https://github.com/benmcollins/libjwt/issues>

# AUTHOR

**jwt-verify** was originally written by Jeremy Thien. Major rewriting and man
page by Ben Collins <bcollins@libjwt.io>.

# SEE ALSO

**jwt-verify(1)**, **key2jwk(1)**, **jwk2key(1)**
