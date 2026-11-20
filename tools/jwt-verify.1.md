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
**-k** option, or a JWK Set with the **-r** option. Verifying a signature
with **-k** requires specifying the algorithm, so it must either be in
the key file (as the **alg** attribute), or passed on the command line
with the **-a** argument.

An unsigned token (**"alg":"none"**) is rejected unless **-a none** is given
with neither **-k** nor **-r** (RFC 8725 §3.2); such a token is then only
decoded, since there is no signature to check.

**jwt-verify** will not assume the algorithm from the JWT itself (for
security reasons), however, the algorithm in the JWT must match what
you provide to **jwt-verify**.

Tokens may be passed on the command line, after any options, separated
by spaces, or passed via **stdin**, one per line. To use **stdin**, you
must pass **-** as the last and only argument after any options.

Each line of **stdin** is one token, and the last line does not need a
newline. An empty line is a token that fails. A line of 1048576 bytes (1 MiB)
or more, not counting its newline, or one that has a NUL byte in it, is not
verified, not even in part, and counts as one token that failed.

When using the **\-\-verbose** option, **jwt-verify** will print the JSON
_HEADER_ and _PAYLOAD_ to **stdout**.

If used in conjunction with **\-\-print**, the JSON will be piped to the
command's **stdin**. It will be called twice: once for _HEAD_ and once for
_PAYLOAD_.

One use is to pass it through **jq -C** for indenting and colorization. Another
would be to use an external program to validate the _PAYLOAD_ contents. A non-0
exit status from the program will cause verification to fail, and so will the
program being ended by a signal.

The command need not read all of its input: if it stops reading, **jwt-verify**
is not ended (no matter how large the JSON is), and the program's exit status,
or a signal that ends it, still decides whether the token passes.

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
  ~ Do not output anything except for hard errors. The result is the exit
  status: see **EXIT STATUS**.

**\-a** _ALG_, **\-\-algorithm**=_ALG_
  ~ Specify the algorithm to be used when verifying the signature block of
  any tokens passed to the program. See **-l** for values of _ALG_. Not
  accepted with **\-\-keyring**, where a key's own **alg**, if it has one,
  pins the algorithm. With neither **-k** nor **-r**, **-a none** accepts an
  unsigned (**"alg":"none"**) token, which is then only decoded; without it,
  such a token is rejected.

**\-k** _FILE_, **\-\-key**=_FILE_
  ~ Path to a file containing a key in JSON Web Key format. If your keys are
  in PEM or DER (or some other common format that _OpenSSL_ understands), then
  you can convert it to a JWK with the **key2jwk(1)** tool.

**\-r** _FILE_, **\-\-keyring**=_FILE_
  ~ Path to a file containing a JWK Set (JWKS) of candidate keys, used to verify
  Compact tokens and the (multi-signature) JWS JSON Serialization (RFC 7515
  §7.2). A signature naming a **kid** is matched to that key; a keyless
  signature is tried against every compatible key. A key whose **use** is not
  **sig**, or whose **key_ops** names neither **verify** nor **sign**, is not a
  candidate. Mutually exclusive with **\-\-key**.

**\-P** _POLICY_, **\-\-policy**=_POLICY_
  ~ Multi-signature acceptance policy when a keyring is used: **any** (the
  default — accept if at least one signature verifies) or **all** (every
  signature in the token must verify).

**\-p** _CMD_, **\-\-print**=_CMD_
  ~ Pipe JSON of header and payload to _CMD_ through its **stdin**. Requires
  **\-\-verbose**; without it the command would never run, so it is a usage
  error.

# EXIT STATUS

**0**
  ~ Every token was verified: its signature checked with **-k** or **-r**, or,
  with neither, the token is unsigned and **-a none** was given, so it is only
  decoded. With neither and no **-a none**, every token fails.

**1**
  ~ A token failed, there was no token to verify (nothing to read on
  **stdin**), or the program could not do its work: a bad option, a key or
  keyring that could not be loaded, a read error.

The exit status is not the number of tokens that failed. It is 1 for one
failure and for any number of them.

**\-\-help** and **\-\-list** verify nothing; given alone they exit 0, but given
with anything else (a token, a key, another option) they are a usage error
(exit 1). An argument that starts with **-** is read as an option unless it
comes after **\-\-**, and a **-** on its own selects **stdin** even after
**\-\-**. To check a string that comes from somewhere you do not trust, write it
to **stdin** as a single line, or reject it first if it starts with **-**, which
a token never does.

# BUGS

See GitHub Issues: <https://github.com/benmcollins/libjwt/issues>

# AUTHOR

**jwt-verify** was originally written by Jeremy Thien. Major rewriting and man
page by Ben Collins <bcollins@libjwt.io>.

# SEE ALSO

**jwt-generate(1)**, **key2jwk(1)**, **jwk2key(1)**
