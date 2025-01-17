% JWK2KEY(1) jwk2key User Manual | LibJWT C Library

# NAME

**jwk2key** - Export JSON Web Keys to PKCS8

# SYNOPSIS

| **jwk2key**  **\[options]** \<FILE\> [FILE]...

# DESCRIPTION

**jwk2key** Takes JSON Web Key files and exports each key to a PKCS8 PEM file

This program will parse a JSON Web Key or Set and write out the individual
files to DIR (by default '**.**'). Output directory must exist. You should make
sure the permissions on the output directory are such that they cannot be
accessed by others.

JWK files must be listed after any options. A **-** will be interpreted as
_stdin_.

All _RSA_ key types will be written as plain _RSA_ keys, including _RSASSA-PSS_
keys, unless it has a _PS256_, _PS384_, or _PS512_ **alg** attribute.

All keys are written in PKCS8 PEM format, except key type _OCT_, which is
written as a binary file (.bin extension).

By default, existing files will not be overwritten. If you use the
**\-\-retry** option, an attempt will be made to add -1 to the file name, up to
-9, in an attempt to create the file.

Output file naming is based on (hopefully) unique characteristics, including:

- **Key type** E.g. **rsa**, **ec**, etc.
- **Bits** in the key. E.g. 2048 for an _RSA_ key, or 384 for an _EC_ key.
- **Private** vs **Public**. Public keys will have **\_pub** added to the end
  of the filename (before the extension).
- Most importantly, the **kid** attribute, which is supposed to be unique.

## Options

**\-h**, **\-\-help**
  ~ Show common options and quit.

**\-r**, **\-\-retry**
  ~ Retry if output file exists.

**\-d** _DIR_, **\-\-dir**=_DIR_
  ~ Directory to write key files to (default is '**.**').

# BUGS

See GitHub Issues: <https://github.com/benmcollins/libjwt/issues>

# AUTHOR

**jwk2key** written by Ben Collins <bcollins@libjwt.io>.

# SEE ALSO

**jwt-verify(1)**, **jwt-generate(1)**, **key2jwk(1)**
