#!/usr/bin/env bats

BASIC_RES="eyJhbGciOiJub25lIn0.e30."

# Fail the test if a sanitizer (ASan/LSan/UBSan) reported in a tool's output.
# The CI "Sanitizer" row builds everything with -fsanitize and runs the suite
# under LeakSanitizer; there, an error-path "run" can exit non-zero from a
# detected *leak* rather than the error under test, with the report captured in
# $output instead of flushed. A bare "[ status -ne 0 ]" would then pass on that
# leak, so the error-exit tests below call this too. Off a sanitizer build
# $output never holds these strings, so it is a no-op for a normal run.
refute_sanitizer() {
	if printf '%s\n' "${output}" | \
	    grep -qE 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:'; then
		printf 'sanitizer report in tool output:\n%s\n' "${output}" >&2
		return 1
	fi
	return 0
}

# Issue #367: every key fixture must be found wherever the build directory
# sits, so key paths resolve through ${SRCDIR} (exported by ctest), never a
# build-dir-relative path that only works when the build directory is a direct
# child of the source root. A depth-1 CI build (which always runs "make all"
# first) would not catch a regression back to the latter, so pin it here: no
# top-level key variable may be assigned such a path. The grep is anchored to
# an assignment at column 0, so this test's own indented grep line and the
# comment lines above it do not match themselves.
@test "key fixtures resolve through \$SRCDIR, not a build-relative path (#367)" {
	[ -n "${SRCDIR}" ]
	[ -d "${SRCDIR}/tests/keys" ]
	run grep -nE '^[A-Za-z_][A-Za-z_0-9]*=.*\.\./tests/keys' \
		"${BATS_TEST_DIRNAME}/jwt-cli.bats"
	[ "${status}" -ne 0 ]
}

@test "Generate a JWT with alg none" {
	result="$(./tools/jwt-generate -v -a none -n)"
	[ "$result" = ${BASIC_RES} ]
}

@test "Verify a JWT with alg none" {
	# A keyless checker rejects unsigned tokens by default (issue #352);
	# "-a none" is the explicit opt-in that accepts one.
	./tools/jwt-verify -v -a none ${BASIC_RES}
}

@test "Verify rejects an unsigned token without -a none" {
	run ./tools/jwt-verify ${BASIC_RES}
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Unsigned tokens are not allowed"
	refute_sanitizer
}

HS256_RES="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds"
HS256_KEY="${SRCDIR}/tests/keys/oct_key_256.json"

@test "Generate a JWT with alg HS256" {
	result="$(./tools/jwt-generate -v -a HS256 -n -k ${HS256_KEY})"
	[ "$result" = ${HS256_RES} ]
}

@test "Verify a JWT with alg HS256" {
	./tools/jwt-verify -v -k ${HS256_KEY} ${HS256_RES}
}

CLAIM_RES="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ZmFsc2UsImV4cCI6MTgzOTMxNzU2MiwiZm9vIjoiYmFyIiwiZ3JvdXAiOiJzdGFmZiIsImlzcyI6ImRpc2suc3dpc3NkaXNrLmNvbSIsInVzZXIiOiJiY29sbGlucyJ9.9RCEoB3XXGZrlU3JAx21x6p8mZguZS_NviKgJqEu330"

@test "Generate a JWT with alg HS256 and claims" {
	result="$(./tools/jwt-generate -v -n 	\
		-k ${HS256_KEY}			\
		-c s:group=staff		\
		-c b:admin=false		\
		-c s:iss=disk.swissdisk.com	\
		-c s:user=bcollins		\
		-c i:exp=1839317562		\
		-j '{"foo":"bar"}')"
	[ "$result" = ${CLAIM_RES} ]
}

@test "Verify a JWT with alg HS256 with claims" {
	./tools/jwt-verify -v -k ${HS256_KEY} ${CLAIM_RES}
}

# issue #360: a token whose payload base64url-decodes to {"sub":"a<TAB>b"} (a
# raw control character in a string) is refused on both JSON backends; json-c
# used to accept it in its lenient mode and report "[YES] Verified".
@test "Verify refuses a raw control character in the payload" {
	token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhCWIifQ.ysAzm8THucw2RI47Xm8hCXDT2WPTWJsLXeDuQKCMexU"
	run ./tools/jwt-verify -k ${HS256_KEY} "${token}"
	[ "${status}" -ne 0 ]
}

# A key without an "alg" needs -a/--algorithm, and both spellings must work.
NOALG_KEY="${SRCDIR}/tests/keys/oct_key_256_sig.json"

@test "Verify with -a ALG as well as --algorithm=ALG" {
	token="$(./tools/jwt-generate -q -n -a HS256 -k ${NOALG_KEY})"
	./tools/jwt-verify -q -a HS256 -k ${NOALG_KEY} "${token}"
	./tools/jwt-verify -q --algorithm=HS256 -k ${NOALG_KEY} "${token}"
	# The algorithm given is the one enforced...
	run ./tools/jwt-verify -a HS384 -k ${NOALG_KEY} "${token}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q 'alg does not match'
	# ...and an unknown one is reported by name.
	run ./tools/jwt-verify -a BOGUS -k ${NOALG_KEY} "${token}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q 'Unknown algorithm \[BOGUS\]'
}

@test "Generate JWKS from PEM Files" {
	# The golden all.json covers every key type, but only the OpenSSL backend
	# converts them all: GnuTLS has no secp256k1, MbedTLS has no EdDSA (the
	# others silently fall back to an "oct" key via TRY_HMAC). OpenSSL is the
	# only backend that yields EC for secp256k1 AND OKP for Ed25519, so probe
	# both and skip otherwise.
	#
	# #364: run key2jwk as a captured command on each probe key first, so a
	# tool failure (e.g. a leak abort under LeakSanitizer, whose report lands
	# in $output) FAILS this test here, instead of the capability probe below
	# silently turning it into a skip. A backend that merely lacks a curve
	# still exits 0 (it falls back to oct), so this trips only on a real
	# key2jwk failure, not a capability gap.
	run ./tools/key2jwk -o - \
		${SRCDIR}/tests/keys/pem-files/ec_key_secp256k1.pem
	[ "${status}" -eq 0 ]
	refute_sanitizer
	run ./tools/key2jwk -o - \
		${SRCDIR}/tests/keys/pem-files/eddsa_key_ed25519.pem
	[ "${status}" -eq 0 ]
	refute_sanitizer
	k1=$(./tools/key2jwk -o - \
		${SRCDIR}/tests/keys/pem-files/ec_key_secp256k1.pem 2>/dev/null \
		| jq -r '.keys[0].kty')
	ed=$(./tools/key2jwk -o - \
		${SRCDIR}/tests/keys/pem-files/eddsa_key_ed25519.pem 2>/dev/null \
		| jq -r '.keys[0].kty')
	if [ "${k1}" != "EC" ] || [ "${ed}" != "OKP" ]; then
		skip "active backend cannot convert all key types (needs OpenSSL)"
	fi

	./tools/key2jwk --disable-kid -o - \
		${SRCDIR}/tests/keys/pem-files/*.pem \
		${SRCDIR}/tests/keys/pem-files/*.bin | \
		grep -v  libjwt.io: > output.json

	jq -r -n --slurpfile A ${SRCDIR}/tests/cli/all.json \
		--slurpfile B output.json -f <(cat<<"EOF"
def walk(f):
  . as $in
  | if type == "object" then
      reduce keys[] as $key
        ( {}; . + { ($key):  ($in[$key] | walk(f)) } ) | f
  elif type == "array" then map( walk(f) ) | f
  else f
  end;

def normalize: walk(if type == "array" then sort else . end);

def equiv(x): normalize == (x | normalize);

if $A | equiv($B) then empty else halt_error(1) end
EOF
)
}

@test "Generate JWK from DER matches PEM" {
	./tools/key2jwk --disable-kid -o - \
		${SRCDIR}/tests/keys/pem-files/rsa_key_2048.der | \
		grep -v libjwt.io: > der.json
	./tools/key2jwk --disable-kid -o - \
		${SRCDIR}/tests/keys/pem-files/rsa_key_2048.pem | \
		grep -v libjwt.io: > pem.json

	jq -r -n --slurpfile A pem.json --slurpfile B der.json -f <(cat<<"EOF"
def equiv(x): . == x;
if ($A[0].keys[0]) == ($B[0].keys[0]) then empty else halt_error(1) end
EOF
)
}

# #364: key2jwk must free the set it has built so far (not lose it) when a later
# file fails to load, and release everything on its error exits. The first key
# loads, the second does not: the tool fails but does not leak under ASan/LSan.
@test "key2jwk fails but keeps its set when a later file is missing" {
	run ./tools/key2jwk -o - \
		${SRCDIR}/tests/keys/pem-files/rsa_key_2048.pem \
		${SRCDIR}/tests/keys/pem-files/does-not-exist.pem
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Error parsing key file"
	refute_sanitizer
}

# A non-key file with --disable-hmac (no HMAC fallback) is flagged in error,
# exercising key2jwk's jwks_error exit path.
@test "key2jwk with --disable-hmac rejects a non-key file" {
	nonkey="${BATS_TMPDIR:-/tmp}/notakey_$$.txt"
	printf 'this is not a key\n' > "${nonkey}"
	run ./tools/key2jwk -m -o - "${nonkey}"
	rm -f "${nonkey}"
	[ "${status}" -ne 0 ]
	refute_sanitizer
}

@test "Convert JWK to PEM - RSA" {
	rm -f rsa_1024_0023a6e1-f093-448d-9038-9ff168611b86.pem
	./tools/jwk2key -d . ${SRCDIR}/tests/keys/rsa_key_1024.json
	# The byte-exact comparison assumes the PKCS#8 ("BEGIN PRIVATE KEY")
	# serialization that OpenSSL and GnuTLS emit. The MbedTLS backend writes
	# the equally-valid PKCS#1 ("BEGIN RSA PRIVATE KEY") form, so skip the
	# comparison when the produced PEM is not PKCS#8.
	head -1 rsa_1024_0023a6e1-f093-448d-9038-9ff168611b86.pem \
		| grep -q -- "-----BEGIN PRIVATE KEY-----" \
		|| skip "backend emits a non-PKCS#8 PEM serialization"
	cmp rsa_1024_0023a6e1-f093-448d-9038-9ff168611b86.pem ${SRCDIR}/tests/keys/pem-files/rsa_key_1024.pem
}

@test "Convert JWK to PEM - OCT" {
	rm -f oct_384*.bin
	./tools/jwk2key -d . ${SRCDIR}/tests/keys/oct_key_384.json
	# oct_key_384.json carries no "kid", so jwk2key names the file by the
	# key's RFC 7638 thumbprint: oct_384_<thumbprint>.bin
	cmp oct_384_*.bin ${SRCDIR}/tests/cli/oct_384.bin
}

# JWE tools

OCT256="${SRCDIR}/tests/keys/oct_dir_256.json"
OCT256B="${SRCDIR}/tests/keys/oct_key_256_enc.json"
RSAENC="${SRCDIR}/tests/keys/rsa_key_2048_enc.json"

@test "JWE dir + A256GCM round-trip" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"a":1}')"
	result="$(echo "${tok}" | ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM)"
	[ "${result}" = '{"a":1}' ]
}

# Issue #375: jwe-decrypt reads the one token correctly. stdin is read whole,
# never truncated at a NUL byte and never with its lines joined; a Compact
# token is one line (a second token or a token split over lines is an error),
# while a JSON token may span lines. Exactly one token argument is accepted.
# Modeled on the jwt-verify stdin cases above.
@test "jwe-decrypt stdin rejects a NUL byte and decrypts nothing" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"a":1}')"
	tok2="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"b":2}')"
	# A token, a NUL byte, then junk used to decrypt the token with exit 0.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM \
		< <(printf '%s\0junk\n' "${tok}")
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'NUL byte'
	[ "$(echo "${output}" | grep -c '{"a":1}')" -eq 0 ]
	refute_sanitizer
	# A NUL byte then a whole second token: the token in front is not used.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM \
		< <(printf '%s\0%s\n' "${tok}" "${tok2}")
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c '{"a":1}')" -eq 0 ]
	# A NUL byte inside the token, and as the very first byte, both error.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM \
		< <(printf '%s\0%s\n' "${tok:0:20}" "${tok:20}")
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'NUL byte'
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM \
		< <(printf '\0%s\n' "${tok}")
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'NUL byte'
	refute_sanitizer
}

@test "jwe-decrypt stdin rejects an over-long token (distinct from NUL)" {
	# More than MAX_TOKEN_LEN (1 MiB) of input, no NUL: read_stdin_token()
	# returns -4 and the tool says it is too long, not a NUL-byte error.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM \
		< <(head -c 1100000 /dev/zero | tr '\000' 'a')
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'too long'
	[ "$(echo "${output}" | grep -c 'NUL byte')" -eq 0 ]
	refute_sanitizer
}

@test "jwe-decrypt stdin rejects a second token or a split Compact token" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"a":1}')"
	tok2="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"b":2}')"
	# Two Compact tokens on two lines used to be joined into one bad token.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM \
		< <(printf '%s\n%s\n' "${tok}" "${tok2}")
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'more than one token'
	refute_sanitizer
	# A Compact token split over two lines used to be rejoined and decrypt.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM \
		< <(printf '%s\n%s\n' "${tok:0:30}" "${tok:30}")
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c '{"a":1}')" -eq 0 ]
	refute_sanitizer
}

@test "jwe-decrypt stdin decrypts with or without a trailing newline" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"a":1}')"
	result="$(printf '%s\n' "${tok}" | \
		./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM)"
	[ "${result}" = '{"a":1}' ]
	result="$(printf '%s' "${tok}" | \
		./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM)"
	[ "${result}" = '{"a":1}' ]
	# A trailing CRLF is a line end too and is dropped.
	result="$(printf '%s\r\n' "${tok}" | \
		./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM)"
	[ "${result}" = '{"a":1}' ]
}

@test "jwe-decrypt stdin accepts a pretty-printed JSON token" {
	# jq . reformats the JSON serialization across several lines; both the
	# Flattened and General forms must still decrypt from stdin.
	ftok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM \
		-f json-flat -j '{"j":1}')"
	gtok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM \
		-f json-general -j '{"g":2}')"
	result="$(jq . <<< "${ftok}" | \
		./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM)"
	[ "${result}" = '{"j":1}' ]
	result="$(jq . <<< "${gtok}" | \
		./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM)"
	[ "${result}" = '{"g":2}' ]
}

@test "jwe-decrypt accepts only one token argument" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"a":1}')"
	tok2="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"b":2}')"
	# A second argument used to be silently ignored, with exit 0.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM "${tok}" "${tok2}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'Only one token argument'
	[ "$(echo "${output}" | grep -c '{"a":1}')" -eq 0 ]
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM "${tok}" junk
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c '{"a":1}')" -eq 0 ]
	refute_sanitizer
	# One argument still decrypts.
	result="$(./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM "${tok}")"
	[ "${result}" = '{"a":1}' ]
}

@test "jwe-decrypt tells empty stdin from a read error" {
	# Empty stdin and a read error both exit 1, with distinct messages.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM < /dev/null
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'No token read from stdin'
	refute_sanitizer
	# A directory cannot be read: the errno is reported, not taken for empty.
	run ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM < .
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'Could not read stdin'
	refute_sanitizer
}

@test "JWE A256KW + A256CBC-HS512 round-trip" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a A256KW -e A256CBC-HS512 -j '{"b":2}')"
	result="$(echo "${tok}" | ./tools/jwe-decrypt -k ${OCT256} -a A256KW -e A256CBC-HS512)"
	[ "${result}" = '{"b":2}' ]
}

@test "JWE RSA-OAEP-256 + A256GCM round-trip" {
	tok="$(./tools/jwe-encrypt -k ${RSAENC} -a RSA-OAEP-256 -e A256GCM -j '{"c":3}')"
	result="$(echo "${tok}" | ./tools/jwe-decrypt -k ${RSAENC} -a RSA-OAEP-256 -e A256GCM)"
	[ "${result}" = '{"c":3}' ]
}

@test "JWE decrypt with wrong key fails" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{}')"
	run bash -c "echo '${tok}' | ./tools/jwe-decrypt -k ${OCT256B} -a dir -e A256GCM"
	[ "${status}" -ne 0 ]
}

# The same key as OCT256B, flagged in error when loaded (a malformed "x5c").
OCT256B_ERR="${SRCDIR}/tests/keys/oct_key_256_enc_bad_x5c.json"

@test "JWE tools refuse a key in error" {
	run ./tools/jwe-encrypt -k ${OCT256B_ERR} -a A256KW -e A256GCM -j '{}'
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Key is in error"

	tok="$(./tools/jwe-encrypt -k ${OCT256B} -a A256KW -e A256GCM -j '{}')"
	run bash -c "echo '${tok}' | ./tools/jwe-decrypt -k ${OCT256B_ERR} -a A256KW -e A256GCM"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Key is in error"
}

@test "JWE encrypt rejects unknown algorithm" {
	run ./tools/jwe-encrypt -k ${OCT256} -a BOGUS -e A256GCM -j '{}'
	[ "${status}" -ne 0 ]
}

ECENC="${SRCDIR}/tests/keys/ec_key_prime256v1_enc.json"

@test "JWE Flattened JSON round-trip (auto-detect on decrypt)" {
	tok="$(./tools/jwe-encrypt -k ${OCT256B} -a A256KW -e A256GCM \
		-f json-flat -j '{"d":4}')"
	# The JSON serialization is a JSON object.
	[ "${tok:0:1}" = '{' ]
	result="$(echo "${tok}" | ./tools/jwe-decrypt -k ${OCT256B} -a A256KW \
		-e A256GCM)"
	[ "${result}" = '{"d":4}' ]
}

@test "JWE General JSON round-trip" {
	tok="$(./tools/jwe-encrypt -k ${OCT256B} -a A256KW -e A256GCM \
		-f json-general -j '{"e":5}')"
	echo "${tok}" | grep -q '"recipients"'
	result="$(echo "${tok}" | ./tools/jwe-decrypt -k ${OCT256B} -a A256KW \
		-e A256GCM)"
	[ "${result}" = '{"e":5}' ]
}

@test "JWE --aad round-trips and is authenticated" {
	aadf="${BATS_TMPDIR:-/tmp}/jwe_aad_$$"
	printf 'extra authenticated data' > "${aadf}"
	tok="$(./tools/jwe-encrypt -k ${OCT256B} -a A256KW -e A256GCM \
		-f json-flat -A "${aadf}" -j '{"f":6}')"
	rm -f "${aadf}"
	echo "${tok}" | grep -q '"aad"'
	result="$(echo "${tok}" | ./tools/jwe-decrypt -k ${OCT256B} -a A256KW \
		-e A256GCM)"
	[ "${result}" = '{"f":6}' ]
}

@test "JWE multi-recipient: each recipient's key decrypts" {
	tok="$(./tools/jwe-encrypt -k ${OCT256B} -a A256KW -e A256GCM \
		-r RSA-OAEP-256:${RSAENC} -r ECDH-ES+A128KW:${ECENC} \
		-j '{"g":7}')"
	echo "${tok}" | grep -q '"recipients"'

	r1="$(echo "${tok}" | ./tools/jwe-decrypt -k ${OCT256B} -a A256KW \
		-e A256GCM)"
	[ "${r1}" = '{"g":7}' ]
	r2="$(echo "${tok}" | ./tools/jwe-decrypt -k ${RSAENC} -a RSA-OAEP-256 \
		-e A256GCM)"
	[ "${r2}" = '{"g":7}' ]
	r3="$(echo "${tok}" | ./tools/jwe-decrypt -k ${ECENC} \
		-a ECDH-ES+A128KW -e A256GCM)"
	[ "${r3}" = '{"g":7}' ]
}

@test "JWE encrypt rejects unknown format" {
	run ./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -f bogus -j '{}'
	[ "${status}" -ne 0 ]
}

@test "JWE encrypt rejects malformed --recipient" {
	run ./tools/jwe-encrypt -k ${OCT256B} -a A256KW -e A256GCM \
		-r noColonHere -j '{}'
	[ "${status}" -ne 0 ]
}

# #364: the tools must release what they allocated on their error exits too, so
# the suite is clean under LeakSanitizer. These exercise the jwe tools' key-load
# error paths (a missing file, an empty key set, a bad --recipient spec).
@test "jwe-encrypt reports a missing key file" {
	run ./tools/jwe-encrypt -k /nonexistent/key.json -a dir -e A256GCM -j '{}'
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Could not load key"
	refute_sanitizer
}

@test "jwe-encrypt reports an empty key set" {
	empty="${BATS_TMPDIR:-/tmp}/jwe_empty_$$.json"
	echo '{"keys":[]}' > "${empty}"
	run ./tools/jwe-encrypt -k "${empty}" -a dir -e A256GCM -j '{}'
	rm -f "${empty}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "No key found"
	refute_sanitizer
}

@test "jwe-encrypt rejects a malformed --recipient" {
	run ./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM \
		-r no-colon-here -j '{}'
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "recipient must be ALG:FILE"
	refute_sanitizer
}

@test "jwe-decrypt reports a missing key file" {
	run ./tools/jwe-decrypt -k /nonexistent/key.json -a dir -e A256GCM x.y.z
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Could not load key"
	refute_sanitizer
}

@test "jwe-decrypt reports an empty key set" {
	empty="${BATS_TMPDIR:-/tmp}/jwe_empty_$$.json"
	echo '{"keys":[]}' > "${empty}"
	run ./tools/jwe-decrypt -k "${empty}" -a dir -e A256GCM x.y.z
	rm -f "${empty}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "No key found"
	refute_sanitizer
}

# #364: jwt-verify allocates its checker only after option parsing, and every
# key/keyring load error returns (not exit()) so the auto_t cleanups run. These
# drive those error exits so the suite stays leak-clean under LeakSanitizer.
@test "jwt-verify reports an unreadable key file" {
	run ./tools/jwt-verify -k /nonexistent/key.json ${BASIC_RES}
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Could not read JWK"
	refute_sanitizer
}

@test "jwt-verify reports an unreadable keyring" {
	run ./tools/jwt-verify -r /nonexistent/ring.json ${BASIC_RES}
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Could not read keyring"
	refute_sanitizer
}

@test "jwt-verify rejects an algorithm that mismatches the key" {
	run ./tools/jwt-verify -a ES256 -k ${HS256_KEY} ${BASIC_RES}
	[ "${status}" -ne 0 ]
	refute_sanitizer
}

@test "jwt-verify reports a malformed key" {
	badkey="${BATS_TMPDIR:-/tmp}/badjwk_$$.json"
	printf '{"kty":"RSA","n":"@@@","e":"AQAB"}\n' > "${badkey}"
	run ./tools/jwt-verify -k "${badkey}" ${BASIC_RES}
	rm -f "${badkey}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Could not read JWK"
	refute_sanitizer
}

@test "jwt-verify needs an algorithm for a key that has none" {
	run ./tools/jwt-verify -k ${NOALG_KEY} ${BASIC_RES}
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "does not contain an"
	refute_sanitizer
}

# issue #354: a keyring (-r) verify failure surfaces the SAME specific
# per-signature reason the single-key path (-k) gives, not just the generic
# "Signature policy not met" count. Here the ring holds a different HS256
# secret, so the HMAC does not match.
WRONG_KEY="${SRCDIR}/tests/keys/oct_key_256_issue1.json"

@test "jwt-verify keyring failure reports the specific reason (#354)" {
	token="$(./tools/jwt-generate -q -n -k ${HS256_KEY})"
	# The single-key path already named the reason...
	run ./tools/jwt-verify -k ${WRONG_KEY} "${token}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Token failed verification"
	refute_sanitizer
	# ...and now the keyring path names the same reason, not the count.
	run ./tools/jwt-verify -r ${WRONG_KEY} "${token}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Token failed verification"
	! echo "${output}" | grep -q "Signature policy not met"
	refute_sanitizer
}

# #364: jwt-generate allocates its builder only after option parsing and routes
# every error through a single cleanup label, so these error exits are leak-free
# under LeakSanitizer.
@test "jwt-generate error exits are leak-clean" {
	# A --claim with no key:value:value structure.
	run ./tools/jwt-generate -q -n -c nocolonhere
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Invalid claim format"
	refute_sanitizer
	# A --claim with an unknown type letter.
	run ./tools/jwt-generate -q -n -c x:key=val
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q "Invalid --claim type"
	refute_sanitizer
	# A key file that does not exist.
	run ./tools/jwt-generate -q -n -a HS256 -k /nonexistent/key.json
	[ "${status}" -ne 0 ]
	refute_sanitizer
	# A key file that parses but whose key is malformed.
	badkey="${BATS_TMPDIR:-/tmp}/gen_badjwk_$$.json"
	printf '{"kty":"RSA","n":"@@@","e":"AQAB"}\n' > "${badkey}"
	run ./tools/jwt-generate -q -n -k "${badkey}"
	rm -f "${badkey}"
	[ "${status}" -ne 0 ]
	refute_sanitizer
	# A key with no "alg" and no --algorithm.
	run ./tools/jwt-generate -q -n -k ${NOALG_KEY}
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q 'No .alg. attribute'
	refute_sanitizer
	# An --algorithm that mismatches the key.
	run ./tools/jwt-generate -q -n -a ES256 -k ${HS256_KEY}
	[ "${status}" -ne 0 ]
	refute_sanitizer
	# An invalid JSON body.
	run ./tools/jwt-generate -q -n -a HS256 -k ${HS256_KEY} -j 'notjson'
	[ "${status}" -ne 0 ]
	refute_sanitizer
}

@test "jwt-generate accepts a true boolean claim" {
	run ./tools/jwt-generate -q -n -a HS256 -k ${HS256_KEY} -c b:flag=true
	[ "${status}" -eq 0 ]
	refute_sanitizer
}

@test "jwt-generate rejects too many --claim options" {
	args=""
	for n in $(seq 1 33); do args="${args} -c s:k${n}=v${n}"; done
	run ./tools/jwt-generate -q -n -a HS256 -k ${HS256_KEY} ${args}
	[ "${status}" -ne 0 ]
	refute_sanitizer
}

# Regression for #264: an oct JWK with a very large `k` makes the key
# bit-length (len_k * 8) an 8+ digit number. jwk2key formatted it into a
# fixed 8-byte buffer (char bits[8]) with an unbounded sprintf, overflowing
# the stack. The decoded `k` here is ~1.3 MB, so bits = 10500000 (8 digits)
# and overflowed bits[8].
#
# A crash is not a reliable signal (the overflow lands in adjacent stack
# memory and often doesn't fault), so instead assert the *observable*
# outcome: with the fix, bits is safely truncated and a correctly named
# oct_1050000_<thumbprint>.bin is written (the JWK has no "kid", so jwk2key
# names it by thumbprint). Without the fix, the overflow corrupts the output
# path and that file is never created.
@test "jwk2key handles oversized oct key without buffer overflow (#264)" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key264_$$"
	mkdir -p "${dir}"
	jwk="${dir}/big.json"
	# 1.75 MB of base64url 'A's decodes to ~1.3 MB -> bits = 10500000,
	# truncated to 1050000 (7 digits) once snprintf bounds the write.
	k="$(head -c 1750000 /dev/zero | tr '\0' 'A')"
	printf '{"kty":"oct","k":"%s"}' "${k}" > "${jwk}"

	run ./tools/jwk2key -d "${dir}" "${jwk}"

	status_was="${status}"
	have_out=0
	ls "${dir}"/oct_1050000_*.bin >/dev/null 2>&1 && have_out=1
	rm -rf "${dir}"

	# Must not crash (128+signal) and must produce the correctly named file.
	[ "${status_was}" -lt 128 ]
	[ "${have_out}" -eq 1 ]
}

# --- jwk2key exit status and error reporting (#374) ----------------------
#
# jwk2key used to exit 0 even when nothing was written: a bad input file, a key
# that did not load, a skipped key, a missing/unwritable output directory, an
# existing output file or a failed write all passed silently. It now exits 1
# and names each key it could not write, and never passes a NULL PEM to
# fputs() (which crashes on glibc). Each case works in its own ${BATS_TMPDIR}
# directory with keys from ${SRCDIR}/tests/keys (#367).

@test "jwk2key exits 1 on a missing input file" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_miss_$$"
	mkdir -p "${dir}"
	run ./tools/jwk2key -d "${dir}" "${dir}/nosuch.json"
	nfiles=$(ls "${dir}" | wc -l)
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "Error reading"
	[ "${nfiles}" -eq 0 ]
	refute_sanitizer
}

@test "jwk2key exits 1 on an input that is not JSON" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_njson_$$"
	mkdir -p "${dir}"
	printf 'not json\n' > "${dir}/notjson.json"
	run ./tools/jwk2key -d "${dir}" "${dir}/notjson.json"
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "Error reading"
	refute_sanitizer
}

@test "jwk2key exits 1 when every key is bad and names each one" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_bad_$$"
	mkdir -p "${dir}"
	run ./tools/jwk2key -d "${dir}" ${SRCDIR}/tests/keys/bad_keys.json
	nfiles=$(ls "${dir}" | wc -l)
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	[ "${nfiles}" -eq 0 ]
	# bad_keys.json holds 14 keys; every one is reported.
	[ "$(echo "${output}" | grep -c 'key [0-9]')" -eq 14 ]
	refute_sanitizer
}

@test "jwk2key writes the good key, reports the bad one, exits 1" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_mix_$$"
	mkdir -p "${dir}"
	# One good RSA key and one EC key that cannot load (bogus x/y).
	jq -c '{keys: [., {kty:"EC",crv:"P-256",x:"AA",y:"AA"}]}' \
		${SRCDIR}/tests/keys/rsa_key_1024.json > "${dir}/mixed.json"
	run ./tools/jwk2key -d "${dir}" "${dir}/mixed.json"
	have_good=0
	ls "${dir}"/rsa_1024_*.pem >/dev/null 2>&1 && have_good=1
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	[ "${have_good}" -eq 1 ]
	# The second key (index 1) is the one reported.
	echo "${output}" | grep -q "key 1"
	refute_sanitizer
}

@test "jwk2key exits 1 on a key set with no keys" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_empty_$$"
	mkdir -p "${dir}"
	echo '{"keys":[]}' > "${dir}/empty.json"
	run ./tools/jwk2key -d "${dir}" "${dir}/empty.json"
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "No keys found"
	refute_sanitizer
}

@test "jwk2key exits 1 on a missing output directory" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_nodir_$$"
	rm -rf "${dir}"
	run ./tools/jwk2key -d "${dir}" ${SRCDIR}/tests/keys/rsa_key_1024.json
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "not an existing writable directory"
	refute_sanitizer
}

@test "jwk2key exits 1 on an output path that is not a directory" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_notdir_$$"
	mkdir -p "${dir}"
	# A regular file is not a writable directory, so -d must reject it.
	printf '' > "${dir}/afile"
	run ./tools/jwk2key -d "${dir}/afile" ${SRCDIR}/tests/keys/rsa_key_1024.json
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "not an existing writable directory"
	refute_sanitizer
}

@test "jwk2key exits 1 on a read-only output directory" {
	[ "$(id -u)" -ne 0 ] || skip "root can write to a read-only directory"
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_ro_$$"
	mkdir -p "${dir}"
	chmod 555 "${dir}"
	run ./tools/jwk2key -d "${dir}" ${SRCDIR}/tests/keys/rsa_key_1024.json
	chmod 755 "${dir}"
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "not an existing writable directory"
	refute_sanitizer
}

@test "jwk2key exits 1 when the output file already exists" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_exists_$$"
	mkdir -p "${dir}"
	./tools/jwk2key -d "${dir}" ${SRCDIR}/tests/keys/rsa_key_1024.json
	run ./tools/jwk2key -d "${dir}" ${SRCDIR}/tests/keys/rsa_key_1024.json
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "cannot create"
	refute_sanitizer
}

@test "jwk2key exits 1 and writes nothing for an unsafe kid" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_unsafe_$$"
	mkdir -p "${dir}"
	printf '{"kty":"oct","kid":"../x","k":"%s"}' \
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > "${dir}/unsafe.json"
	run ./tools/jwk2key -d "${dir}" "${dir}/unsafe.json"
	# Only the input file is left; no key file escaped the directory.
	nfiles=$(ls "${dir}" | wc -l)
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q "unsafe key id"
	[ "${nfiles}" -eq 1 ]
	refute_sanitizer
}

@test "jwk2key reports only the failed file and still writes the good one" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_isolate_$$"
	mkdir -p "${dir}"
	run ./tools/jwk2key -d "${dir}" "${dir}/nosuch.json" \
		${SRCDIR}/tests/keys/rsa_key_1024.json
	have_good=0
	ls "${dir}"/rsa_1024_*.pem >/dev/null 2>&1 && have_good=1
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	[ "${have_good}" -eq 1 ]
	# The good file's load is not reported with the missing file's error:
	# exactly one "Error reading" line.
	[ "$(echo "${output}" | grep -c 'Error reading')" -eq 1 ]
	refute_sanitizer
}

@test "jwk2key exits 1 on a failed write and leaves no file behind" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_wfail_$$"
	mkdir -p "${dir}"
	# RLIMIT_FSIZE 0 with SIGXFSZ ignored makes the write fail; bats captures
	# output through a pipe, so only the key file (not the test) is limited.
	run bash -c "trap '' XFSZ; ulimit -f 0; \
		./tools/jwk2key -d '${dir}' ${SRCDIR}/tests/keys/rsa_key_1024.json"
	nfiles=$(ls "${dir}" | wc -l)
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	[ "${nfiles}" -eq 0 ]
	refute_sanitizer
}

@test "jwk2key reads a JWK from stdin with -" {
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_stdin_$$"
	mkdir -p "${dir}"
	run bash -c "./tools/jwk2key -d '${dir}' - \
		< ${SRCDIR}/tests/keys/oct_key_384.json"
	have=0
	ls "${dir}"/oct_384_*.bin >/dev/null 2>&1 && have=1
	rm -rf "${dir}"
	[ "${status}" -eq 0 ]
	[ "${have}" -eq 1 ]
	refute_sanitizer
}

# The existing "Convert JWK to PEM" cases above must still exit 0; add an AKP
# (ML-DSA) conversion when the default backend can export it, so every key-type
# branch of jwk2key is exercised.
@test "jwk2key converts an ML-DSA key and exits 0" {
	mldsa_supported || skip "ML-DSA not built in"
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_akp_$$"
	mkdir -p "${dir}"
	run ./tools/jwk2key -d "${dir}" ${SRCDIR}/tests/keys/mldsa_key_44.json
	have_out=0
	ls "${dir}"/mldsa_44_*.pem >/dev/null 2>&1 && have_out=1
	rm -rf "${dir}"
	[ "${status}" -eq 0 ]
	[ "${have_out}" -eq 1 ]
	refute_sanitizer
}

# With JWT_CRYPTO=mbedtls the OKP/ML-DSA export paths differ: MbedTLS has no PEM
# for an Ed25519 key (a NULL that once reached fputs() and crashed on glibc),
# and it cannot load an ML-DSA key at all. Both must exit 1, not crash, and
# leave no file. Skipped when MbedTLS is not compiled in (it falls back and
# prints "No such crypto ops").
@test "jwk2key under MbedTLS: Ed25519 exits 1 without crashing or a file" {
	env JWT_CRYPTO=mbedtls ./tools/jwk2key -h >/dev/null 2>/tmp/jwk2key_mb_$$ \
		|| true
	if grep -q "No such crypto ops" "/tmp/jwk2key_mb_$$"; then
		rm -f "/tmp/jwk2key_mb_$$"
		skip "MbedTLS backend not built in"
	fi
	rm -f "/tmp/jwk2key_mb_$$"
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_mbed_$$"
	mkdir -p "${dir}"
	run env JWT_CRYPTO=mbedtls ./tools/jwk2key -d "${dir}" \
		${SRCDIR}/tests/keys/eddsa_key_ed25519.json
	nfiles=$(ls "${dir}" | wc -l)
	rm -rf "${dir}"
	# Exit 1 (not 0 as on macOS, not a SIGSEGV 139 as on glibc), no file.
	[ "${status}" -eq 1 ]
	[ "${nfiles}" -eq 0 ]
	echo "${output}" | grep -q "no PEM available"
	refute_sanitizer
}

@test "jwk2key under MbedTLS: an ML-DSA key exits 1 with its error" {
	env JWT_CRYPTO=mbedtls ./tools/jwk2key -h >/dev/null 2>/tmp/jwk2key_mb2_$$ \
		|| true
	if grep -q "No such crypto ops" "/tmp/jwk2key_mb2_$$"; then
		rm -f "/tmp/jwk2key_mb2_$$"
		skip "MbedTLS backend not built in"
	fi
	rm -f "/tmp/jwk2key_mb2_$$"
	dir="${BATS_TMPDIR:-/tmp}/jwk2key_mbed2_$$"
	mkdir -p "${dir}"
	run env JWT_CRYPTO=mbedtls ./tools/jwk2key -d "${dir}" \
		${SRCDIR}/tests/keys/mldsa_key_44.json
	nfiles=$(ls "${dir}" | wc -l)
	rm -rf "${dir}"
	[ "${status}" -eq 1 ]
	[ "${nfiles}" -eq 0 ]
	echo "${output}" | grep -q "key 0"
	refute_sanitizer
}

# --- ML-DSA (FIPS 204 / RFC 9964) ----------------------------------------
#
# These only run when the library was built with WITH_ML_DSA against a capable
# backend (OpenSSL >= 3.5); otherwise jwt-generate does not list the algorithm
# and the tests skip. Fixtures are the committed AKP JWKs under tests/keys.

mldsa_supported() {
	./tools/jwt-generate -l 2>/dev/null | grep -q 'ML-DSA-44'
}

@test "ML-DSA sign and verify (all variants)" {
	mldsa_supported || skip "ML-DSA not built in (needs WITH_ML_DSA + OpenSSL>=3.5)"

	for v in 44 65 87; do
		priv="${SRCDIR}/tests/keys/mldsa_key_${v}.json"
		pub="${SRCDIR}/tests/keys/mldsa_key_${v}_pub.json"
		token="$(./tools/jwt-generate -q -k "${priv}" -c s:sub=alice)"
		[ -n "${token}" ]
		./tools/jwt-verify -k "${pub}" "${token}"
	done
}

@test "ML-DSA cross-variant verification fails" {
	mldsa_supported || skip "ML-DSA not built in"

	token="$(./tools/jwt-generate -q -k ${SRCDIR}/tests/keys/mldsa_key_44.json -c s:sub=bob)"
	[ -n "${token}" ]
	run ./tools/jwt-verify -k ${SRCDIR}/tests/keys/mldsa_key_87_pub.json "${token}"
	[ "${status}" -ne 0 ]
}

@test "key2jwk converts an ML-DSA PEM to an AKP JWK" {
	mldsa_supported || skip "ML-DSA not built in"

	kty=$(./tools/key2jwk -o - \
		${SRCDIR}/tests/keys/mldsa-pem/mldsa_key_65.pem 2>/dev/null \
		| jq -r '.keys[0].kty')
	[ "${kty}" = "AKP" ]
}

# JWS JSON Serialization (multi-signature, RFC 7515 7.2) — issue #308
EC_KEY="${SRCDIR}/tests/keys/ec_key_prime256v1.json"
RS_KEY="${SRCDIR}/tests/keys/rsa_key_2048.json"
JWS_RING="${SRCDIR}/tests/keys/jwks_jws_pair.json"

@test "Generate a Flattened JWS and verify it" {
	token="$(./tools/jwt-generate -q -n -F flat -k ${EC_KEY})"
	[ "${token:0:1}" = "{" ]
	echo "${token}" | jq -e '.protected and .signature and (.signatures | not)'
	./tools/jwt-verify -q -k ${EC_KEY} "${token}"
}

@test "Generate a General multi-signature JWS (RS256 + ES256)" {
	token="$(./tools/jwt-generate -q -n -k ${RS_KEY} -k ${EC_KEY})"
	echo "${token}" | jq -e '.signatures | length == 2'
}

@test "Verify a multi-signature JWS against a keyring (policy any)" {
	token="$(./tools/jwt-generate -q -n -k ${RS_KEY} -k ${EC_KEY})"
	./tools/jwt-verify -q -r ${JWS_RING} -P any "${token}"
}

@test "Verify a multi-signature JWS against a keyring (policy all)" {
	token="$(./tools/jwt-generate -q -n -k ${RS_KEY} -k ${EC_KEY})"
	./tools/jwt-verify -q -r ${JWS_RING} -P all "${token}"
}

@test "Policy all fails when the keyring lacks a signer's key" {
	token="$(./tools/jwt-generate -q -n -k ${RS_KEY} -k ${EC_KEY})"
	# A ring with only the EC key: ES256 verifies, RS256 does not.
	run ./tools/jwt-verify -q -r ${EC_KEY} -P all "${token}"
	[ "${status}" -ne 0 ]
	run ./tools/jwt-verify -q -r ${EC_KEY} -P any "${token}"
	[ "${status}" -eq 0 ]
}

# With a keyring, the ring's keys decide each signature's algorithm: say so,
# rather than "none (from options)", and show the token as a signed one.
@test "Verify against a keyring names the keyring as the alg source" {
	token="$(./tools/jwt-generate -q -n -k ${EC_KEY})"
	run ./tools/jwt-verify -r ${JWS_RING} "${token}"
	[ "${status}" -eq 0 ]
	echo "${output}" | grep '\[ALG\]' | grep -q 'per key (from keyring)'
	[ "$(echo "${output}" | grep -c 'from options')" -eq 0 ]
	# The locked (signed) token icon, not the unlocked one of alg none.
	echo "${output}" | grep '\[TOK\]' | grep -q $'\xF0\x9F\x94\x90'
}

# Tokens read from stdin (one per line) take the same path; the exit status
# is 1 when any of them fails.
@test "Verify tokens from stdin against a keyring" {
	t1="$(./tools/jwt-generate -q -n -k ${EC_KEY})"
	t2="$(./tools/jwt-generate -q -n -k ${RS_KEY})"
	run bash -c "printf '%s\n' '${t1}' x.y.z '${t2}' | \
		./tools/jwt-verify -r ${JWS_RING} -"
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 2 ]
	[ "$(echo "${output}" | grep '\[TOK\]' | \
		grep -c $'\xF0\x9F\x94\x90')" -eq 3 ]
}

@test "--algorithm cannot be used with --keyring" {
	token="$(./tools/jwt-generate -q -n -k ${EC_KEY})"
	for alg in ES256 none; do
		run ./tools/jwt-verify --algorithm=${alg} -r ${JWS_RING} "${token}"
		[ "${status}" -ne 0 ]
		echo "${output}" | grep -q 'cannot be used with --keyring'
	done
}

@test "key and keyring are mutually exclusive" {
	run ./tools/jwt-verify -k ${EC_KEY} -r ${JWS_RING} "x.y.z"
	[ "${status}" -ne 0 ]
}

# GHSA-mhc9-xvg5-qg29: --keyring verifies a Compact token as a one-signature
# JWS (kid binding or a scan of the compatible keys), never as a keyless
# checker that accepts an unsigned token.
KEYRING="${SRCDIR}/tests/keys/jwks_keyring.json"
# {"alg":"none"} . {"sub":"admin","iss":"trusted","aud":"api"} . (unsigned)
NONE_TOK="eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImlzcyI6InRydXN0ZWQiLCJhdWQiOiJhcGkifQ."

@test "Verify a signed Compact token against a keyring" {
	token="$(./tools/jwt-generate -q -n -k ${EC_KEY})"
	[ "${token:0:1}" != "{" ]
	./tools/jwt-verify -q -r ${JWS_RING} -P any "${token}"
	./tools/jwt-verify -q -r ${JWS_RING} -P all "${token}"
	./tools/jwt-verify -v -r ${KEYRING} "${token}"
}

@test "A forged alg none Compact token fails against a keyring" {
	run ./tools/jwt-verify -q -r ${KEYRING} "${NONE_TOK}"
	[ "${status}" -ne 0 ]
	run ./tools/jwt-verify -q -r ${KEYRING} -P all "${NONE_TOK}"
	[ "${status}" -ne 0 ]
	run ./tools/jwt-verify -r ${JWS_RING} "${NONE_TOK}"
	[ "${status}" -ne 0 ]
	echo "${output}" | grep -q 'invalid "alg"'
}

# GHSA-g7xw-4cjw-2247: the exit status is 0 only when every token verified and
# 1 otherwise. It is not the number of failures, which an exit status holds
# modulo 256. A line of stdin is one token whatever its length, never several
# pieces verified one by one, and no token at all is a failure.

# {"alg":"HS256","typ":"JWT"} . {"sub":"admin"} . (not a signature)
FORGED_TOK="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.AAAA"

@test "256 failing tokens as arguments exit 1" {
	# printf repeats its format for each of the 256 arguments, and %.0s
	# prints nothing of them.
	args=($(printf "${FORGED_TOK} %.0s" {1..256}))
	[ "${#args[@]}" -eq 256 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} "${args[@]}"
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} "${args[@]}" ${HS256_RES}
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} "${args[@]}" "${args[@]}"
	[ "${status}" -eq 1 ]
}

@test "256 failing lines on stdin exit 1" {
	toks=($(printf "${FORGED_TOK} %.0s" {1..256}))
	[ "${#toks[@]}" -eq 256 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < <(
		printf '%s\n' "${toks[@]}")
	[ "${status}" -eq 1 ]
}

@test "Mixed tokens exit 1 and all good tokens exit 0" {
	run ./tools/jwt-verify -q -k ${HS256_KEY} ${HS256_RES} ${FORGED_TOK} \
		${HS256_RES}
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} ${FORGED_TOK} ${FORGED_TOK}
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} ${HS256_RES} ${HS256_RES}
	[ "${status}" -eq 0 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < <(
		printf '%s\n' ${HS256_RES} ${FORGED_TOK} ${HS256_RES})
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < <(
		printf '%s\n' ${HS256_RES} ${HS256_RES})
	[ "${status}" -eq 0 ]
}

# The line buffer is 1 MiB, so a line of 1048576 bytes does not fit. It is not
# verified, not even in part, and the lines after it are still read as lines:
# one of 1048575 bytes, which fits and is a token (not a valid one), and a
# good token.
@test "An over-long line on stdin is one failed token" {
	run ./tools/jwt-verify -k ${HS256_KEY} - < <(
		printf '%0*d\n' 1048576 0
		printf '%0*d\n' 1048575 0
		echo "${HS256_RES}")
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c 'Line is too long')" -eq 1 ]
	[ "$(echo "${output}" | grep -c '\[TOK\]')" -eq 2 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 1 ]
}

# A forged token padded to one line of 256 * (BUFSIZ - 1) - 1 bytes was read
# as 256 failing pieces, for an exit status of 0. BUFSIZ is 1024 or 8192,
# depending on the C library, so try both lengths. The first one now fits in
# the line buffer and the second one does not.
@test "A padded forged token on stdin exits 1" {
	for len in 261887 2096895; do
		run ./tools/jwt-verify -q -k ${HS256_KEY} - < <(
			printf '%s%0*d\n' ${FORGED_TOK} \
				$((len - ${#FORGED_TOK})) 0)
		[ "${status}" -eq 1 ]
	done
}

@test "A valid token longer than BUFSIZ verifies from stdin" {
	# With 9000 bytes of claim it is longer than either BUFSIZ.
	token="$(./tools/jwt-generate -q -n -k ${HS256_KEY} \
		-c "s:pad=$(printf '%09000d' 0)")"
	[ "${#token}" -gt 8192 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < <(echo "${token}")
	[ "${status}" -eq 0 ]
	# The last line needs no newline.
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < <(printf '%s' "${token}")
	[ "${status}" -eq 0 ]
}

@test "A line with a NUL byte on stdin is one failed token" {
	# The valid token in front of the NUL byte was verified on its own.
	# With -q the line is not reported, as no token is.
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < <(
		printf '%s\0%s\n' ${HS256_RES} ${FORGED_TOK})
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c '\[BAD\]')" -eq 0 ]
	# Nothing in front of a NUL byte or after it is verified, and a last
	# line of nothing else still counts. The other lines are verified.
	run ./tools/jwt-verify -k ${HS256_KEY} - < <(
		printf '%s\0\n' ${HS256_RES}
		printf '\0%s\n' ${HS256_RES}
		printf '%s\n' ${HS256_RES}
		printf '\0')
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c 'has a NUL byte')" -eq 3 ]
	[ "$(echo "${output}" | grep -c '\[TOK\]')" -eq 1 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 1 ]
}

@test "No token to verify exits 1" {
	# Without a token argument, as before.
	run ./tools/jwt-verify -q -k ${HS256_KEY}
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'No token(s) given'
	# And with nothing to read on stdin, also when the - comes after --.
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < /dev/null
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'No token(s) read from stdin'
	run ./tools/jwt-verify -q -k ${HS256_KEY} -- - < /dev/null
	[ "${status}" -eq 1 ]
	# A read error is not the end of the input either: a directory
	# cannot be read, nor can a stdin that is only open for writing.
	run ./tools/jwt-verify -q -k ${HS256_KEY} - < .
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} - 0> /dev/null
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'Could not read stdin'
}

@test "A - for stdin must be the only token argument" {
	# The token after the - was never verified.
	run ./tools/jwt-verify -q -k ${HS256_KEY} - ${FORGED_TOK} \
		<<< "${HS256_RES}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'must be the only token argument'
}

# Unchanged on purpose: a line of stdin is verified as it is. A carriage
# return or a blank next to a token is not stripped and an empty line is not
# skipped (each is a token that fails), and the last line needs no newline.
@test "A line of stdin is verified as it is" {
	run ./tools/jwt-verify -k ${HS256_KEY} - < <(
		printf '%s\r\n\n %s\n%s' ${HS256_RES} ${HS256_RES} ${HS256_RES})
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c '\[TOK\]')" -eq 4 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 1 ]
}

# #373: read_line() looks at every byte of a line (so a NUL byte or an
# over-long line fails the whole line), which is why it reads a byte at a
# time. The reader was changed from an fgetc() loop to getc_unlocked() under
# one flockfile()/funlockfile() per line -- the per-byte stream lock is most
# of the run time on bulk input on macOS -- and must stay byte-for-byte the
# same. Read a bulk stream of a few thousand lines that crosses the stdio
# buffer many times and mixes valid tokens, an over-long line, a NUL-byte line
# and a final line with no newline: each line is still scored as one token on
# its own. A reader that split a long line or stopped at a NUL byte (the pre-
# fix fgets() behaviour) would miscount these.
@test "Bulk stdin is read one token per line, unchanged (#373)" {
	run ./tools/jwt-verify -k ${HS256_KEY} - < <(
		for _ in $(seq 1 1000); do printf '%s\n' ${HS256_RES}; done
		printf '%0*d\n' 1048576 0                    # over-long: 1 failed token
		printf '%s\0%s\n' ${HS256_RES} ${HS256_RES}  # NUL byte: 1 failed token
		for _ in $(seq 1 1000); do printf '%s\n' ${HS256_RES}; done
		printf '%s' ${HS256_RES})                    # last line needs no newline
	[ "${status}" -eq 1 ]
	# 2000 full lines + 1 final line with no newline, each verified once.
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 2001 ]
	[ "$(echo "${output}" | grep -c '\[TOK\]')" -eq 2001 ]
	# The over-long line and the NUL-byte line, each one failed token, nothing
	# verified from either.
	[ "$(echo "${output}" | grep -c 'Line is too long or has a NUL byte')" -eq 2 ]
}

# GHSA-g7xw-4cjw-2247: -h/-l print and exit 0 only as the sole argument and the
# only option in it. In a token position (getopt permutes argv) they once exited
# 0 while the tokens went unverified; clustered with another option into the one
# argument (getopt reads -hv as -h -v) they likewise exited 0. Given with
# anything else -- a token, a key, or another option, whether separate (-h -v)
# or clustered (-hv) -- they are a usage error.
@test "-h or -l alone exits 0, but with other arguments it is an error" {
	run ./tools/jwt-verify -h
	[ "${status}" -eq 0 ]
	run ./tools/jwt-verify -l
	[ "${status}" -eq 0 ]
	echo "${output}" | grep -q 'Algorithms supported'
	# The long forms, and a unique prefix, are also fine as the sole option.
	run ./tools/jwt-verify --help
	[ "${status}" -eq 0 ]
	run ./tools/jwt-verify --list
	[ "${status}" -eq 0 ]
	echo "${output}" | grep -q 'Algorithms supported'
	run ./tools/jwt-verify --he
	[ "${status}" -eq 0 ]
	# As the token argument, next to a key.
	run ./tools/jwt-verify -q -k ${HS256_KEY} -h
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} -l
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -q -k ${HS256_KEY} --help
	[ "${status}" -eq 1 ]
	# Reordered after a token: the token must not go unverified at exit 0.
	run ./tools/jwt-verify -q -k ${HS256_KEY} ${FORGED_TOK} -h
	[ "${status}" -eq 1 ]
	# A forged token spelled as an option (-l<forged>) is not a listing.
	run ./tools/jwt-verify -q -k ${HS256_KEY} "-l${FORGED_TOK}"
	[ "${status}" -eq 1 ]
	# Clustered into the one argument: -h/-l must be the only option in it, so
	# these are the same usage error as -h -v (exit 1), not a help/list at
	# exit 0. -hk<file> and -hr<file> never open the file.
	for opt in -hv -vh -lq -ql "-hk${HS256_KEY}" -laHS256 -hl; do
		run ./tools/jwt-verify "${opt}"
		[ "${status}" -eq 1 ]
		echo "${output}" | grep -q 'take no other arguments'
	done
}

# GHSA-g7xw-4cjw-2247: a key set with no keys (as after a rotation) must exit 1,
# not dereference a NULL item and crash (SIGSEGV).
@test "A key set with no keys exits 1 and does not crash" {
	empty="${BATS_TMPDIR:-/tmp}/empty_keys_$$.json"
	echo '{"keys":[]}' > "${empty}"
	run ./tools/jwt-verify -k "${empty}" ${HS256_RES}
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'No key found'
	run ./tools/jwt-generate -a HS256 -k "${empty}"
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'No key found'
	refute_sanitizer
	rm -f "${empty}"
}

# The --print command is a validator: a token passes only if the command runs
# to its end and exits 0. One that a signal ends has no exit status, which
# read as 0. Since issue #371 the command need not read its input first: the
# tool ignores SIGPIPE while writing, so a command that stops reading is not
# killed off, and its exit status alone decides.
@test "A --print command that fails or is killed fails the token" {
	run ./tools/jwt-verify -v -p true -k ${HS256_KEY} ${HS256_RES}
	[ "${status}" -eq 0 ]
	run ./tools/jwt-verify -v -p 'exit 3' -k ${HS256_KEY} ${HS256_RES}
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -v -p 'kill -9 $$' -k ${HS256_KEY} ${HS256_RES}
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 0 ]
	run ./tools/jwt-generate -v -p 'kill -9 $$' -a HS256 -k ${HS256_KEY}
	[ "${status}" -ne 0 ]
}

# Issue #371: the JSON is written to the --print command through a pipe, once
# for the header and once for the payload. A payload larger than the pipe
# buffer blocks in write() until the command reads it, and a command that
# stops reading first (true, false, head -c) once killed the tool with SIGPIPE
# (exit 141) in mid-run: the tokens after the big one were never processed and
# buffered output was lost. The tool now ignores SIGPIPE while writing, so a
# stopped reader no longer ends it and the command's exit status decides at any
# size, exactly as for a token that fits the buffer. The 70000-byte claim makes
# the payload exceed the 64 KiB pipe buffer; a good token sits before and after
# the big one to prove the run is not cut short.
BIG_CLAIM="s:pad=$(printf '%070000d' 0)"

@test "A --print command surviving a payload larger than the pipe buffer (#371)" {
	big="$(./tools/jwt-generate -q -n -k ${HS256_KEY} -c "${BIG_CLAIM}")"
	[ "$(printf '%s' "${big}" | wc -c)" -gt 65536 ]
	# -p true reads nothing and exits 0: all three tokens pass, none lost.
	run ./tools/jwt-verify -v -p true -k ${HS256_KEY} \
		${HS256_RES} "${big}" ${HS256_RES}
	[ "${status}" -eq 0 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 3 ]
	# -p false reads nothing and exits 1: every token fails, with a [BAD].
	run ./tools/jwt-verify -v -p false -k ${HS256_KEY} \
		${HS256_RES} "${big}" ${HS256_RES}
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c '\[BAD\]')" -eq 3 ]
	# The same through stdin, one token per line.
	run bash -c "printf '%s\n' ${HS256_RES} '${big}' ${HS256_RES} | \
		./tools/jwt-verify -v -p true -k ${HS256_KEY} -"
	[ "${status}" -eq 0 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 3 ]
	run bash -c "printf '%s\n' ${HS256_RES} '${big}' ${HS256_RES} | \
		./tools/jwt-verify -v -p false -k ${HS256_KEY} -"
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c '\[BAD\]')" -eq 3 ]
	# jwt-generate shares write_json(): -p true passes, -p false fails.
	run ./tools/jwt-generate -v -p true -n -k ${HS256_KEY} -c "${BIG_CLAIM}"
	[ "${status}" -eq 0 ]
	run ./tools/jwt-generate -v -p false -n -k ${HS256_KEY} -c "${BIG_CLAIM}"
	[ "${status}" -eq 1 ]
	refute_sanitizer
}

# GHSA-g7xw-4cjw-2247: --print runs its validator only with --verbose. Without
# -v the validator was silently skipped and the token passed on its signature
# alone; it is now a usage error.
@test "--print without --verbose is a usage error" {
	run ./tools/jwt-verify -k ${HS256_KEY} -p false ${HS256_RES}
	[ "${status}" -eq 1 ]
	echo "${output}" | grep -q 'requires --verbose'
	run ./tools/jwt-verify -q -k ${HS256_KEY} -p false ${HS256_RES}
	[ "${status}" -eq 1 ]
	# With -v the validator runs, and its non-zero status fails the token.
	run ./tools/jwt-verify -v -k ${HS256_KEY} -p false ${HS256_RES}
	[ "${status}" -eq 1 ]
}

# GHSA-g7xw-4cjw-2247: a forged token whose header "alg" carries a CR and escape
# sequences once painted a fake green "[YES] ... Verified" line over its own
# "[BAD]" line (the error message echoes the alg). Control bytes are now escaped,
# so the real verified marker (with ESC bytes) never appears for a failed token.
# VERIFIED is that exact success sequence.
VERIFIED=$'\033[0;92m[YES]\033[0m Verified'
# header {"alg":"\r\e[2K<thumbsup> \e[0;92m[YES]\e[0m Verified\e[8m"}.{"sub":"admin"}.AAAA
SPOOF_TOK="eyJhbGciOiAiXHJcdTAwMWJbMktcdWQ4M2RcdWRjNGQgXHUwMDFiWzA7OTJtW1lFU11cdTAwMWJbMG0gVmVyaWZpZWRcdTAwMWJbOG0ifQ.eyJzdWIiOiJhZG1pbiJ9.AAAA"

@test "A forged token cannot paint a fake verified line" {
	# An honest token prints the real green verified marker (the control).
	run ./tools/jwt-verify -k ${HS256_KEY} ${HS256_RES}
	[ "${status}" -eq 0 ]
	[ "$(printf '%s' "${output}" | grep -Fc "${VERIFIED}")" -eq 1 ]
	# The forged token fails and cannot produce that marker, as an argument...
	run ./tools/jwt-verify -k ${HS256_KEY} "${SPOOF_TOK}"
	[ "${status}" -eq 1 ]
	[ "$(printf '%s' "${output}" | grep -Fc "${VERIFIED}")" -eq 0 ]
	# ...nor through stdin.
	run ./tools/jwt-verify -k ${HS256_KEY} - <<< "${SPOOF_TOK}"
	[ "${status}" -eq 1 ]
	[ "$(printf '%s' "${output}" | grep -Fc "${VERIFIED}")" -eq 0 ]
}

# jwt-verify shows text from a token (the [TOK] line, a [BAD] message that
# quotes its "alg", the --verbose dump) through one escaper, which jwt-generate
# shares for its dump: a byte below 0x20, DEL, a byte that does not start
# well-formed UTF-8 and both bytes of a C1 control (U+0080 to U+009F, encoded
# C2 80 to C2 9F) are shown as \xNN. Printable ASCII and all other well-formed
# UTF-8 are shown as they are. The output is matched with LC_ALL=C grep -a, as
# it holds bytes from 0x80 up.
#
# MIXED_TOK is 57 bytes, so the [TOK] line shows all of it (it shortens a
# token longer than 60): ESC, TAB, DEL, the C1 controls U+009B and U+009F (C2
# 9B, C2 9F), a lone 9B, then U+00A0 (C2 A0), e-acute (C3 A9), the euro sign
# (E2 82 AC) and an emoji (F0 9F 98 80). Then malformed UTF-8, each case read
# from its first byte (after a "|", or after a whole character): C0 AF, E0 80
# 80 and F0 8F BF BF (overlong forms), ED A0 80 (a surrogate), F4 90 80 80
# (above U+10FFFF), F5 80 80 80 (no lead byte above F4), a lone 80, E2
# followed by "A", E2 followed by e-acute, the emoji with "A" for its last
# byte, and E2 82 cut off at the end.
MIXED_TOK=$'\033\t\x7f\xc2\x9b\xc2\x9f\x9b'
MIXED_TOK+=$'\xc2\xa0\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80'
MIXED_TOK+=$'\xc0\xaf|\xe0\x80\x80|\xf0\x8f\xbf\xbf|\xed\xa0\x80|'
MIXED_TOK+=$'\xf4\x90\x80\x80|\xf5\x80\x80\x80|\x80'
MIXED_TOK+=$'\xe2A\xe2\xc3\xa9\xf0\x9f\x98A\xe2\x82'
# What the [TOK] line shows of it: the valid characters that are not controls
# (C2 A0, C3 A9, E2 82 AC and F0 9F 98 80) as they are, every other byte below
# 0x20 or from 0x7f up as \xNN, and each byte of a malformed case on its own,
# so what follows it ("A", e-acute) as it is.
MIXED_SHOWN='\x1b\x09\x7f\xc2\x9b\xc2\x9f\x9b'
MIXED_SHOWN+=$'\xc2\xa0\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80'
MIXED_SHOWN+='\xc0\xaf|\xe0\x80\x80|\xf0\x8f\xbf\xbf|\xed\xa0\x80|'
MIXED_SHOWN+='\xf4\x90\x80\x80|\xf5\x80\x80\x80|\x80'
MIXED_SHOWN+='\xe2A\xe2'$'\xc3\xa9''\xf0\x9f\x98A\xe2\x82'
# How a [TOK] line starts for a token checked without a key.
TOK_NOKEY=$'\xf0\x9f\x94\x93 \033[0;93m[TOK]\033[0m '

@test "The [TOK] line escapes control bytes and malformed UTF-8 only" {
	[ "$(printf '%s' "${MIXED_TOK}" | wc -c)" -eq 57 ]
	run ./tools/jwt-verify "${MIXED_TOK}"
	[ "${status}" -eq 1 ]
	[ "$(printf '%s\n' "${output}" | LC_ALL=C grep -a '\[TOK\]')" = \
		"${TOK_NOKEY}${MIXED_SHOWN}" ]
	run ./tools/jwt-verify - <<< "${MIXED_TOK}"
	[ "${status}" -eq 1 ]
	[ "$(printf '%s\n' "${output}" | LC_ALL=C grep -a '\[TOK\]')" = \
		"${TOK_NOKEY}${MIXED_SHOWN}" ]
}

# Both sides of each edge of the UTF-8 ranges (RFC 3629). EDGE_TOK is well
# formed and shown as it is: U+07FF (DF BF), U+0800 (E0 A0 80), U+D7FF (ED 9F
# BF), U+E000 (EE 80 80), U+FFFD (EF BF BD), U+10000 (F0 90 80 80), U+40000
# (F1 80 80 80) and U+10FFFF (F4 8F BF BF), but for U+0080 (C2 80), the first
# C1 control, shown as \xNN. PAST_TOK is just past the edges, so each of its
# bytes is shown as \xNN: C1 BF and E0 9F BF (overlong forms of U+007F and
# U+07FF), then E2 with 7F or C0 (just outside 80-BF) as its second or third
# byte. MIXED_TOK has the other side of the ED, F0 and F4 edges, F5, and C2 9F
# and C2 A0 at the top of the C1 controls.
EDGE_TOK=$'\xc2\x80\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf\xee\x80\x80'
EDGE_TOK+=$'\xef\xbf\xbd\xf0\x90\x80\x80\xf1\x80\x80\x80\xf4\x8f\xbf\xbf'
EDGE_SHOWN='\xc2\x80'$'\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf\xee\x80\x80'
EDGE_SHOWN+=$'\xef\xbf\xbd\xf0\x90\x80\x80\xf1\x80\x80\x80\xf4\x8f\xbf\xbf'
PAST_TOK=$'\xc1\xbf|\xe0\x9f\xbf|\xe2\x7f\x80|'
PAST_TOK+=$'\xe2\xc0\x80|\xe2\x80\x7f|\xe2\x80\xc0'
PAST_SHOWN='\xc1\xbf|\xe0\x9f\xbf|\xe2\x7f\x80|'
PAST_SHOWN+='\xe2\xc0\x80|\xe2\x80\x7f|\xe2\x80\xc0'

@test "The [TOK] line keeps UTF-8 at the edges of each range, not past them" {
	run ./tools/jwt-verify "${EDGE_TOK}"
	[ "${status}" -eq 1 ]
	[ "$(printf '%s\n' "${output}" | LC_ALL=C grep -a '\[TOK\]')" = \
		"${TOK_NOKEY}${EDGE_SHOWN}" ]
	run ./tools/jwt-verify "${PAST_TOK}"
	[ "${status}" -eq 1 ]
	[ "$(printf '%s\n' "${output}" | LC_ALL=C grep -a '\[TOK\]')" = \
		"${TOK_NOKEY}${PAST_SHOWN}" ]
}

# A token longer than 60 bytes is shown as its first 28 bytes, "..." and its
# last 28. Each part is escaped on its own and no byte past it is read, so a
# character the cut splits is shown as \xNN on both sides. Here the first part
# ends in the first byte of a euro sign (E2 82 AC), the last part starts with
# the last two bytes of another one and ends in a whole third one.
@test "A character split where the [TOK] line is shortened is escaped" {
	a27="$(printf 'a%.0s' {1..27})"
	c23="$(printf 'c%.0s' {1..23})"
	euro=$'\xe2\x82\xac'
	tok="${a27}${euro}mmmm${euro}${c23}${euro}"
	[ "$(printf '%s' "${tok}" | wc -c)" -eq 63 ]
	run ./tools/jwt-verify "${tok}"
	[ "${status}" -eq 1 ]
	[ "$(printf '%s\n' "${output}" | LC_ALL=C grep -a '\[TOK\]')" = \
		"${TOK_NOKEY}${a27}"'\xe2...\x82\xac'"${c23}${euro}" ]
}

# {"alg":"<U+009B as C2 9B>"} . {} . (no signature)
C1_ALG_TOK="eyJhbGciOiLCmyJ9.e30."

@test "The [BAD] line escapes a C1 control quoted from the alg" {
	run ./tools/jwt-verify -k ${HS256_KEY} "${C1_ALG_TOK}"
	[ "${status}" -eq 1 ]
	printf '%s\n' "${output}" | LC_ALL=C grep -a '\[BAD\]' |
		LC_ALL=C grep -aqF '[\xc2\x9b]'
	[ "$(printf '%s\n' "${output}" | LC_ALL=C grep -acF $'\xc2\x9b')" -eq 0 ]
}

# A string claim of U+009B (C2 9B), DEL and e-acute (C3 A9), which the JSON
# encoders leave as they are, and the way the dump shows it.
C1_CLAIM=$'\xc2\x9b\x7f\xc3\xa9'
C1_SHOWN='"note": "\xc2\x9b\x7f'$'\xc3\xa9''"'

# Check the --verbose output in ${output} for a token whose payload holds only
# the claim "note". Jansson spreads a dump over indented lines and json-c
# prints it on one, so the line of the claim must be Jansson's indented member
# line or json-c's whole payload dump in its colour codes. Each of the two
# dumps (header and payload) starts with its colour code and ends its own
# line with the reset, so the [PAYLOAD] title has a line to itself. No line
# break or tab of a dump is shown as \xNN.
check_note_dump() {
	local line

	line="$(printf '%s\n' "${output}" | LC_ALL=C grep -aF '"note": ')"
	[ "${line}" = "    ${C1_SHOWN}" ] ||
		[ "${line}" = $'\033[0;96m{'"${C1_SHOWN}"$'}\033[0m' ]
	[ "$(printf '%s\n' "${output}" |
		LC_ALL=C grep -acF $'\xc2\x9b')" -eq 0 ]
	[ "$(printf '%s\n' "${output}" | LC_ALL=C grep -acF $'\x7f')" -eq 0 ]
	[ "$(printf '%s\n' "${output}" |
		LC_ALL=C grep -acF -e '\x0a' -e '\x09')" -eq 0 ]
	[ "$(printf '%s\n' "${output}" |
		LC_ALL=C grep -acF $'\033[0;96m{')" -eq 2 ]
	[ "$(printf '%s\n' "${output}" |
		LC_ALL=C grep -acF $'}\033[0m')" -eq 2 ]
	[ "$(printf '%s\n' "${output}" |
		LC_ALL=C grep -acxF $'\033[0;95m[PAYLOAD]\033[0m')" -eq 1 ]
}

@test "The --verbose dump escapes control bytes and keeps its layout" {
	tok="$(./tools/jwt-generate -q -n -k ${HS256_KEY} -c "s:note=${C1_CLAIM}")"
	run ./tools/jwt-verify -v -k ${HS256_KEY} "${tok}"
	[ "${status}" -eq 0 ]
	check_note_dump
	# jwt-generate prints the same dump, on stderr.
	run ./tools/jwt-generate -v -n -k ${HS256_KEY} -c "s:note=${C1_CLAIM}"
	[ "${status}" -eq 0 ]
	check_note_dump
}

# The command of --print is given the JSON as it is, not the shown text. It is
# run once for the header and once for the payload.
@test "--print gets the JSON unescaped" {
	raw="${BATS_TMPDIR:-/tmp}/print_raw_$$.json"
	tok="$(./tools/jwt-generate -q -n -k ${HS256_KEY} -c "s:note=${C1_CLAIM}")"
	rm -f "${raw}"
	run ./tools/jwt-verify -v -p "cat >> '${raw}'" -k ${HS256_KEY} "${tok}"
	[ "${status}" -eq 0 ]
	[ "$(LC_ALL=C grep -acF "${C1_CLAIM}" "${raw}")" -eq 1 ]
	[ "$(LC_ALL=C grep -acF '\x' "${raw}")" -eq 0 ]
	rm -f "${raw}"
	run ./tools/jwt-generate -v -n -p "cat >> '${raw}'" -k ${HS256_KEY} \
		-c "s:note=${C1_CLAIM}"
	[ "${status}" -eq 0 ]
	[ "$(LC_ALL=C grep -acF "${C1_CLAIM}" "${raw}")" -eq 1 ]
	[ "$(LC_ALL=C grep -acF '\x' "${raw}")" -eq 0 ]
	rm -f "${raw}"
}
