#!/usr/bin/env bats

BASIC_RES="eyJhbGciOiJub25lIn0.e30."

@test "Generate a JWT with alg none" {
	result="$(./tools/jwt-generate -v -a none -n)"
	[ "$result" = ${BASIC_RES} ]
}

@test "Verify a JWT with alg none" {
	./tools/jwt-verify -v ${BASIC_RES}
}

HS256_RES="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds"
HS256_KEY="../tests/keys/oct_key_256.json"

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

# A key without an "alg" needs -a/--algorithm, and both spellings must work.
NOALG_KEY="../tests/keys/oct_key_256_sig.json"

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

OCT256="../tests/keys/oct_dir_256.json"
OCT256B="../tests/keys/oct_key_256_enc.json"
RSAENC="../tests/keys/rsa_key_2048_enc.json"

@test "JWE dir + A256GCM round-trip" {
	tok="$(./tools/jwe-encrypt -k ${OCT256} -a dir -e A256GCM -j '{"a":1}')"
	result="$(echo "${tok}" | ./tools/jwe-decrypt -k ${OCT256} -a dir -e A256GCM)"
	[ "${result}" = '{"a":1}' ]
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

@test "JWE encrypt rejects unknown algorithm" {
	run ./tools/jwe-encrypt -k ${OCT256} -a BOGUS -e A256GCM -j '{}'
	[ "${status}" -ne 0 ]
}

ECENC="../tests/keys/ec_key_prime256v1_enc.json"

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
EC_KEY="../tests/keys/ec_key_prime256v1.json"
RS_KEY="../tests/keys/rsa_key_2048.json"
JWS_RING="../tests/keys/jwks_jws_pair.json"

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
KEYRING="../tests/keys/jwks_keyring.json"
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

# GHSA-g7xw-4cjw-2247: -h/-l print and exit 0 only as the sole argument. In a
# token position (getopt permutes argv) they once exited 0 while the tokens
# went unverified. Given with anything else they are now a usage error.
@test "-h or -l alone exits 0, but with other arguments it is an error" {
	run ./tools/jwt-verify -h
	[ "${status}" -eq 0 ]
	run ./tools/jwt-verify -l
	[ "${status}" -eq 0 ]
	echo "${output}" | grep -q 'Algorithms supported'
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
	rm -f "${empty}"
}

# The --print command is a validator: a token passes only if the command runs
# to its end and exits 0. One that a signal ends has no exit status, which
# read as 0. Each command reads its input first, so that the tool never
# writes to a pipe nobody reads.
@test "A --print command that fails or is killed fails the token" {
	run ./tools/jwt-verify -v -p 'cat > /dev/null' -k ${HS256_KEY} \
		${HS256_RES}
	[ "${status}" -eq 0 ]
	run ./tools/jwt-verify -v -p 'cat > /dev/null; exit 3' \
		-k ${HS256_KEY} ${HS256_RES}
	[ "${status}" -eq 1 ]
	run ./tools/jwt-verify -v -p 'cat > /dev/null; kill -9 $$' \
		-k ${HS256_KEY} ${HS256_RES}
	[ "${status}" -eq 1 ]
	[ "$(echo "${output}" | grep -c 'Verified')" -eq 0 ]
	run ./tools/jwt-generate -v -p 'cat > /dev/null; kill -9 $$' \
		-a HS256 -k ${HS256_KEY}
	[ "${status}" -ne 0 ]
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
