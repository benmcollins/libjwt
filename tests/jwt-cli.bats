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

@test "key and keyring are mutually exclusive" {
	run ./tools/jwt-verify -k ${EC_KEY} -r ${JWS_RING} "x.y.z"
	[ "${status}" -ne 0 ]
}
