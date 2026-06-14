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

@test "Convert JWK to PEM - RSA" {
	rm -f rsa_1024_0023a6e1-f093-448d-9038-9ff168611b86.pem
	./tools/jwk2key -d . ${SRCDIR}/tests/keys/rsa_key_1024.json
	cmp rsa_1024_0023a6e1-f093-448d-9038-9ff168611b86.pem ${SRCDIR}/tests/keys/pem-files/rsa_key_1024.pem
}

@test "Convert JWK to PEM - OCT" {
	rm -f oct_384.bin
	./tools/jwk2key -d . ${SRCDIR}/tests/keys/oct_key_384.json
	cmp oct_384.bin ${SRCDIR}/tests/cli/oct_384.bin
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

# Regression for #264: an oct JWK with a very large `k` makes the key
# bit-length (len_k * 8) an 8+ digit number. jwk2key formatted it into a
# fixed 8-byte buffer (char bits[8]) with an unbounded sprintf, overflowing
# the stack. The decoded `k` here is ~1.3 MB, so bits = 10500000 (8 digits)
# and overflowed bits[8].
#
# A crash is not a reliable signal (the overflow lands in adjacent stack
# memory and often doesn't fault), so instead assert the *observable*
# outcome: with the fix, bits is safely truncated and a correctly named
# oct_1050000.bin is written. Without the fix, the overflow corrupts the
# output path and that file is never created.
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
	[ -f "${dir}/oct_1050000.bin" ] && have_out=1
	rm -rf "${dir}"

	# Must not crash (128+signal) and must produce the correctly named file.
	[ "${status_was}" -lt 128 ]
	[ "${have_out}" -eq 1 ]
}
