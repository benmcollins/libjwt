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
		${SRCDIR}/tests/keys/pem-files/*.bin | grep -v  libjwt.io: > output.json
	cmp output.json ${SRCDIR}/tests/cli/all.json
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
