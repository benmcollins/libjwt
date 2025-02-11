#!/usr/bin/env bats

BASIC_RES="eyJhbGciOiJub25lIn0.e30."

@test "Generate a JWT with alg none" {
	result="$(./tools/jwt-generate -a none -q -n)"
	[ "$result" = ${BASIC_RES} ]
}

@test "Verify a JWT with alg none" {
	./tools/jwt-verify -q ${BASIC_RES}
}

HS256_RES="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.CM4dD95Nj0vSfMGtDas432AUW1HAo7feCiAbt5Yjuds"
HS256_KEY="../tests/keys/oct_key_256.json"

@test "Generate a JWT with alg HS256" {
	result="$(./tools/jwt-generate -a HS256 -q -n -k ${HS256_KEY})"
	[ "$result" = ${HS256_RES} ]
}

@test "Verify a JWT with alg HS256" {
	./tools/jwt-verify -q -k ${HS256_KEY} ${HS256_RES}
}

CLAIM_RES="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ZmFsc2UsImV4cCI6MTgzOTMxNzU2MiwiZ3JvdXAiOiJzdGFmZiIsImlzcyI6ImRpc2suc3dpc3NkaXNrLmNvbSIsInVzZXIiOiJiY29sbGlucyJ9.83VR9A9jbQxp6KRq8iXHihIxe9LkAjnMAz3L0GdKlPI"

@test "Generate a JWT with alg HS256 and claims" {
	result="$(./tools/jwt-generate -q -n 	\
		-k ${HS256_KEY}			\
		-c s:group=staff		\
		-c b:admin=false		\
		-c s:iss=disk.swissdisk.com	\
		-c s:user=bcollins		\
		-c i:exp=1839317562)"
	[ "$result" = ${CLAIM_RES} ]
}

@test "Verify a JWT with alg HS256 with claims" {
	./tools/jwt-verify -q -k ${HS256_KEY} ${CLAIM_RES}
}
