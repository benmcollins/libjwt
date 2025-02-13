#!/bin/bash

if command -v jq > /dev/null; then
	JQ="--print=jq -C"
fi

KEY=jwt-test-key.bin
JWK=jwk-test-key.json

if [ ! -e "${KEY}" ]; then
	echo Creating 512 bit binary random key
	dd if=/dev/urandom bs=1 count=64 "of=${KEY}"
fi

if [ ! -e "$JWK" ]; then
	echo Converting key to JWK
	key2jwk -o "${JWK}" "${KEY}"
	if [ -n "$JQ" ]; then
		cat "${JWK}" | jq -C
	else
		cat "${JWK}"
	fi
fi

TOKEN=jwt-test-token

EXP="$(date -d '+7 days' +%s)"


echo Generating token
jwt-generate -k "${JWK}"		\
	-c s:group=staff		\
	-c b:admin=false		\
	-c s:iss=disk.swissdisk.com	\
	-c s:user=bcollins		\
	-c i:exp=${EXP} > ${TOKEN}

echo Verifying token
cat ${TOKEN} | jwt-verify -k "${JWK}" "${JQ}" -v -
