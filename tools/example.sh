#!/bin/bash

KEY=jwt-test-key.bin
JWK=jwk-test-key.json

if [ ! -e "${KEY}" ]; then
	echo Creating 512 bit binary random key
	dd if=/dev/urandom bs=1 count=64 "of=${KEY}"
fi

if [ ! -e "$JWK" ]; then
	echo Converting key to JWK
	key2jwk -o "${JWK}" "${KEY}"
fi

TOKEN=jwt-test-token

echo Generating token
jwt-generate -k "${JWK}"		\
	-c s:group=staff		\
	-c b:admin=false		\
	-c s:iss=disk.swissdisk.com	\
	-c s:user=bcollins		\
	-c i:exp=1768402249 > ${TOKEN}

if command -v jq > /dev/null; then
	JQ="--print=jq -C"
fi

echo Verifying token
cat ${TOKEN} | jwt-verify -k "${JWK}" "${JQ}" -v -
