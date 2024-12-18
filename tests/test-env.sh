if [ "$TEST" = "jwt_new" ]; then
	export JWT_CRYPTO=openssl
elif [ "$TEST" = "jwt_dump" ]; then
	export JWT_CRYPTO=NONEXISTENT
fi
