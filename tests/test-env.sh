if [ "$TEST" = "jwt_new" ]; then
	export JWT_CRYPTO=openssl
elif [ "$TEST" = "jwt_flipflop" ]; then
	export JWT_CRYPTO=NONEXISTENT
fi
