/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>

#include <jwt.h>

static void jwt_exit(void)
{
	perror("testjwt:");
	exit(1);
}

int main(int argc, char *argv[])
{
	jwt_t *jwt;

	if (jwt_new(&jwt))
		jwt_exit();

	if (jwt_add_grant(jwt, "iss", "files-v2.cyphre.com"))
		jwt_exit();

	if (jwt_add_grant(jwt, "sub", "user0"))
		jwt_exit();

	if (jwt_add_grant(jwt, "ref", "XXX-111-222-444-666"))
		jwt_exit();

	jwt_dump_fp(jwt, stdout, 1);

	jwt_del_grant(jwt, "ref");

	jwt_dump_fp(jwt, stdout, 0);

	jwt_encode_fp(jwt, stdout);

	jwt_free(jwt);

	exit(0);
}
