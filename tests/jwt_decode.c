/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <check.h>

#include <jwt.h>

typedef struct {
	bool expected;
	const char *jwt_file_name;
	bool is_key_in_file;
	const char *key;
	const char *decode_test_name;
} test_case_t;

test_case_t test_list[] = {
  {true, "jwtn.txt",  false, "", "No Alg claims on on"},
  {true, "jwtnx.txt", false, "", "No Alg claims off on"},
  {true, "jwtny.txt", false, "", "No Alg claims off off"},
  {false, "jwtia.txt", false, "test_passwd1", "HS256 invalid jwt"},
  {false, "jwtib.txt", false, "test_passwd1", "HS256 invalid jwt"},
  {false, "jwtic.txt", false, "test_passwd1", "HS256 invalid jwt"},
  {false, "jwtid.txt", false, "test_passwd1", "HS256 invalid jwt"},
  {false, "jwtie.txt", false, "test_passwd1", "HS256 invalid jwt"},
  {false, "jwtif.txt", false, "test_passwd1", "HS256 invalid jwt"},
  {true, "jwt1.txt", false, "test_passwd1", "HS256 claims on on"},
  {true, "jwt1.txt", false, "test_passwd1", "HS256 claims on on"},
  {false, "jwt1.txt", false, "test_passbad", "HS256 claims on on"}, 
  {true, "jwt2.txt", false, "test_passwd2", "HS384 claims on on"},
  {false, "jwt2.txt", false, "test_passbad", "HS384 claims on on"},
  {true, "jwt3.txt", false, "test_passwd3", "HS512 claims on on"},
  {false, "jwt3.txt", false, "test_passbad", "HS512 claims on on"},
  {true, "jwt4.txt", true, "pubkey4.pem", "RS256 claims on on"},
  {false, "jwt4.txt", true, "badkey4.pem", "RS256 claims on on"},
  {true, "jwt5.txt", true, "pubkey5.pem", "RS384 claims on on"},
  {false, "jwt5.txt", true, "badkey4.pem", "RS384 claims on on"},
  {true, "jwt6.txt", true, "pubkey6.pem", "RS512 claims on on"},
  {false, "jwt6.txt", true, "badkey6.pem", "RS512 claims on on"},
  {true, "jwt1x.txt", false, "test_passwd1", "HS256 claims off on"},
  {false, "jwt1x.txt", false, "test_prasswd1", "HS256 claims off on"},
  {true, "jwt2x.txt", false, "test_passwd2", "HS384 claims off on"},
  {false, "jwt2x.txt", false, "twest_passwd2", "HS384 claims off on"},
  {true, "jwt3x.txt", false, "test_passwd3", "HS512 claims off on"},
  {false, "jwt3x.txt", false, "test_passwd3...", "HS512 claims off on"},
  {true, "jwt4x.txt", true, "pubkey4.pem", "RS256 claims off on"},
  {false, "jwt4x.txt", true, "pubkey5.pem", "RS256 claims off on"},
  {true, "jwt5x.txt", true, "pubkey5.pem", "RS384 claims off on"},
  {false, "jwt5x.txt", true, "badkey5.pem", "RS384 claims off on"},
  {true, "jwt6x.txt", true, "pubkey6.pem", "RS512 claims off on"},
  {false, "jwt6x.txt", true, "badkey6.pem", "RS512 claims off on"},
  {true, "jwt1y.txt", false, "test_passwd1", "HS256 claims off off"},
  {false, "jwt1y.txt", false, "tast_passwd1", "HS256 claims off off"},
  {true, "jwt2y.txt", false, "test_passwd2", "HS384 claims off off"},
  {false, "jwt2y.txt", false, "test..passwd2", "HS384 claims off off"},
  {true, "jwt3y.txt", false, "test_passwd3", "HS512 claims off off"},
  {false, "jwt3y.txt", false, "tteesstt_passwd3", "HS512 claims off off"},
  {true, "jwt4y.txt", true, "pubkey4.pem", "RS256 claims off off"},
  {false, "jwt4y.txt", true, "badkey4.pem", "RS256 claims off off"},
  {true, "jwt5y.txt", true, "pubkey5.pem", "RS384 claims off off"},
  {false, "jwt5y.txt", true, "pubkey6.pem", "RS384 claims off off"},
  {true, "jwt6y.txt", true, "pubkey6.pem", "RS512 claims off off"},
  {false, "jwt6y.txt", true, "pubkey5.pem", "RS512 claims off off"},
  {true, "jwt1l.txt", false, "test_passwd1", "HS256 claims long"},
  {false, "jwt1l.txt", false, "test_keyword1", "HS256 claims long"},
  {true, "jwt2l.txt", false, "test_passwd2", "HS384 claims long"},
  {false, "jwt2l.txt", false, "test_passwd1", "HS384 claims long"},
  {true, "jwt3l.txt", false, "test_passwd3", "HS512 claims long"},
  {false, "jwt3l.txt", false, "passwd3", "HS512 claims long"},
  {true, "jwt4l.txt", true, "pubkey4.pem", "RS256 claims long"},
  {false, "jwt4l.txt", true, "badkey4.pem", "RS256 claims long"},
  {true, "jwt5l.txt", true, "pubkey5.pem", "RS384 claims long"},
  {false, "jwt5l.txt", true, "badkey5.pem", "RS384 claims long"},
  {true, "jwt6l.txt", true, "pubkey6.pem", "RS512 claims long"},
  {false, "jwt6l.txt", true, "badkey6.pem", "RS512 claims long"},
  {true, "jwt2.txt", false, "test_passwd2", "HS384 claims on on"},
  {true, "jwt3.txt", false, "test_passwd3", "HS512 claims on on"}
};

#define _NUM_TEST_CASES ( sizeof(test_list) / sizeof(test_case_t) )

int open_input_file (const char *fname)
{
  int fd = open(fname, O_RDONLY);
  if (fd<0)
  {
    printf ("File %s open error\n", fname);
  }
  return fd;
} 

ssize_t read_file (const char *fname, char *buf, size_t buflen)
{
  ssize_t nbytes;
  int fd = open_input_file(fname);
	if (fd < 0)
		return fd;
  nbytes = read(fd, buf, buflen);
  if (nbytes < 0)
  {
    printf ("Read file %s error\n", fname);
    close(fd);
    return nbytes;
  }
  close(fd);
  printf ("%d bytes read\n", nbytes);
  return nbytes;
}

static unsigned int pass_cnt = 0;
static unsigned int fail_cnt = 0;

START_TEST(test_jwt_decode)
{
  const char *jwt_fname;
  const char *key_str;
	const char *decode_test_name;
	bool expected;
  int key_len;
  ssize_t jwt_bytes;
  int result;
  jwt_t *jwt;
  unsigned char jwt_buf[65535];
  unsigned char pem_buf[8192];

	jwt_fname = test_list[_i].jwt_file_name;
	key_str = test_list[_i].key;
  key_len = strlen (key_str);
	expected = test_list[_i].expected;
	decode_test_name = test_list[_i].decode_test_name;
	if (key_len == 0) {
		key_str = NULL;
	} else if (test_list[_i].is_key_in_file) {
		key_len = read_file (key_str, pem_buf, sizeof(pem_buf));
		if (key_len >= 0) {
			key_str = pem_buf;
		} else {
			printf ("Error reading pem file\n");
			ck_assert (0 == 1);
			fail_cnt += 1;
			return;
		}
	}
	if (expected)
		printf ("\n--- Test %s expected good\n", decode_test_name);
	else
		printf ("\n--- Test %s expected bad\n", decode_test_name);

  jwt_bytes = read_file (jwt_fname, jwt_buf, sizeof(jwt_buf));
	jwt_buf[jwt_bytes] = '\0';
	result = jwt_decode (&jwt, (const char*) jwt_buf, key_str, key_len);
	if (expected == (result==0)) {
		printf ("--- PASSED: %s\n", decode_test_name);
		pass_cnt += 1;
	} else {
		printf ("--- FAILED: %s\n", decode_test_name);
		fail_cnt += 1;
	}
	ck_assert_int_eq(expected, (result==0));
}
END_TEST

Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT Decode");

	tc_core = tcase_create("jwt_decode");

	pass_cnt = 0;
	fail_cnt = 0;
	tcase_add_loop_test(tc_core, test_jwt_decode, 0, _NUM_TEST_CASES);
	printf ("Decode Tests passed %d\n", pass_cnt);
	printf ("Decode Tests failed %d\n", fail_cnt);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = libjwt_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


