// test_decode.c
//
// build it with this command:
//  gcc -o test_decode -I../include -ljansson -lcrypto -lssl test_decode.c ../libjwt/.libs/libjwt.a
//
// tests:
//  ./test_decode test_password jwt.txt
//  ./test_decode -f pubkey.pem jwt5.txt
//

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <jwt.h>

int open_input_file (const char *fname)
{
  int fd = open(fname, O_RDONLY);
  if (fd<0)
  {
    printf ("File %s open error\n", fname);
    exit(1);
  }
  return fd;
} 

ssize_t read_file (const char *fname, char *buf, size_t buflen)
{
  ssize_t nbytes;
  int fd = open_input_file(fname);
  nbytes = read(fd, buf, buflen);
  if (nbytes < 0)
  {
    printf ("Read file %s error\n", fname);
    close(fd);
    exit(2);
  }
  close(fd);
  printf ("%d bytes read\n", nbytes);
  return nbytes;
}

int main(int argc, char *argv[])
{
  const char *jwt_fname;
  const char *key_str;
  int key_len;
  ssize_t jwt_bytes;
  int result;
  jwt_t *jwt;
  unsigned char jwt_buf[65535];
  unsigned char pem_buf[8192];

	if (argc == 2) {
		key_str = NULL;
		key_len = 0;
		jwt_fname = argv[1];
	} else {

		if(argc < 3) {
	    printf ("Usage:\n");
	    printf (" ./test_decode test_password jwt.txt\n");
	    printf ("or\n");
	    printf (" ./test_decode -f pubkey.pem jwt.txt\n");
	    exit(1);
		}
	  key_str = argv[1];
	  key_len = strlen (key_str);
	  jwt_fname = argv[2];
	  if (argc >= 4) {
	    jwt_fname = argv[3];
	    if ((key_len == 2) && (key_str[0] == '-') && (key_str[1] == 'f')) {
	      key_len = read_file (argv[2], pem_buf, sizeof(pem_buf));
	      if (key_len >= 0) {
	        key_str = pem_buf;
	      } else {
	        printf ("Error reading pem file\n");
	        exit(1);
	      }
	    } else {
	      printf ("Invalid option\n");
	      exit(1);
	    }
	  }
	}

  jwt_bytes = read_file (jwt_fname, jwt_buf, sizeof(jwt_buf));

  result = jwt_decode (&jwt, (const char*) jwt_buf, key_str, key_len);

  if (result)
    printf ("jwt_decode error %d\n", result);
  exit(result);
}

