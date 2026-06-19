/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jwt_tests.h"

/* @rfc{7517} Cached remote JWKS source: TTL, Cache-Control/ETag conditional
 * refresh (304), kid-miss refresh + cooldown, and the http(s) SSRF guard
 * (issue #313). Only meaningful with libcurl; a tiny in-process HTTP server
 * serves the JWKS with caching headers and counts requests. */

#ifdef HAVE_LIBCURL
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* A minimal one-key JWKS the test server returns. */
static const char JWKS_BODY[] =
	"{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
	"\"x\":\"Y--DdSpCZ5oF3j__h-SdNJIwvB5aI4AXzpRErGUjWrM\","
	"\"y\":\"_bSTCXlDeU-pZZbOKDUVLANspSIeuKZfTM8rtXFG_RU\"}]}";

static struct {
	int listen_fd;
	int port;
	int requests;		/* total GETs served			*/
	int conditional;	/* GETs that carried If-None-Match	*/
	int max_age;		/* Cache-Control: max-age to advertise	*/
	int fail;		/* when set, respond 500			*/
	pthread_t thread;
	pthread_mutex_t lock;
	volatile int stop;
} srv;

static void *server_thread(void *arg)
{
	(void)arg;

	for (;;) {
		char req[4096];
		int fd = accept(srv.listen_fd, NULL, NULL);
		ssize_t n;
		int cond;

		if (fd < 0)
			break;	/* listen socket closed -> shut down */

		n = read(fd, req, sizeof(req) - 1);
		if (n <= 0) {
			close(fd);
			continue;
		}
		req[n] = '\0';

		cond = (strstr(req, "If-None-Match: \"v1\"") != NULL);

		pthread_mutex_lock(&srv.lock);
		srv.requests++;
		if (cond)
			srv.conditional++;
		pthread_mutex_unlock(&srv.lock);

		/* Consume write()'s result (glibc marks it warn_unused_result, and a
		 * (void) cast does not suppress that under -Werror). We do NOT assert
		 * it: a test client may legitimately hang up early, and this runs on a
		 * worker thread where a failing ck_assert would longjmp across threads. */
		if (srv.fail) {
			const char *e = "HTTP/1.1 500 Internal Server Error\r\n"
					"Content-Length: 0\r\n\r\n";
			ssize_t w = write(fd, e, strlen(e));
			(void)w;
		} else if (cond) {
			char hdr[256];
			int hlen = snprintf(hdr, sizeof(hdr),
				"HTTP/1.1 304 Not Modified\r\n"
				"ETag: \"v1\"\r\n"
				"Cache-Control: max-age=%d\r\n"
				"\r\n", srv.max_age);
			ssize_t w = write(fd, hdr, hlen);
			(void)w;
		} else {
			char hdr[256];
			int hlen = snprintf(hdr, sizeof(hdr),
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: application/json\r\n"
				"ETag: \"v1\"\r\n"
				"Cache-Control: max-age=%d\r\n"
				"Content-Length: %zu\r\n"
				"\r\n", srv.max_age, strlen(JWKS_BODY));
			ssize_t wh = write(fd, hdr, hlen);
			ssize_t wb = write(fd, JWKS_BODY, strlen(JWKS_BODY));
			(void)wh;
			(void)wb;
		}

		close(fd);
	}

	return NULL;
}

static int server_start(void)
{
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);

	memset(&srv, 0, sizeof(srv));
	pthread_mutex_init(&srv.lock, NULL);

	srv.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv.listen_fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;	/* ephemeral */

	if (bind(srv.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(srv.listen_fd, 8) ||
	    getsockname(srv.listen_fd, (struct sockaddr *)&addr, &alen))
		return -1;

	srv.port = ntohs(addr.sin_port);

	return pthread_create(&srv.thread, NULL, server_thread, NULL);
}

static void server_stop(void)
{
	shutdown(srv.listen_fd, SHUT_RDWR);
	close(srv.listen_fd);
	pthread_join(srv.thread, NULL);
	pthread_mutex_destroy(&srv.lock);
}

static int req_count(void)
{
	int n;

	pthread_mutex_lock(&srv.lock);
	n = srv.requests;
	pthread_mutex_unlock(&srv.lock);

	return n;
}

static void req_reset(void)
{
	pthread_mutex_lock(&srv.lock);
	srv.requests = 0;
	srv.conditional = 0;
	pthread_mutex_unlock(&srv.lock);
}

static char *make_url(void)
{
	char *url = NULL;

	ck_assert_int_gt(asprintf(&url, "http://127.0.0.1:%d/jwks", srv.port), 0);

	return url;
}

/* A second call within the TTL is served from cache: no new request. */
START_TEST(test_cache_hit)
{
	jwk_set_t *set = NULL;
	jwks_url_config_t cfg = { .verify = 0, .ttl = 0, .cooldown = 2 };
	char *url = make_url();

	srv.max_age = 300;	/* fresh well past the test duration */
	req_reset();

	set = jwks_load_fromurl_cached(NULL, url, &cfg);
	ck_assert_int_eq(req_count(), 1);
	ck_assert_int_gt(jwks_item_count(set), 0);

	jwks_load_fromurl_cached(set, url, &cfg);
	jwks_load_fromurl_cached(set, url, &cfg);
	ck_assert_int_eq(req_count(), 1);	/* still cached */

	jwks_free(set);
	free(url);
}
END_TEST

/* TTL cache hit; stale -> conditional GET (304) keeps the keys. */
START_TEST(test_cache_ttl)
{
	jwk_set_t *set = NULL;
	jwks_url_config_t cfg = { .verify = 0, .ttl = 1, .cooldown = 2 };
	char *url = make_url();

	srv.max_age = 1;
	req_reset();

	/* First call fetches; one request. */
	set = jwks_load_fromurl_cached(NULL, url, &cfg);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_eq(jwks_error(set), 0);
	ck_assert_int_gt(jwks_item_count(set), 0);
	ck_assert_int_eq(req_count(), 1);

	/* After TTL (max-age=1): a conditional GET; the 304 keeps the keys. */
	sleep(2);
	jwks_load_fromurl_cached(set, url, &cfg);
	ck_assert_int_eq(req_count(), 2);
	ck_assert_int_eq(srv.conditional, 1);
	ck_assert_int_gt(jwks_item_count(set), 0);
	ck_assert_int_eq(jwks_error(set), 0);

	jwks_free(set);
	free(url);
}
END_TEST

/* A kid-miss refresh is bounded by the cooldown. */
START_TEST(test_cooldown)
{
	jwk_set_t *set = NULL;
	jwks_url_config_t cfg = { .verify = 0, .ttl = 100, .cooldown = 2 };
	char *url = make_url();

	srv.max_age = 300;
	req_reset();

	set = jwks_load_fromurl_cached(NULL, url, &cfg);
	ck_assert_int_eq(req_count(), 1);

	/* Immediately forcing a refresh is within the cooldown: no request. */
	jwks_refresh_fromurl(set);
	ck_assert_int_eq(req_count(), 1);

	/* After the cooldown elapses, a forced refresh does fetch. */
	sleep(2);
	jwks_refresh_fromurl(set);
	ck_assert_int_eq(req_count(), 2);

	jwks_free(set);
	free(url);
}
END_TEST

/* On an HTTP error during refresh, the previously cached keys are retained
 * (a transient 5xx must not wipe a good cache). */
START_TEST(test_refresh_keeps_keys_on_error)
{
	jwk_set_t *set = NULL;
	jwks_url_config_t cfg = { .verify = 0, .ttl = 100, .cooldown = 0 };
	char *url = make_url();
	int n;

	srv.max_age = 300;
	srv.fail = 0;
	req_reset();

	set = jwks_load_fromurl_cached(NULL, url, &cfg);
	n = (int)jwks_item_count(set);
	ck_assert_int_gt(n, 0);

	/* The origin now errors; a forced refresh must keep the cached keys. */
	srv.fail = 1;
	jwks_refresh_fromurl(set);
	ck_assert_int_ne(jwks_error(set), 0);
	ck_assert_int_eq((int)jwks_item_count(set), n);
	srv.fail = 0;

	jwks_free(set);
	free(url);
}
END_TEST

/* Only http(s) is accepted; file:// is rejected (SSRF guard). */
START_TEST(test_scheme_guard)
{
	jwk_set_t *set = NULL;

	set = jwks_load_fromurl_cached(NULL, "file:///etc/passwd", NULL);
	ck_assert_ptr_nonnull(set);
	ck_assert_int_ne(jwks_error(set), 0);
	ck_assert_int_eq(jwks_item_count(set), 0);

	jwks_free(set);
}
END_TEST

#else  /* !HAVE_LIBCURL */

START_TEST(test_no_libcurl)
{
	ck_assert_ptr_null(jwks_load_fromurl_cached(NULL, "https://x/", NULL));
}
END_TEST

#endif

static Suite *libjwt_suite(const char *title)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create(title);
	tc_core = tcase_create("jwt_jwks_cache");

#ifdef HAVE_LIBCURL
	tcase_add_test(tc_core, test_cache_hit);
	tcase_add_test(tc_core, test_cache_ttl);
	tcase_add_test(tc_core, test_cooldown);
	tcase_add_test(tc_core, test_refresh_keeps_keys_on_error);
	tcase_add_test(tc_core, test_scheme_guard);
#else
	tcase_add_test(tc_core, test_no_libcurl);
#endif

	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int failed;
	SRunner *sr;

#ifdef HAVE_LIBCURL
	if (server_start() != 0) {
		fprintf(stderr, "could not start the test HTTP server\n");
		return EXIT_FAILURE;
	}
#endif

	sr = srunner_create(libjwt_suite("LibJWT cached remote JWKS (#313)"));
	/* The server thread + request counters live in this process; run the
	 * tests here too (no fork) so they observe the same state. */
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

#ifdef HAVE_LIBCURL
	server_stop();
#endif

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
