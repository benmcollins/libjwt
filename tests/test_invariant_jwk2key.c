#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

START_TEST(test_jwk2key_buffer_safety)
{
    // Invariant: jwk2key must not overflow buffers when processing adversarial JWK input
    const char *payloads[] = {
        "{\"kty\":\"RSA\",\"n\":\"" "A" "\",\"e\":\"AQAB\",\"key_ops\":[\"sign\"]}",
        "{\"kty\":\"oct\",\"k\":\"" "AAAAAAAAAAAAAAAAAAAAAA" "\"}",
        "{\"kty\":\"RSA\",\"n\":\"xGOr-H7A\",\"e\":\"AQAB\"}"
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char tmpfile[] = "/tmp/jwk_test_XXXXXX";
        int fd = mkstemp(tmpfile);
        ck_assert_int_ge(fd, 0);
        
        write(fd, payloads[i], strlen(payloads[i]));
        close(fd);

        pid_t pid = fork();
        if (pid == 0) {
            freopen("/dev/null", "w", stdout);
            freopen("/dev/null", "w", stderr);
            execl("./jwk2key", "jwk2key", tmpfile, NULL);
            exit(127);
        } else {
            int status;
            waitpid(pid, &status, 0);
            
            // Invariant: process must not crash (segfault/abort indicate buffer overflow)
            ck_assert_msg(!WIFSIGNALED(status) || 
                         (WTERMSIG(status) != SIGSEGV && WTERMSIG(status) != SIGABRT),
                         "jwk2key crashed on payload %d (signal %d)", i, 
                         WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        }
        
        unlink(tmpfile);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_jwk2key_buffer_safety);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}