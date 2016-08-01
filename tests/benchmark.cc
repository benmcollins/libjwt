#include "benchmark/benchmark.h"

#include <string.h>
#include <jwt.h>

static void BM_jwt_new(benchmark::State& state) {
    int result;
    while (state.KeepRunning()){

        jwt_t *jwt = nullptr;
        result = jwt_new(&jwt);

        if ( result != 0 || jwt == nullptr)
            state.SkipWithError("jwt_new error !");
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_jwt_new);

static void BM_jwt__new__add_grant__free(benchmark::State& state) {
    jwt_t *jwt = nullptr;

    while (state.KeepRunning()){
        if ( jwt_new(&jwt) != 0 || jwt == nullptr)
            state.SkipWithError("jwt_new error !");
        if ( jwt_add_grant(jwt, "iss", "test") != 0)
            state.SkipWithError("jwt_add_grant error !");
        jwt_free(jwt);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_jwt__new__add_grant__free);

static void BM_jwt_dup(benchmark::State& state) {
    jwt_t *jwt = nullptr, *jwt_test = nullptr;
    const char *val = nullptr;
    if ( jwt_new(&jwt) != 0 || jwt == nullptr)
        state.SkipWithError("jwt_new error !");
    if ( jwt_add_grant(jwt, "iss", "test") != 0)
        state.SkipWithError("jwt_add_grant error !");

    while (state.KeepRunning()){

        jwt_test = jwt_dup(jwt);

        val = jwt_get_grant(jwt_test, "iss");
        if ( strcmp(val,"test") != 0 )
            state.SkipWithError("jwt_new error !");

    }
    jwt_free(jwt_test);
    jwt_free(jwt);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_jwt_dup);

static void BM_jwt_decode_without_key(benchmark::State& state) {


    const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJmaWxlcy5jeXBo"
        "cmUuY29tIiwic3ViIjoidXNlcjAifQ.";

    jwt_t *jwt = nullptr;

    while (state.KeepRunning()){

        if ( jwt_decode(&jwt, token, nullptr, 0) != 0
            || jwt == nullptr  )
            state.SkipWithError("jwt_decode error !");
        jwt_free(jwt);

    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_jwt_decode_without_key);

static void BM_jwt_decode_hs256(benchmark::State& state) {

    const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3Mi"
        "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
        "Q.dLFbrHVViu1e3VD1yeCd9aaLNed-bfXhSsF0Gh56fBg";

    unsigned char key256[33] = "012345678901234567890123456789XY";
    jwt_t *jwt = nullptr;

    while (state.KeepRunning()){

        if ( jwt_decode(&jwt, token, key256, sizeof(key256) - 1) != 0
            || jwt == nullptr  )
            state.SkipWithError("jwt_decode error !");
        jwt_free(jwt);

    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_jwt_decode_hs256);


static void BM_jwt_decode_hs384(benchmark::State& state) {

    const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
        "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
        "3ViIjoidXNlcjAifQ.xqea3OVgPEMxsCgyikr"
        "R3gGv4H2yqMyXMm7xhOlQWpA-NpT6n2a1d7TD"
        "GgU6LOe4";
    const unsigned char key384[49] = "aaaabbbbccccddddeeeeffffg"
        "ggghhhhiiiijjjjkkkkllll";
    jwt_t *jwt = nullptr;

    while (state.KeepRunning()){

        if ( jwt_decode(&jwt, token, key384, sizeof(key384) - 1) != 0
            || jwt == nullptr  )
            state.SkipWithError("jwt_decode error !");
        jwt_free(jwt);

    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_jwt_decode_hs384);


static void BM_jwt_decode_hs512(benchmark::State& state) {

    const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3Mi"
        "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
        "Q.u-4XQB1xlYV8SgAnKBof8fOWOtfyNtc1ytTlc_vHo0U"
        "lh5uGT238te6kSacnVzBbC6qwzVMT1806oa1Y8_8EOg";
    unsigned char key512[65] = "012345678901234567890123456789XY"
        "012345678901234567890123456789XY";
    jwt_t *jwt = nullptr;

    while (state.KeepRunning()){

        if ( jwt_decode(&jwt, token, key512, sizeof(key512) - 1) != 0
            || jwt == nullptr  )
            state.SkipWithError("jwt_decode error !");
        jwt_free(jwt);

    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_jwt_decode_hs512);

BENCHMARK_MAIN()

