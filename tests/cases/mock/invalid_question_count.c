#include "common.h"
#include "config.h"
#include "mock_config.h"
#include "resolve.h"

MockResponse mock_response = {
    .questions = (const uint8_t[]) {0},
    .questions_length = 0,
    .questions_count = 3,
};

int main(void) {
    RRVec result = {0};
    bool found = resolve(&result, TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, RESOLVE_NO_ROOT_NS);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
