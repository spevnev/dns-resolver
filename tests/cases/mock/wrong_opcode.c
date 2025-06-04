#include "common.h"
#include "config.h"
#include "mock_config.h"
#include "resolve.h"

#define OPCODE_IQUERY 1

MockResponse mock_response = {
    .opcode = OPCODE_IQUERY,
};

int main(void) {
    RRVec result = {0};
    bool found = resolve(TEST_DOMAIN, TYPE_A, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
