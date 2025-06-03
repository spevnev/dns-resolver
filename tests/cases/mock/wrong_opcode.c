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
    bool found = resolve(TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, RESOLVE_NO_ROOT_NS, &result);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
