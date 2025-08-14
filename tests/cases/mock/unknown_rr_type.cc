#include "common.hh"
#include "config.hh"
#include "mock_config.hh"
#include "resolve.hh"

MockResponse mock_response = {
    .answers = {0x4, 0x74, 0x65, 0x73, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0xFF, 0x00,
                0x0, 0x1,  0x0,  0x0,  0x0,  0x0, 0x0,  0x4,  0x1,  0x2, 0x3,  0x4},
    .answers_count = 1,
};

int main() {
    auto unknown_rr_type = static_cast<RRType>(0xFF00);

    Resolver resolver{MOCK_RESOLVER_CONFIG};
    auto response = resolver.resolve(MOCK_DOMAIN, unknown_rr_type);
    ASSERT(response.has_value());

    auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    ASSERT(rrset[0].type == unknown_rr_type);

    return EXIT_SUCCESS;
}
