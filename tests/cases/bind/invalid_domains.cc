#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("test.com..", RRType::A);
    ASSERT(!opt_rrset.has_value());

    opt_rrset = resolver.resolve("test..com", RRType::A);
    ASSERT(!opt_rrset.has_value());

    opt_rrset = resolver.resolve(".test.com", RRType::A);
    ASSERT(!opt_rrset.has_value());

    opt_rrset = resolver.resolve("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", RRType::A);
    ASSERT(!opt_rrset.has_value());

    return EXIT_SUCCESS;
}
