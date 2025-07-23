#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    auto config = TEST_RESOLVER_CONFIG;
    config.timeout_ms = 500;
    config.nameserver = "127.0.0.2";
    config.port = 65535;

    Resolver resolver{config};
    auto opt_rrset = resolver.resolve(TEST_DOMAIN, RRType::A);
    ASSERT(!opt_rrset.has_value());

    return EXIT_SUCCESS;
}
