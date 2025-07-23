#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    /// invalid.ttl 2147483648 A 1.2.3.4
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("invalid.ttl." TEST_DOMAIN, RRType::A);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);
    ASSERT(rrset[0].ttl == 0);

    return EXIT_SUCCESS;
}
