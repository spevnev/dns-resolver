#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main() {
    /// ttl 123456 A 1.2.3.4
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("ttl." TEST_DOMAIN, RRType::A);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);
    ASSERT(rrset[0].ttl == 123456);

    return EXIT_SUCCESS;
}
