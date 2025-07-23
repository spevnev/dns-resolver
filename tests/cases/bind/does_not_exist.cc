#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("does.not.exist." TEST_DOMAIN, RRType::A);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.empty());

    return EXIT_SUCCESS;
}
