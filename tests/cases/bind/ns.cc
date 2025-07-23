#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve(TEST_DOMAIN, RRType::NS);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 2);
    ASSERT(rrset[0].type == RRType::NS);
    ASSERT(rrset[1].type == RRType::NS);

    return EXIT_SUCCESS;
}
