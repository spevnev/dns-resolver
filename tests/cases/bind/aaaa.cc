#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    /// aaaa AAAA 1:2:3:4::
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("aaaa." TEST_DOMAIN, RRType::AAAA);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);

    auto &rr = rrset[0];
    ASSERT(rr.type == RRType::AAAA);
    ASSERT(ip6_equals(std::get<AAAA>(rr.data).address, "1:2:3:4::"));

    return EXIT_SUCCESS;
}
