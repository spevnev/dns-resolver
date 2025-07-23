#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    /// cname CNAME result.cname
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("cname." TEST_DOMAIN, RRType::CNAME);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);

    auto &rr = rrset[0];
    ASSERT(rr.type == RRType::CNAME);
    ASSERT(std::get<CNAME>(rr.data).domain == "result.cname." TEST_DOMAIN);

    return EXIT_SUCCESS;
}
