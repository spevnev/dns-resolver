#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main() {
    /// chain.cname CNAME chain2.cname
    /// chain2.cname CNAME chain1.cname
    /// chain1.cname CNAME result.chain.cname
    /// result.chain.cname A 1.2.3.4
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("chain.cname." TEST_DOMAIN, RRType::A);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);

    auto &rr = rrset[0];
    ASSERT(rr.type == RRType::A);
    ASSERT(std::get<A>(rr.data).address == get_ip4("1.2.3.4"));

    return EXIT_SUCCESS;
}
