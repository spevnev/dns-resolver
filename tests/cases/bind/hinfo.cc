#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main() {
    /// hinfo HINFO cpu os
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("hinfo." TEST_DOMAIN, RRType::HINFO);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);

    auto &rr = rrset[0];
    ASSERT(rr.type == RRType::HINFO);
    auto &hinfo = std::get<HINFO>(rr.data);

    ASSERT(hinfo.cpu == "cpu");
    ASSERT(hinfo.os == "os");

    return EXIT_SUCCESS;
}
