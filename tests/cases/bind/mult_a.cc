#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    /// mult.a A 1.1.1.1
    /// mult.a A 2.2.2.2
    /// mult.a A 3.3.3.3
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("mult.a." TEST_DOMAIN, RRType::A);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 3);

    bool found1 = false, found2 = false, found3 = false;
    for (auto &rr : rrset) {
        ASSERT(rr.type == RRType::A);
        auto address = std::get<A>(rr.data).address;
        if (address == get_ip4("1.1.1.1")) found1 = true;
        if (address == get_ip4("2.2.2.2")) found2 = true;
        if (address == get_ip4("3.3.3.3")) found3 = true;
    }
    ASSERT(found1 && found2 && found3);

    return EXIT_SUCCESS;
}
