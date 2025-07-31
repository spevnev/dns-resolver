#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main() {
    /// nsec NSEC next (A DS TYPE1000)
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("nsec." TEST_DOMAIN, RRType::NSEC);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);

    auto &rr = rrset[0];
    ASSERT(rr.type == RRType::NSEC);
    auto &nsec = std::get<NSEC>(rr.data);

    ASSERT(nsec.next_domain == "next." TEST_DOMAIN);
    ASSERT(nsec.types.size() == 3);
    ASSERT(nsec.types.contains(RRType::A));
    ASSERT(nsec.types.contains(RRType::DS));
    ASSERT(nsec.types.contains(static_cast<RRType>(1000)));

    return EXIT_SUCCESS;
}
