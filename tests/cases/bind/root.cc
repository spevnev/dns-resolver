#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main() {
    Resolver resolver{{.nameserver = "1.1.1.1", .dnssec = FeatureState::Disable, .cookies = FeatureState::Disable}};
    auto opt_rrset = resolver.resolve(".", RRType::NS);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 13);

    for (auto &rr : rrset) {
        ASSERT(rr.type == RRType::NS);
        ASSERT(std::get<NS>(rr.data).domain.ends_with(".root-servers.net."));
    }

    return EXIT_SUCCESS;
}
