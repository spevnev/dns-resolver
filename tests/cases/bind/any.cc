#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// any A 1.1.1.1
/// any A 2.2.2.2
/// any TXT result

int main() {
    Resolver resolver{UNSIGNED_RESOLVER_CONFIG};
    auto response = resolver.resolve("any." UNSIGNED_DOMAIN, RRType::ANY);
    ASSERT(response.has_value());

    auto &rrset = response.value();
    ASSERT(rrset.size() == 3);

    bool found1 = false;
    bool found2 = false;
    bool found3 = false;
    for (auto &rr : rrset) {
        if (rr.type == RRType::A) {
            auto address = std::get<A>(rr.data).address;
            if (address == get_ip4("1.1.1.1")) found1 = true;
            if (address == get_ip4("2.2.2.2")) found2 = true;
        } else if (rr.type == RRType::TXT) {
            auto &txt = std::get<TXT>(rr.data);
            if (txt.strings.size() == 1 && txt.strings[0] == "result") found3 = true;
        }
    }
    ASSERT(found1 && found2 && found3);

    return EXIT_SUCCESS;
}
