#include <cstdlib>
#include <memory>
#include <print>
#include <string>
#include "dns.hh"
#include "resolve.hh"

#define CXXOPTS_NO_REGEX
#include <cxxopts.hpp>

// NOLINTNEXTLINE
std::istream &operator>>(std::istream &is, RRType &out) {
    std::string str;
    is >> str;
    for (auto &ch : str) ch = std::toupper(ch);

    // NOLINTBEGIN
    if (str == "A") out = RRType::A;
    else if (str == "NS") out = RRType::NS;
    else if (str == "CNAME") out = RRType::CNAME;
    else if (str == "SOA") out = RRType::SOA;
    else if (str == "HINFO") out = RRType::HINFO;
    else if (str == "TXT") out = RRType::TXT;
    else if (str == "AAAA") out = RRType::AAAA;
    else if (str == "DS") out = RRType::DS;
    else if (str == "NSEC") out = RRType::NSEC;
    else if (str == "DNSKEY") out = RRType::DNSKEY;
    else if (str == "NSEC3") out = RRType::NSEC3;
    else if (str == "ANY") out = RRType::ANY;
    else is.setstate(std::ios::failbit);
    // NOLINTEND

    return is;
}

// NOLINTNEXTLINE
std::istream &operator>>(std::istream &is, FeatureState &out) {
    std::string str;
    is >> str;
    for (auto &ch : str) ch = std::tolower(ch);

    if (str == "on" || str == "true" || str == "enable") {
        out = FeatureState::Enable;
    } else if (str == "off" || str == "false" || str == "disable") {
        out = FeatureState::Disable;
    } else if (str == "require") {
        out = FeatureState::Require;
    } else {
        is.setstate(std::ios::failbit);
    }

    return is;
}

int main(int argc, char **argv) {
    try {
        cxxopts::Options options{"resolver", "CLI DNS resolver"};
        options.custom_help("[options]");
        options.positional_help("<domain>");

        options.add_options()                                                                        //
            ("domain", "Domain name to resolve", cxxopts::value<std::string>())                      //
            ("h,help", "Print usage", cxxopts::value<bool>()->default_value("false"))                //
            ("s,server", "Nameserver domain or address", cxxopts::value<std::string>())              //
            ("p,port", "Nameserver port", cxxopts::value<uint16_t>()->default_value("53"))           //
            ("t,type", "Query type", cxxopts::value<RRType>()->default_value("A"))                   //
            ("T,timeout", "Timeout in seconds", cxxopts::value<uint64_t>()->default_value("5"))      //
            ("v,verbose", "Verbose output", cxxopts::value<bool>()->default_value("false"))          //
            ("rdflag", "Set recursion desired flag", cxxopts::value<bool>()->default_value("true"))  //
            ("edns", "EDNS", cxxopts::value<FeatureState>()->default_value("on"))                    //
            ("dnssec", "DNSSEC", cxxopts::value<FeatureState>()->default_value("on"))                //
            ("cookies", "Cookies", cxxopts::value<FeatureState>()->default_value("on"))              //
            ("use-root", "Use root nameservers", cxxopts::value<bool>()->default_value("true"))      //
            ("use-config", "Use nameservers from /etc/resolv.conf", cxxopts::value<bool>()->default_value("true"));
        options.parse_positional({"domain"});

        auto result = options.parse(argc, argv);
        if (result.contains("help")) {
            std::print("{}", options.help());
            return EXIT_SUCCESS;
        }

        if (!result.unmatched().empty()) {
            std::println(stderr, "Unmatched arguments: {}", result.unmatched());
            return EXIT_FAILURE;
        }

        Resolver resolver{{
            .timeout_ms = result["timeout"].as<uint64_t>() * 1000,
            .nameserver = result["server"].as_optional<std::string>(),
            .use_root_nameservers = result["use-root"].as<bool>(),
            .use_resolve_config = result["use-config"].as<bool>(),
            .port = result["port"].as<uint16_t>(),
            .verbose = result["verbose"].as<bool>(),
            .enable_rd = result["rdflag"].as<bool>(),
            .edns = result["edns"].as<FeatureState>(),
            .dnssec = result["dnssec"].as<FeatureState>(),
            .cookies = result["cookies"].as<FeatureState>(),
        }};

        auto opt_rrset = resolver.resolve(result["domain"].as<std::string>(), result["type"].as<RRType>());
        if (!opt_rrset.has_value()) {
            std::println(stderr, "Failed to resolve the domain.");
            return EXIT_FAILURE;
        }

        const auto &rrset = opt_rrset.value();
        if (rrset.empty()) {
            std::println("Domain name does not exist.");
        } else {
            std::println("Answer:");
            for (const auto &rr : rrset) std::println("{}", rr);
        }

        return EXIT_SUCCESS;
    } catch (const cxxopts::exceptions::exception &e) {
        std::println(stderr, "{}", e.what());
        return EXIT_FAILURE;
    }
}
