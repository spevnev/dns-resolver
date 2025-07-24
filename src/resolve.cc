#include "resolve.hh"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <exception>
#include <fstream>
#include <memory>
#include <optional>
#include <print>
#include <queue>
#include <random>
#include <ratio>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "dns.hh"
#include "dnssec.hh"

static const constexpr uint64_t MIN_UDP_TIMEOUT_MS = 300;
static const constexpr int MAX_QUERY_DEPTH = 20;

// https://www.iana.org/domains/root/servers
static const constexpr char *ROOT_IP[] = {
    "198.41.0.4",    "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10", "192.5.5.241",  "192.112.36.4",
    "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",    "202.12.27.33",
};

// https://data.iana.org/root-anchors/root-anchors.xml
static const DS ROOT_DS[]
    = {{
           .key_tag = 20326,
           .signing_algorithm = SigningAlgorithm::RSASHA256,
           .digest_algorithm = DigestAlgorithm::SHA256,
           .digest = {0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
                      0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D},
           .data = {},
       },
       {
           .key_tag = 38696,
           .signing_algorithm = SigningAlgorithm::RSASHA256,
           .digest_algorithm = DigestAlgorithm::SHA256,
           .digest = {0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
                      0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16},
           .data = {},
       }};

class bad_cookie_error : std::runtime_error {
public:
    bad_cookie_error() : std::runtime_error("Bad server cookie") {}
};

Resolver::Resolver(ResolverConfig config)
    : query_timeout_duration(config.timeout_ms),
      udp_timeout_ms(std::max(config.timeout_ms / 5, MIN_UDP_TIMEOUT_MS)),
      port(config.port),
      verbose(config.verbose),
      enable_rd(config.enable_rd),
      edns(config.edns),
      dnssec(config.dnssec),
      cookies(config.cookies),
      rng(std::chrono::system_clock::now().time_since_epoch().count()) {
    if (edns == FeatureState::Disable) {
        if (dnssec == FeatureState::Require) throw std::runtime_error("DNSSEC requires EDNS to be enabled");
        dnssec = FeatureState::Disable;

        if (cookies == FeatureState::Require) throw std::runtime_error("Cookies require EDNS to be enabled");
        cookies = FeatureState::Disable;
    }
    if (dnssec == FeatureState::Require || cookies == FeatureState::Require) edns = FeatureState::Require;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) throw std::runtime_error("Failed to create UDP socket");

    in_addr_t ip_address;
    if (config.use_root_nameservers) {
        root_zone = new_zone(".");
        for (auto ip : ROOT_IP) {
            if (inet_pton(AF_INET, ip, &ip_address) != 1) throw std::runtime_error("Failed to add root nameservers");
            root_zone->nameservers.emplace_back(ip_address);
        }
        if (dnssec != FeatureState::Disable) root_zone->dss.assign_range(ROOT_DS);
    }

    if (config.use_resolve_config && dnssec != FeatureState::Require) {
        resolve_config_zone = new_zone(".");
        resolve_config_zone->enable_dnssec = false;
        load_resolve_config(*resolve_config_zone);
    }

    if (config.nameserver.has_value()) {
        const auto &address_or_domain = config.nameserver.value();
        if (inet_pton(AF_INET, address_or_domain.c_str(), &ip_address) == 1) {
            if (dnssec != FeatureState::Require) {
                specified_zone = new_zone(".");
                specified_zone->enable_dnssec = false;
                specified_zone->nameservers.emplace_back(ip_address);
            }
        } else {
            specified_zone = new_zone(".");
            specified_zone->nameservers.emplace_back(fully_qualify_domain(address_or_domain));
        }
    }

    if (root_zone == nullptr && resolve_config_zone == nullptr && specified_zone == nullptr) {
        throw std::runtime_error("No nameserver is specified");
    }
}

Resolver::~Resolver() { close(fd); }

std::optional<std::vector<RR>> Resolver::resolve(const std::string &domain, RRType rr_type) {
    try {
        timeout_instant = std::chrono::steady_clock::now() + query_timeout_duration;
        set_socket_timeout(udp_timeout_ms);
        return resolve_rec(fully_qualify_domain(domain), rr_type, 0);
    } catch (const std::exception &e) {
        if (verbose) std::println(stderr, "Failed to resolve the domain: {}", e.what());
        return std::nullopt;
    }
}

std::string Resolver::fully_qualify_domain(const std::string &domain) const {
    std::string fqd;
    fqd.reserve(domain.length() + 1);

    size_t label_index = 0;
    for (size_t i = 0; i < domain.size(); i++) {
        if (domain[i] == '.') {
            if (i == 0 && domain != ".") throw std::runtime_error("Domain starts with a dot");
            if (i > 0 && domain[i - 1] == '.') throw std::runtime_error("Domain has an empty label");
            if (i - label_index > MAX_LABEL_LENGTH) throw std::runtime_error("Label is too long");
            label_index = i + 1;
        }

        fqd.push_back(tolower(domain[i]));
    }
    if (!domain.ends_with('.')) fqd.push_back('.');

    if (fqd.size() > MAX_DOMAIN_LENGTH) throw std::runtime_error("Domain is too long");
    return fqd;
}

int Resolver::count_matching_labels(const std::string &a, const std::string &b) const {
    assert(!a.empty() && !b.empty());

    int count = 0;
    auto a_it = a.crbegin() + 1, b_it = b.crbegin() + 1;
    while (a_it != a.crend() && b_it != b.crend()) {
        if (*a_it != *b_it) return count;
        if (*a_it == '.') count++;
        ++a_it, ++b_it;
    }
    if ((a_it == a.crend() || *a_it == '.') && (b_it == b.crend() || *b_it == '.')) count++;
    return count;
}

void Resolver::set_socket_timeout(uint64_t timeout_ms) const {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||  //
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        throw std::runtime_error{"Failed to set receive/send timeout"};
    }
}

void Resolver::update_timeout() {
    auto time_left = timeout_instant - std::chrono::steady_clock::now();
    auto time_left_ms = std::chrono::duration_cast<std::chrono::duration<uint64_t, std::milli>>(time_left).count();

    if (time_left_ms <= 0) {
        throw std::runtime_error{"Query timed out"};
    } else if (time_left_ms <= udp_timeout_ms) {
        set_socket_timeout(time_left_ms);
    }
}

void Resolver::udp_send(const std::vector<uint8_t> &buffer, struct sockaddr_in address) {
    auto socket_address = reinterpret_cast<struct sockaddr *>(&address);
    auto result = sendto(fd, buffer.data(), buffer.size(), 0, socket_address, sizeof(address));
    update_timeout();
    if (result == -1 && errno == EAGAIN) throw std::runtime_error("Request timed out");
    if (result != static_cast<ssize_t>(buffer.size())) throw std::runtime_error("Failed to send the request");
}

static inline constexpr bool address_equals(struct sockaddr_in a, struct sockaddr_in b) {
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

void Resolver::udp_receive(std::vector<uint8_t> &buffer, struct sockaddr_in request_address) {
    struct sockaddr_in address;
    auto socket_address = reinterpret_cast<struct sockaddr *>(&address);
    socklen_t address_length;
    ssize_t result;
    // Read responses until we find the one from the same address and port as in request.
    do {
        address_length = sizeof(address);
        result = recvfrom(fd, buffer.data(), buffer.size(), 0, socket_address, &address_length);
        update_timeout();
        if (result == -1) {
            if (errno == EAGAIN) {
                throw std::runtime_error("Response timed out");
            } else {
                throw std::runtime_error("Failed to receive the response");
            }
        }
    } while (address_length != sizeof(address) || !address_equals(address, request_address));
    buffer.resize(result);
}

void Resolver::load_resolve_config(Zone &zone) const {
    std::ifstream is{"/etc/resolv.conf"};
    in_addr_t ip_address;
    std::string line;
    while (std::getline(is, line)) {
        auto start_idx = line.find_first_not_of(" \t");
        if (start_idx == std::string::npos) continue;

        if (line.compare(start_idx, 10, "nameserver") != 0) continue;
        start_idx += 10;

        auto address_start_idx = line.find_first_not_of(" \t", start_idx);
        if (address_start_idx == std::string::npos) continue;

        auto address_end_idx = line.find_last_not_of(" \t");
        if (address_end_idx == std::string::npos) continue;

        auto ip_str = line.data() + address_start_idx;
        line[address_end_idx + 1] = '\0';

        if (inet_pton(AF_INET, ip_str, &ip_address) == 1) zone.nameservers.emplace_back(ip_address);
    }

    // If no nameserver entries are present, the default is to use the local nameserver.
    if (zone.nameservers.empty()) {
        auto result = inet_pton(AF_INET, "127.0.0.1", &ip_address);
        assert(result == 1);
        zone.nameservers.emplace_back(ip_address);
    }
}

std::shared_ptr<Zone> Resolver::new_zone(const std::string &domain) const {
    return std::make_shared<Zone>(domain, edns != FeatureState::Disable, dnssec != FeatureState::Disable,
                                  cookies != FeatureState::Disable);
}

std::shared_ptr<Zone> Resolver::find_zone(const std::string &domain) const {
    std::string_view current{domain};
    for (;;) {
        auto zone_it = zones.find(current);
        if (zone_it != zones.cend()) {
            const auto &zone = zone_it->second;
            if (!zone->is_being_resolved) return zone;
        }

        auto next_label_index = current.find('.');
        if (next_label_index == current.length() - 1) return nullptr;
        current.remove_prefix(next_label_index + 1);
    }
}

std::shared_ptr<Zone> Resolver::get_safe_zone(std::queue<std::shared_ptr<Zone>> &safe_zones) const {
    while (!safe_zones.empty()) {
        auto zone = std::move(safe_zones.front());
        safe_zones.pop();
        if (zone != nullptr && !zone->is_being_resolved) return zone;
    }
    return nullptr;
}

void Resolver::zone_disable_edns(Zone &zone) const {
    if (edns == FeatureState::Require) throw std::runtime_error("Nameserver does not support EDNS");
    zone.enable_edns = false;
    zone.enable_dnssec = false;
    zone.enable_cookies = false;
}

void Resolver::zone_disable_dnssec(Zone &zone) const {
    if (dnssec == FeatureState::Require) throw std::runtime_error("Nameserver does not support DNSSEC");
    zone.enable_dnssec = false;
}

void Resolver::zone_disable_cookies(Zone &zone) const {
    if (cookies == FeatureState::Require) throw std::runtime_error("Nameserver does not support Cookies");
    zone.enable_cookies = false;
}

std::vector<RR> Resolver::filter_rrset(std::vector<RR> &rrset, RRType rr_type) const {
    std::vector<RR> result;
    for (auto it = rrset.begin(); it != rrset.end(); ++it) {
        if (it->type == rr_type || rr_type == RRType::ANY) {
            result.push_back(std::move(*it));
            it = rrset.erase(it) - 1;
        }
    }
    return result;
}

std::vector<RR> Resolver::filter_rrset(std::vector<RR> &rrset, RRType rr_type, const std::string &domain) const {
    std::vector<RR> result;
    for (auto it = rrset.begin(); it != rrset.end(); ++it) {
        if ((it->type == rr_type || rr_type == RRType::ANY) && it->domain == domain) {
            result.push_back(std::move(*it));
            it = rrset.erase(it) - 1;
        }
    }
    return result;
}

std::vector<RRSIG> Resolver::get_rrsigs(std::vector<RR> &rrset, const std::string &domain,
                                        RRType rr_type_covered) const {
    std::vector<RRSIG> result;
    for (auto it = rrset.begin(); it != rrset.end(); ++it) {
        if (it->type != RRType::RRSIG) continue;
        if (it->domain != domain) continue;

        auto &rrsig = std::get<RRSIG>(it->data);
        if (rrsig.type_covered != rr_type_covered) continue;

        result.push_back(std::move(rrsig));
        it = rrset.erase(it) - 1;
    }

    return result;
}

std::optional<std::vector<RR>> Resolver::resolve_rec(const std::string &domain, RRType rr_type, int depth,
                                                     std::shared_ptr<Zone> search_zone) {
    if (depth >= MAX_QUERY_DEPTH) throw std::runtime_error("Query is too deep");

    std::vector<uint8_t> buffer;
    std::string sname{domain};
    std::queue<std::shared_ptr<Zone>> safe_zones({specified_zone, resolve_config_zone, root_zone});

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    // Choose the initial zone.
    std::shared_ptr<Zone> next_zone;
    if (search_zone != nullptr) {
        next_zone = std::move(search_zone);
    } else {
        next_zone = find_zone(sname);
        if (next_zone == nullptr) next_zone = get_safe_zone(safe_zones);
    }

    while (next_zone != nullptr) {
        std::shared_ptr<Zone> zone = std::move(next_zone);
        next_zone = nullptr;

        // Get zone's DNSKEYs.
        if (zone->enable_dnssec && zone->dnskeys.empty() && rr_type != RRType::DNSKEY) {
            auto opt_dnskey_rrset = resolve_rec(zone->domain, RRType::DNSKEY, depth + 1, zone);
            if (opt_dnskey_rrset.has_value() && !opt_dnskey_rrset->empty()) {
                zone->dnskeys = rrset_to_data<DNSKEY>(std::move(opt_dnskey_rrset.value()));
            } else {
                zone_disable_dnssec(*zone);
            }
        }

        // Try asking every nameserver in random order.
        std::ranges::shuffle(zone->nameservers, rng);
        for (auto it = zone->nameservers.begin(); it != zone->nameservers.end(); ++it) {
            auto &nameserver = *it;
            try {
                // If nameserver has only the domain, get the address.
                if (std::holds_alternative<std::string>(nameserver.address)) {
                    // Do not use this zone while it is being resolver to avoid infinite recursion.
                    ZoneResolutionGuard zone_guard{*zone};
                    auto opt_a_rrset = resolve_rec(std::get<std::string>(nameserver.address), RRType::A, depth + 1);

                    if (!opt_a_rrset.has_value() || opt_a_rrset->empty()) {
                        throw std::runtime_error("Failed to get nameserver's address");
                    }

                    auto a_rrset = rrset_to_data<A>(std::move(opt_a_rrset.value()));
                    std::ranges::shuffle(a_rrset, rng);

                    nameserver.address = a_rrset[0].address;
                    for (size_t i = 1; i < a_rrset.size(); i++) zone->nameservers.emplace_back(a_rrset[i].address);
                }
                address.sin_addr.s_addr = std::get<in_addr_t>(nameserver.address);

                if (verbose) {
                    char ip_addr_buf[INET_ADDRSTRLEN];
                    auto address_str = inet_ntop(AF_INET, &address.sin_addr, ip_addr_buf, sizeof(ip_addr_buf));
                    if (address_str == nullptr) address_str = "invalid address";
                    std::println("Resolving \"{}\" using {} ({})", sname, address_str, zone->domain);
                }

                auto payload_size = nameserver.udp_payload_size > 0
                                        ? nameserver.udp_payload_size
                                        : (zone->enable_edns ? EDNS_UDP_PAYLOAD_SIZE : STANDARD_UDP_PAYLOAD_SIZE);

                // Write and send the request.
                buffer.reserve(payload_size);
                buffer.clear();
                auto id = write_request(buffer, payload_size, sname, rr_type, enable_rd, zone->enable_edns,
                                        zone->enable_dnssec, zone->enable_cookies, nameserver.cookies);
                udp_send(buffer, address);

                // Ensure buffer is big enough to receive the response.
                buffer.resize(payload_size);
                udp_receive(buffer, address);
                auto response = read_response(buffer, id, sname, rr_type);
                auto rcode = response.rcode;

                // Handle OPT record.
                if (zone->enable_edns) {
                    std::vector<RR> opt_rrset = filter_rrset(response.additional, RRType::OPT);
                    if (opt_rrset.size() == 1) {
                        const auto &opt = std::get<OPT>(opt_rrset[0].data);

                        rcode = static_cast<RCode>((static_cast<uint16_t>(opt.upper_extended_rcode) << 4)
                                                   | std::to_underlying(rcode));
                        nameserver.udp_payload_size = opt.udp_payload_size;

                        if (!opt.dnssec_ok) zone_disable_dnssec(*zone);

                        // Check and save DNS cookies.
                        if (zone->enable_cookies) {
                            if (!opt.cookies.has_value()) {
                                zone_disable_cookies(*zone);
                            } else {
                                if (opt.cookies->client != nameserver.cookies.client) {
                                    throw std::runtime_error("Wrong client cookie");
                                }
                                nameserver.cookies.server = std::move(opt.cookies->server);
                            }
                        }
                    } else {
                        zone_disable_edns(*zone);
                    }
                }

                switch (rcode) {
                    case RCode::Success:     break;
                    case RCode::FormatError: throw std::runtime_error("Nameserver is unable to interpret query"); break;
                    case RCode::ServerError: throw std::runtime_error("Nameserver error"); break;
                    case RCode::NameError:
                        if (!response.is_authoritative) {
                            throw std::runtime_error("Non-authoritative nameserver cannot deny the existence");
                        }
                        return std::vector<RR>{};
                    case RCode::NotImplemented:
                        throw std::runtime_error("Nameserver does not support this query");
                        break;
                    case RCode::Refused:    throw std::runtime_error("Nameserver refused to answer"); break;
                    case RCode::BadVersion: throw std::runtime_error("Nameserver does not support EDNS"); break;
                    case RCode::BadCookie:  throw bad_cookie_error(); break;
                    default:                throw std::runtime_error("Unknown response code");
                }

                if (verbose) {
                    if (!response.answers.empty()) std::println("Answer:");
                    for (const auto &rr : response.answers) std::println("{}", rr);

                    if (!response.authority.empty()) std::println("Authority:");
                    for (const auto &rr : response.authority) std::println("{}", rr);

                    if (!response.additional.empty()) std::println("Additional:");
                    for (const auto &rr : response.additional) std::println("{}", rr);
                    std::println();
                }

                // Follow the CNAMEs before looking for the answer.
                bool followed_cname = false;
                auto cname_rrset = filter_rrset(response.answers, RRType::CNAME);
                for (;;) {
                    auto cname_rr
                        = std::ranges::find_if(cname_rrset, [&sname](const RR &rr) { return rr.domain == sname; });
                    if (cname_rr == cname_rrset.end()) break;

                    if (zone->enable_dnssec) {
                        auto cname_rrsigs = get_rrsigs(response.answers, cname_rr->domain, RRType::CNAME);
                        if (!verify_rrsig(std::vector<RR>{*cname_rr}, zone->dnskeys, zone->domain, cname_rrsigs)) {
                            zone_disable_dnssec(*zone);
                        }
                    }

                    // If the query type is CNAME, return it instead of following.
                    if (rr_type == RRType::CNAME) return std::vector<RR>{std::move(*cname_rr)};

                    sname = std::get<CNAME>(cname_rr->data).domain;
                    followed_cname = true;
                }

                // Look for the answer.
                auto result = filter_rrset(response.answers, rr_type, sname);
                if (!result.empty()) {
                    // Check that the answer is secure, verify RRSIGs.
                    if (zone->enable_dnssec) {
                        auto rrsigs = get_rrsigs(response.answers, sname, rr_type);
                        if (rr_type == RRType::DNSKEY) {
                            if (!verify_dnskeys(result, zone->dss, zone->domain, rrsigs)) {
                                if (zone->dss.empty() && dnssec != FeatureState::Require) {
                                    // Delegation is insecure, but we can still use DNSSEC within the zone.
                                } else {
                                    zone_disable_dnssec(*zone);
                                }
                            }
                        } else {
                            if (!verify_rrsig(result, zone->dnskeys, zone->domain, rrsigs)) zone_disable_dnssec(*zone);
                        }
                    }

                    return result;
                }

                // Look for the referral.
                std::shared_ptr<Zone> referral_zone = nullptr;
                auto ns_rrset = filter_rrset(response.authority, RRType::NS);
                for (auto &rr : ns_rrset) {
                    if (referral_zone == nullptr) {
                        if (count_matching_labels(sname, rr.domain) <= count_matching_labels(sname, zone->domain)) {
                            throw std::runtime_error("Referral must be closer to the search name");
                        }
                        referral_zone = new_zone(rr.domain);
                    } else if (rr.domain != referral_zone->domain) {
                        throw std::runtime_error(std::format("Authority contains multiple referrals: {} and {}",
                                                             rr.domain, referral_zone->domain));
                    }

                    // Check if the additional section has nameservers' addresses.
                    auto &ns_domain = std::get<NS>(rr.data).domain;
                    auto a_rrset = rrset_to_data<A>(filter_rrset(response.additional, RRType::A, ns_domain));
                    if (a_rrset.empty()) {
                        referral_zone->nameservers.emplace_back(std::move(ns_domain));
                    } else {
                        for (auto &a_rr : a_rrset) referral_zone->nameservers.emplace_back(a_rr.address);
                    }
                }

                if (referral_zone != nullptr) {
                    // Follow the referral.
                    auto ds_rrset = filter_rrset(response.authority, RRType::DS);
                    if (!ds_rrset.empty() && zone->enable_dnssec) {
                        auto ds_rrsigs = get_rrsigs(response.authority, referral_zone->domain, RRType::DS);
                        if (verify_rrsig(ds_rrset, zone->dnskeys, zone->domain, ds_rrsigs)) {
                            referral_zone->dss = rrset_to_data<DS>(std::move(ds_rrset));
                        } else {
                            zone_disable_dnssec(*zone);
                        }
                    }

                    zones[referral_zone->domain] = referral_zone;
                    next_zone = std::move(referral_zone);
                    break;
                } else if (followed_cname) {
                    // There is no referral and CNAME points outside of this zone, restart the search.
                    return resolve_rec(sname, rr_type, depth);
                } else {
                    // No referral and no answer, try querying the safe zones if there are any left.
                    next_zone = get_safe_zone(safe_zones);
                    if (next_zone == nullptr) return std::nullopt;
                    break;
                }
            } catch (const bad_cookie_error &e) {
                // Retry the same nameserver with the new server cookie before trying a different nameserver.
                if (!nameserver.sent_bad_cookie) it--;
                nameserver.sent_bad_cookie = true;
            } catch (const std::exception &e) {
                // Nameserver error, try asking the different nameserver if there are any left.
                if (verbose) std::println(stderr, "Failed to resolve the domain: {}", e.what());
            }
        }
    }
    return std::nullopt;
}
