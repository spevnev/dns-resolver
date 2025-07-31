#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "dns.hh"

template <typename T, typename Variant>
inline constexpr bool IsInVariant = false;

template <typename T, typename... Ts>
inline constexpr bool IsInVariant<T, std::variant<Ts...>> = (std::same_as<T, Ts> || ...);

struct Nameserver {
    std::variant<in_addr_t, std::string> address;
    std::optional<uint16_t> udp_payload_size{std::nullopt};
    bool sent_bad_cookie{false};
    DNSCookies cookies{};

    Nameserver(in_addr_t address) : address(address) {}
    Nameserver(const std::string &address) : address(address) {}
    Nameserver(std::string &&address) : address(std::move(address)) {}
};

struct Zone {
    // Do not ask the zone whose nameserver is being resolved.
    bool is_being_resolved{false};
    bool no_secure_delegation{false};
    std::string domain;
    bool enable_edns;
    bool enable_dnssec;
    bool enable_cookies;
    std::vector<std::shared_ptr<Nameserver>> nameservers;
    std::vector<DS> dss;
    std::vector<DNSKEY> dnskeys;

    Zone(std::string domain, bool enable_edns, bool enable_dnssec, bool enable_cookies)
        : domain(std::move(domain)),
          enable_edns(enable_edns),
          enable_dnssec(enable_dnssec),
          enable_cookies(enable_cookies) {}

    void add_nameserver(in_addr_t address) { nameservers.push_back(std::make_shared<Nameserver>(address)); }
    void add_nameserver(const std::string &domain) { nameservers.push_back(std::make_shared<Nameserver>(domain)); }
    void add_nameserver(std::string &&domain) {
        nameservers.push_back(std::make_shared<Nameserver>(std::move(domain)));
    }
};

// https://www.cppstories.com/2021/heterogeneous-access-cpp20/
struct StringHash {
    using is_transparent = void;

    size_t operator()(const char *str) const { return std::hash<std::string_view>{}(str); }
    size_t operator()(std::string_view str) const { return std::hash<std::string_view>{}(str); }
    size_t operator()(const std::string &str) const { return std::hash<std::string>{}(str); }
};

enum class FeatureState { Disable, Enable, Require };

struct ResolverConfig {
    uint64_t timeout_ms{5000};
    std::optional<std::string> nameserver{std::nullopt};
    bool use_root_nameservers{true};
    bool use_resolve_config{true};
    uint16_t port{DNS_PORT};
    bool verbose{false};
    bool enable_rd{true};
    FeatureState edns{FeatureState::Enable};
    FeatureState dnssec{FeatureState::Enable};
    FeatureState cookies{FeatureState::Enable};
};

class Resolver {
public:
    Resolver(ResolverConfig config = {});
    ~Resolver();

    std::optional<std::vector<RR>> resolve(const std::string &domain, RRType rr_type);

private:
    std::chrono::duration<uint64_t, std::milli> timeout_duration;
    uint64_t udp_timeout_ms;
    uint16_t port;
    bool verbose, enable_rd;
    FeatureState edns, dnssec, cookies;
    std::default_random_engine rng;
    std::unordered_map<std::string, std::shared_ptr<Zone>, StringHash, std::equal_to<>> zones;
    int fd;
    std::chrono::time_point<std::chrono::steady_clock> timeout_instant;
    std::shared_ptr<Zone> specified_zone, resolve_config_zone, root_zone;

    void set_socket_timeout(uint64_t timeout) const;
    void update_timeout();

    void udp_send(const std::vector<uint8_t> &buffer, struct sockaddr_in address);
    void udp_receive(std::vector<uint8_t> &buffer, struct sockaddr_in address);

    std::shared_ptr<Zone> new_zone(const std::string &domain) const;
    std::shared_ptr<Zone> find_zone(const std::string &domain) const;
    void zone_disable_edns(Zone &zone) const;
    void zone_disable_dnssec(Zone &zone) const;
    void zone_disable_cookies(Zone &zone) const;

    bool verify_rrset(const std::vector<RR> &rrset, const std::vector<RRSIG> &rrsigs, RRType rr_type,
                      const Zone &zone) const;
    std::vector<RR> get_rrset(std::vector<RR> &rrset, RRType rr_type, const Zone &zone, bool verify = true) const;
    std::vector<RR> get_rrset(std::vector<RR> &rrset, RRType rr_type, const std::string &domain, const Zone &zone,
                              bool verify = true) const;

    template <typename T>
        requires IsInVariant<T, decltype(RR::data)>
    std::vector<T> rrset_to_data(const std::vector<RR> &rrset) const {
        std::vector<T> result;
        result.reserve(rrset.size());
        for (const auto &rr : rrset) result.push_back(std::get<T>(rr.data));
        return result;
    }

    template <typename T>
        requires IsInVariant<T, decltype(RR::data)>
    std::vector<T> rrset_to_data(std::vector<RR> &&rrset) const {
        std::vector<T> result;
        result.reserve(rrset.size());
        for (auto &rr : rrset) result.push_back(std::move(std::get<T>(rr.data)));
        return result;
    }

    std::optional<std::vector<RR>> resolve_rec(const std::string &domain, RRType rr_type, int depth,
                                               std::shared_ptr<Zone> search_zone = nullptr);
};
