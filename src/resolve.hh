#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <chrono>
#include <optional>
#include <queue>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>
#include "dns.hh"

template <typename T, typename Variant>
inline constexpr bool IsInVariant = false;

template <typename T, typename... Ts>
inline constexpr bool IsInVariant<T, std::variant<Ts...>> = (std::same_as<T, Ts> || ...);

// https://www.cppstories.com/2021/heterogeneous-access-cpp20
struct StringHash {
    using is_transparent = void;

    size_t operator()(const char *str) const { return std::hash<std::string_view>{}(str); }
    size_t operator()(std::string_view str) const { return std::hash<std::string_view>{}(str); }
    size_t operator()(const std::string &str) const { return std::hash<std::string>{}(str); }
};

struct Zone;

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
    uint64_t query_timeout_ms, udp_timeout_ms;
    uint16_t port;
    bool verbose, enable_rd;
    FeatureState edns, dnssec, cookies;
    std::default_random_engine rng;
    std::unordered_map<std::string, std::shared_ptr<Zone>, StringHash, std::equal_to<>> zones;
    int fd;
    std::chrono::time_point<std::chrono::steady_clock> query_start;
    // List of zones to ask when the resolver has no information.
    std::queue<std::shared_ptr<Zone>> safe_zones;

    std::shared_ptr<Zone> new_zone(const std::string &domain, bool enable_dnssec = true) const;
    std::shared_ptr<Zone> new_root_zone() const;
    std::shared_ptr<Zone> load_resolve_config() const;
    std::shared_ptr<Zone> new_zone_from_nameserver(const std::string &address_or_domain) const;
    std::shared_ptr<Zone> find_zone(const std::string &domain) const;
    void zone_disable_dnssec(Zone &zone) const;

    void set_socket_timeout(uint64_t timeout) const;
    void update_timeout();

    void udp_send(const std::vector<uint8_t> &buffer, struct sockaddr_in address);
    void udp_receive(std::vector<uint8_t> &buffer, struct sockaddr_in address);

    bool authenticate_rrset(const std::vector<RR> &rrset, const std::vector<RRSIG> &rrsigs, RRType rr_type,
                            const Zone &zone) const;
    std::vector<RR> get_rrset(std::vector<RR> &rrset, RRType rr_type, const Zone &zone, bool authenticate = true) const;
    std::vector<RR> get_rrset(std::vector<RR> &rrset, RRType rr_type, const std::string &domain, const Zone &zone,
                              bool authenticate = true) const;

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
