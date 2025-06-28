#define _POSIX_C_SOURCE 200809L
#include "resolve.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "dns.h"
#include "dnssec.h"
#include "error.h"
#include "root_ns.h"
#include "vector.h"

typedef struct {
    in_addr_t addr;
    uint16_t udp_payload_size;
    bool sent_bad_cookie;
    DNSCookies cookies;
} Nameserver;

VECTOR_TYPEDEF(NameserverVec, Nameserver);

typedef struct {
    bool is_being_resolved;
    bool enable_edns;
    bool enable_cookie;
    bool enable_dnssec;
    char domain[DOMAIN_SIZE];
    StrVec nameserver_domains;
    NameserverVec nameservers;
    RRVec dss;
    RRVec dnskeys;
} Zone;

VECTOR_TYPEDEF(ZoneVec, Zone);

typedef struct {
    int fd;
    uint16_t port;
    bool enable_rd;
    bool enable_edns;
    bool require_edns;
    bool enable_cookie;
    bool require_cookie;
    bool enable_dnssec;
    bool require_dnssec;
    bool verbose;
    // Time when timeout was last updated.
    uint64_t time_ns;
    // UDP request/response timeout.
    uint64_t udp_timeout_ns;
    uint64_t time_left_ns;
    ZoneVec zones;
} Query;

#define RESOLV_CONF_PATH "/etc/resolv.conf"

static const uint64_t MIN_QUERY_TIMEOUT_MS = 300;

static const uint64_t NS_IN_SEC = 1000000000;
static const uint64_t NS_IN_MS = 1000000;
static const uint64_t NS_IN_US = 1000;

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static void add_nameserver(Zone *zone, in_addr_t addr) {
    Nameserver nameserver = {
        .addr = addr,
        .udp_payload_size = 0,
        .sent_bad_cookie = false,
        .cookies = {0},
    };
    VECTOR_PUSH(&zone->nameservers, nameserver);
}

static void free_zone(Zone *zone) {
    for (uint32_t j = 0; j < zone->nameserver_domains.length; j++) free(zone->nameserver_domains.data[j]);
    VECTOR_FREE(&zone->nameserver_domains);
    VECTOR_FREE(&zone->nameservers);
    free_rr_vec(zone->dss);
    free_rr_vec(zone->dnskeys);
}

static void add_zone(Query *query, Zone zone) {
    zone.enable_edns = query->enable_edns;
    zone.enable_cookie = query->enable_cookie;
    zone.enable_dnssec = query->enable_dnssec;
    VECTOR_PUSH(&query->zones, zone);
}

static bool add_root_zone(Query *query) {
    Zone zone = {.domain = "."};

    in_addr_t ip_addr;
    for (size_t i = 0; i < ROOT_IP_ADDRS_COUNT; i++) {
        if (inet_pton(AF_INET, ROOT_IP_ADDRS[i], &ip_addr) != 1) goto error;
        add_nameserver(&zone, ip_addr);
    }

    if (query->enable_dnssec) {
        for (size_t i = 0; i < ROOT_DNSKEYS_COUNT; i++) {
            RR *rr = malloc(sizeof(*rr));
            if (rr == NULL) goto error;
            memcpy(rr, &ROOT_DNSKEYS[i], sizeof(*rr));

            rr->domain = strdup(rr->domain);
            if (rr->domain == NULL) {
                free(rr);
                goto error;
            }

            rr->data.dnskey.key = malloc(rr->data.dnskey.key_size);
            if (rr->data.dnskey.key == NULL) {
                free(rr->domain);
                free(rr);
                goto error;
            }
            memcpy(rr->data.dnskey.key, ROOT_DNSKEYS[i].data.dnskey.key, rr->data.dnskey.key_size);

            VECTOR_PUSH(&zone.dnskeys, rr);
        }
    }

    add_zone(query, zone);
    return true;
error:
    free_zone(&zone);
    return false;
}

static void zone_disable_edns(Zone *zone) {
    zone->enable_edns = false;
    zone->enable_cookie = false;
    zone->enable_dnssec = false;
}

static bool is_whitespace(char ch) { return ch == ' ' || ch == '\t'; }

static void load_resolve_config(Zone *zone) {
    FILE *fp = fopen(RESOLV_CONF_PATH, "r");
    if (fp == NULL) goto not_found;

    bool found = false;
    char *line = NULL;
    size_t line_size = 0;
    ssize_t line_len;
    int result;
    in_addr_t ip_addr;
    while ((line_len = getline(&line, &line_size, fp)) != -1) {
        char *cur = line;
        while (is_whitespace(*cur)) cur++;

        if (strncmp(cur, "nameserver", strlen("nameserver")) != 0) continue;
        cur += strlen("nameserver");

        // Find the beginning of the address.
        while (is_whitespace(*cur)) cur++;
        char *addr_str = cur;

        // Go to the end of the address and put null terminator.
        while (*cur != '\n' && !is_whitespace(*cur)) cur++;
        *cur = '\0';

        if (inet_pton(AF_INET, addr_str, &ip_addr) == 1) {
            found = true;
            add_nameserver(zone, ip_addr);
        }
    }
    free(line);
    fclose(fp);
    if (found) return;

not_found:
    // If no nameserver entries are present, the default is to use the local nameserver.
    result = inet_pton(AF_INET, "127.0.0.1", &ip_addr);
    assert(result == 1);
    add_nameserver(zone, ip_addr);
}

static bool set_timeout(const Query *query) {
    struct timeval tv = {
        .tv_sec = query->udp_timeout_ns / NS_IN_SEC,
        .tv_usec = (query->udp_timeout_ns % NS_IN_SEC) / NS_IN_US,
    };
    if (setsockopt(query->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return false;
    if (setsockopt(query->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return false;
    return true;
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return UINT64_MAX;
    return ts.tv_sec * NS_IN_SEC + ts.tv_nsec;
}

static bool update_query_timeout(Query *query, bool *timed_out) {
    uint64_t current_time_ns = get_time_ns();
    if (current_time_ns == UINT64_MAX) return false;

    uint64_t time_diff_ns = current_time_ns - query->time_ns;
    if (time_diff_ns >= query->time_left_ns) {
        *timed_out = true;
        return true;
    }

    query->time_left_ns -= time_diff_ns;
    query->time_ns = current_time_ns;

    if (query->time_left_ns < query->udp_timeout_ns) {
        if (!set_timeout(query)) return false;
        query->udp_timeout_ns = query->time_left_ns;
    }
    return true;
}

static bool udp_send(Query *query, Request request, struct sockaddr_in address, bool *timed_out) {
    ssize_t result
        = sendto(query->fd, request.buffer, request.length, 0, (struct sockaddr *) &address, sizeof(address));
    if (!update_query_timeout(query, timed_out)) return false;
    return result == request.length;
}

static bool address_equals(struct sockaddr_in a, struct sockaddr_in b) {
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

static bool udp_receive(Query *query, uint8_t *buffer, size_t buffer_size, struct sockaddr_in request_address,
                        ssize_t *response_length_out, bool *timed_out) {
    struct sockaddr_in address;
    socklen_t address_length;
    ssize_t result;
    // Read responses until we find one from the same address and port as in request.
    do {
        address_length = sizeof(address);
        result = recvfrom(query->fd, buffer, buffer_size, 0, (struct sockaddr *) &address, &address_length);
        if (!update_query_timeout(query, timed_out)) return false;
    } while (result != -1 && (address_length != sizeof(address) || !address_equals(request_address, address)));
    if (result == -1) return false;

    *response_length_out = result;
    return true;
}

static bool resolve_rec(Query *query, const char *domain, RRType qtype, bool is_subquery, RRVec *result);

static bool choose_nameserver(Query *query, const char *sname, size_t *zone_index_out, size_t *nameserver_index_out) {
    for (;;) {
        for (int i = query->zones.length - 1; i >= 0; i--) {
            Zone *zone = &query->zones.data[i];
            if (zone->is_being_resolved || strcmp(zone->domain, sname) != 0) continue;

            // If there are resolved nameservers, return a random one.
            if (zone->nameservers.length > 0) {
                *zone_index_out = i;
                *nameserver_index_out = rand() % zone->nameservers.length;
                return true;
            }

            // There are no resolved nameservers, try to resolve starting from a random index.
            while (zone->nameserver_domains.length > 0) {
                zone->is_being_resolved = true;

                uint32_t index = rand() % zone->nameserver_domains.length;
                char *nameserver_domain = zone->nameserver_domains.data[index];

                RRVec nameserver_addrs = {0};
                bool found = resolve_rec(query, nameserver_domain, TYPE_A, true, &nameserver_addrs);

                // Adding a zone to `query->zones` (inside of `resolve_rec`) might cause
                // a realloc which invalidates the pointer, so we take it again.
                zone = &query->zones.data[i];
                zone->is_being_resolved = false;

                // If removed before resolving, zone might get empty and be deleted.
                VECTOR_REMOVE(&zone->nameserver_domains, index);
                free(nameserver_domain);

                if (!found) continue;

                for (uint32_t j = 0; j < nameserver_addrs.length; j++) {
                    add_nameserver(zone, nameserver_addrs.data[j]->data.ip4_addr);
                }
                free_rr_vec(nameserver_addrs);

                if (zone->nameservers.length == 0) continue;

                *zone_index_out = i;
                *nameserver_index_out = rand() % zone->nameservers.length;
                return true;
            }

            // Failed to resolve all nameservers in the zone, remove it.
            if (zone->nameserver_domains.length == 0) {
                free_zone(zone);
                VECTOR_REMOVE(&query->zones, i);
            }
        }

        // No zone for current domain, try parent domain.
        if (is_root_domain(sname)) return false;
        while (*sname != '\0' && *sname != '.') sname++;
        if (!is_root_domain(sname)) sname++;
    }
}

static void remove_nameserver(Query *query, size_t zone_index, size_t nameserver_index) {
    Zone *zone = &query->zones.data[zone_index];
    VECTOR_REMOVE(&zone->nameservers, nameserver_index);
    if (zone->nameservers.length == 0 && zone->nameserver_domains.length == 0) {
        free_zone(zone);
        VECTOR_REMOVE(&query->zones, zone_index);
    }
}

static bool is_subdomain(const char *subdomain, const char *domain) {
    size_t subdomain_length = strlen(subdomain);
    size_t domain_length = strlen(domain);
    if (subdomain_length < domain_length) return false;

    size_t subdomain_prefix_length = subdomain_length - domain_length;
    return strcmp(subdomain + subdomain_prefix_length, domain) == 0;
}

static bool follow_cnames(RRVec *rrs, char sname[static DOMAIN_SIZE], RRType qtype, RRVec *result) {
    bool found = false;
    bool restart;
    do {
        restart = false;
        for (uint32_t i = 0; i < rrs->length; i++) {
            RR *rr = rrs->data[i];
            if (strcmp(rr->domain, sname) != 0) continue;

            if (rr->type == qtype) {
                VECTOR_REMOVE(rrs, i);
                i--;

                VECTOR_PUSH(result, rr);
                found = true;
            }

            // Follow CNAME and restart search with new name.
            if (rr->type == TYPE_CNAME) {
                memcpy(sname, rr->data.domain, strlen(rr->data.domain) + 1);
                restart = true;
                break;
            }
        }
    } while (restart);
    return found;
}

static bool resolve_rec(Query *query, const char *domain, RRType qtype, bool is_subquery, RRVec *result) {
#define QUERY_ERROR(...)                                                        \
    do {                                                                        \
        if (query->verbose) fprintf(stderr, __VA_ARGS__);                       \
        for (uint32_t i = 0; i < result->length; i++) free_rr(result->data[i]); \
        VECTOR_RESET(result);                                                   \
        found = false;                                                          \
        goto query_error;                                                       \
    } while (0)
#define NAMESERVER_ERROR(...)                             \
    do {                                                  \
        if (query->verbose) fprintf(stderr, __VA_ARGS__); \
        goto nameserver_error;                            \
    } while (0)

    char sname[DOMAIN_SIZE];
    memcpy(sname, domain, strlen(domain) + 1);

    bool found = false;
    bool timed_out = false;
    size_t zone_index;
    size_t nameserver_index;
    char addr_buffer[INET_ADDRSTRLEN];
    uint16_t buffer_size = 0;
    uint8_t *buffer = NULL;
    uint16_t id;
    struct sockaddr_in request_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(query->port),
        .sin_zero = {0},
    };
    ssize_t response_length;
    DNSHeader response_header;
    RR *rr = NULL;
    RRVec prev_rrs = {0};
    Zone authority_zone = {0};
    while (!found && !timed_out && choose_nameserver(query, sname, &zone_index, &nameserver_index)) {
        Zone *zone = &query->zones.data[zone_index];
        Nameserver *nameserver = &zone->nameservers.data[nameserver_index];

        if (zone->enable_dnssec && zone->dnskeys.length == 0 && qtype != TYPE_DNSKEY) {
            if (zone->dss.length == 0 || !resolve_rec(query, zone->domain, TYPE_DNSKEY, true, &zone->dnskeys)) {
                if (query->require_dnssec) {
                    NAMESERVER_ERROR("Failed to get or verify DNSKEYs for zone \"%s\".\n", zone->domain);
                } else {
                    zone->enable_dnssec = false;
                }
            }
        }

        if (query->verbose) {
            printf("\n");

            const char *addr_str = inet_ntop(AF_INET, &nameserver->addr, addr_buffer, sizeof(addr_buffer));
            if (addr_str == NULL) addr_str = "invalid address";
            printf("Resolving %s using %s (%s).\n", sname, addr_str, zone->domain);
        }

        uint16_t request_size;
        if (nameserver->udp_payload_size == 0) {
            request_size = zone->enable_edns ? EDNS_UDP_PAYLOAD_SIZE : STANDARD_UDP_PAYLOAD_SIZE;
        } else {
            request_size = nameserver->udp_payload_size;
        }

        if (request_size > buffer_size) {
            buffer_size = request_size;
            buffer = realloc(buffer, buffer_size);
            if (buffer == NULL) QUERY_ERROR("Out of memory.\n");
        }

        Request request = {
            .buffer = buffer,
            .size = request_size,
            .length = 0,
        };
        if (!write_request(&request, query->enable_rd, sname, qtype, zone->enable_edns, zone->enable_cookie,
                           zone->enable_dnssec, &nameserver->cookies, &id)) {
            QUERY_ERROR("Request buffer is too small.\n");
        }

        request_addr.sin_addr.s_addr = nameserver->addr;
        if (!udp_send(query, request, request_addr, &timed_out)) NAMESERVER_ERROR("Request timeout.\n");

        if (!udp_receive(query, buffer, buffer_size, request_addr, &response_length, &timed_out)) {
            NAMESERVER_ERROR("Response timeout.\n");
        }

        // Reuse request buffer for response.
        Response response = {
            .buffer = buffer,
            .current = 0,
            .length = response_length,
        };
        if (!read_response_header(&response, id, &response_header)) NAMESERVER_ERROR("Invalid response header.\n");
        if (response_header.is_truncated) QUERY_ERROR("Response is truncated.\n");

        bool unknown_rcode = false;
        switch (response_header.rcode) {
            case RCODE_SUCCESS: break;
            case RCODE_NAME_ERROR:
                if (!response_header.is_authoritative) goto nameserver_error;
                if (query->verbose && is_subquery) printf("Domain name does not exist.\n");
                found = true;
                break;
            case RCODE_FORMAT_ERROR:    NAMESERVER_ERROR("Nameserver unable to interpret query.\n");
            case RCODE_SERVER_ERROR:    NAMESERVER_ERROR("Nameserver error.\n");
            case RCODE_NOT_IMPLEMENTED: NAMESERVER_ERROR("Nameserver does not support this type of query.\n");
            case RCODE_REFUSED:         NAMESERVER_ERROR("Nameserver refused to answer.\n");
            default:
                // It may be unknown because it is the lower half of the extended rcode,
                // wait for the OPT RR (or absence of it) before throwing an error.
                unknown_rcode = true;
                break;
        }

        if (!validate_question(&response, qtype, sname)) NAMESERVER_ERROR("Invalid question in response.\n");

        if (response_header.answer_count > 0) {
            for (uint32_t i = 0; i < prev_rrs.length; i++) free_rr(prev_rrs.data[i]);
            VECTOR_RESET(&prev_rrs);

            // If qtype is ANY, terminate search after any response with answers section.
            if (qtype == QTYPE_ANY) found = true;

            RRVec rrsigs = {0};
            if (query->verbose) printf("Answer section:\n");
            for (uint16_t i = 0; i < response_header.answer_count; i++) {
                if (!read_rr(&response, &rr)) NAMESERVER_ERROR("Invalid resource record.\n");
                if (query->verbose) print_rr(rr);

                if (strcmp(rr->domain, sname) != 0) {
                    VECTOR_PUSH(&prev_rrs, rr);
                    // Set to NULL to avoid freeing it.
                    rr = NULL;
                    continue;
                }

                if (rr->type == qtype || qtype == QTYPE_ANY) {
                    VECTOR_PUSH(result, rr);
                    // Set to NULL to avoid freeing it.
                    rr = NULL;
                    found = true;
                } else if (rr->type == TYPE_CNAME) {
                    // Change sname to the alias.
                    memcpy(sname, rr->data.domain, strlen(rr->data.domain) + 1);
                    // Check previous RRs.
                    if (follow_cnames(&prev_rrs, sname, qtype, result)) found = true;
                } else if (zone->enable_dnssec && rr->type == TYPE_RRSIG && rr->data.rrsig.type_covered == qtype) {
                    VECTOR_PUSH(&rrsigs, rr);
                    rr = NULL;
                }
            }

            if (zone->enable_dnssec && qtype != QTYPE_ANY && result->length > 0) {
                bool are_verified = false;
                if (rrsigs.length > 0) {
                    if (qtype == TYPE_DNSKEY && zone->dnskeys.length == 0) {
                        are_verified = verify_dnskeys(result, zone->dss, zone->domain, &rrsigs);
                    } else {
                        are_verified = verify_rrsig(result, zone->dnskeys, zone->domain, &rrsigs);
                    }
                    free_rr_vec(rrsigs);
                }

                if (!are_verified) {
                    if (query->require_dnssec) NAMESERVER_ERROR("Failed to verify the answer RRs.\n");
                    zone->enable_dnssec = false;
                }
            }
        }

        bool zone_has_domain = false;
        if (response_header.authority_count > 0) {
            RRVec rrsigs = {0};
            if (query->verbose) printf("Authority section:\n");
            for (uint16_t i = 0; i < response_header.authority_count; i++) {
                if (!read_rr(&response, &rr)) NAMESERVER_ERROR("Invalid resource record.\n");
                if (query->verbose) print_rr(rr);

                if (rr->type == TYPE_NS || rr->type == TYPE_SOA) {
                    if (!zone_has_domain) {
                        zone_has_domain = true;

                        // Check that the referral is a subzone of the current nameserver.
                        if (!is_subdomain(rr->domain, zone->domain)) NAMESERVER_ERROR("Ignoring upward referral.\n");

                        free_zone(&authority_zone);
                        memset(&authority_zone, 0, sizeof(authority_zone));

                        memcpy(authority_zone.domain, rr->domain, strlen(rr->domain) + 1);
                    } else if (strcmp(authority_zone.domain, rr->domain) != 0) {
                        NAMESERVER_ERROR("Authority section should refer to a single zone but found many.\n");
                    }

                    char *domain = strdup(rr->type == TYPE_NS ? rr->data.domain : rr->data.soa.master_name);
                    if (domain == NULL) OUT_OF_MEMORY();
                    VECTOR_PUSH(&authority_zone.nameserver_domains, domain);
                } else if (zone->enable_dnssec && rr->type == TYPE_DS) {
                    VECTOR_PUSH(&authority_zone.dss, rr);
                    // Set to NULL to avoid freeing it.
                    rr = NULL;
                } else if (zone->enable_dnssec && rr->type == TYPE_RRSIG && rr->data.rrsig.type_covered == TYPE_DS) {
                    VECTOR_PUSH(&rrsigs, rr);
                    rr = NULL;
                }
            }

            if (authority_zone.dss.length > 0) {
                bool are_verified = false;
                if (rrsigs.length > 0) {
                    are_verified = verify_rrsig(&authority_zone.dss, zone->dnskeys, zone->domain, &rrsigs);
                    free_rr_vec(rrsigs);
                }

                if (!are_verified) {
                    if (query->require_dnssec) NAMESERVER_ERROR("Failed to verify the DS RRs.\n");
                    zone->enable_dnssec = false;

                    // DS RRs that failed verification must not be used.
                    for (uint32_t i = 0; i < authority_zone.dss.length; i++) free_rr(authority_zone.dss.data[i]);
                    VECTOR_RESET(&authority_zone.dss);
                }
            }
        }

        if (response_header.additional_count > 0) {
            bool has_opt = false;
            bool printed_section = false;
            uint16_t extended_rcode = 0;
            for (uint16_t i = 0; i < response_header.additional_count; i++) {
                if (!read_rr(&response, &rr)) NAMESERVER_ERROR("Invalid resource record.\n");

                if (zone->enable_edns && rr->type == TYPE_OPT) {
                    if (has_opt) NAMESERVER_ERROR("Multiple OPT RRs in additional section.\n");
                    has_opt = true;

                    nameserver->udp_payload_size = rr->data.opt.udp_payload_size;
                    extended_rcode = (((uint16_t) rr->data.opt.extended_rcode) << 4) | response_header.rcode;

                    if (zone->enable_cookie) {
                        if (rr->data.opt.has_cookies) {
                            if (nameserver->cookies.client != rr->data.opt.cookies.client) {
                                NAMESERVER_ERROR("Invalid client cookie.\n");
                            }

                            nameserver->cookies.server_size = rr->data.opt.cookies.server_size;
                            memcpy(nameserver->cookies.server, rr->data.opt.cookies.server,
                                   nameserver->cookies.server_size);
                        } else {
                            if (query->require_cookie) NAMESERVER_ERROR("Nameserver does not support cookie.\n");
                            zone->enable_cookie = false;
                        }
                    }
                    continue;
                }

                if (query->verbose) {
                    if (!printed_section) {
                        printed_section = true;
                        printf("Additional section:\n");
                    }
                    print_rr(rr);
                }

                if (rr->type != TYPE_A) continue;

                for (uint32_t j = 0; j < authority_zone.nameserver_domains.length; j++) {
                    if (strcmp(authority_zone.nameserver_domains.data[j], rr->domain) == 0) {
                        free(authority_zone.nameserver_domains.data[j]);
                        VECTOR_REMOVE(&authority_zone.nameserver_domains, j);
                        add_nameserver(&authority_zone, rr->data.ip4_addr);
                        break;
                    }
                }
            }

            if (zone->enable_edns && !has_opt) {
                if (query->require_edns) NAMESERVER_ERROR("Nameserver does not support EDNS.\n");
                zone_disable_edns(zone);
            }

            unknown_rcode = false;
            switch (extended_rcode) {
                case RCODE_SUCCESS:
                case RCODE_NAME_ERROR: break;
                case RCODE_BAD_VERSION:
                    if (query->require_edns) {
                        NAMESERVER_ERROR("Nameserver does not support EDNS version %d.\n", EDNS_VERSION);
                    } else {
                        zone_disable_edns(zone);
                    }
                    break;
                case RCODE_BAD_COOKIE:
                    // Retry with the new server cookie once before removing the nameserver.
                    if (nameserver->sent_bad_cookie) NAMESERVER_ERROR("Bad server cookie.\n");
                    nameserver->sent_bad_cookie = true;
                    continue;
                default: NAMESERVER_ERROR("Invalid or unsupported response code %d.\n", extended_rcode);
            }

            if (authority_zone.nameservers.length > 0 || authority_zone.nameserver_domains.length > 0) {
                add_zone(query, authority_zone);
                memset(&authority_zone, 0, sizeof(authority_zone));
            }
        } else if (zone->enable_edns) {
            // Response does not have additional sections, and thus no OPT.
            if (query->require_edns) NAMESERVER_ERROR("Nameserver does not support EDNS.\n");
            zone_disable_edns(zone);
        }

        if (unknown_rcode) NAMESERVER_ERROR("Invalid or unsupported response code %d.\n", response_header.rcode);

        continue;
    nameserver_error:
        remove_nameserver(query, zone_index, nameserver_index);
        for (uint32_t i = 0; i < result->length; i++) free_rr(result->data[i]);
        VECTOR_RESET(result);
        found = false;
    }
    if (query->verbose && is_subquery && !found) printf("Failed to resolve the domain.\n");

query_error:
    free_zone(&authority_zone);
    free_rr_vec(prev_rrs);
    free_rr(rr);
    free(buffer);
    return found;

#undef QUERY_ERROR
#undef NAMESERVER_ERROR
}

bool resolve(const char *domain, RRType qtype, const char *nameserver, uint16_t port, uint64_t timeout_ms,
             uint32_t flags, RRVec *result) {
    if (result == NULL || domain == NULL) return false;

    bool enable_edns = !(flags & RESOLVE_DISABLE_EDNS);

    bool enable_cookie = enable_edns && !(flags & RESOLVE_DISABLE_COOKIE);
    bool require_cookie = enable_cookie && (flags & RESOLVE_REQUIRE_COOKIE);

    bool enable_dnssec = enable_edns && !(flags & RESOLVE_DISABLE_DNSSEC);
    bool require_dnssec = enable_dnssec && (flags & RESOLVE_REQUIRE_DNSSEC);

    bool require_edns = (flags & RESOLVE_REQUIRE_EDNS) || require_cookie || require_dnssec;

    bool found = false;
    Query query = {
        .fd = -1,
        .port = port,
        .enable_rd = !(flags & RESOLVE_DISABLE_RDFLAG),
        .enable_edns = enable_edns,
        .require_edns = require_edns,
        .enable_cookie = enable_cookie,
        .require_cookie = require_cookie,
        .enable_dnssec = enable_dnssec,
        .require_dnssec = require_dnssec,
        .verbose = flags & RESOLVE_VERBOSE,
        .time_ns = get_time_ns(),
        .udp_timeout_ns = MAX(timeout_ms / 5, MIN_QUERY_TIMEOUT_MS) * NS_IN_MS,
        .time_left_ns = timeout_ms * NS_IN_MS,
        .zones = {0},
    };

    if ((query.fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) goto exit;

    srand(time(NULL));
    if (!set_timeout(&query)) goto exit;

    // Load root nameservers in case provided nameserver cannot answer the query.
    if (!(flags & RESOLVE_NO_ROOT_NS) && !add_root_zone(&query)) goto exit;

    // Create a zone of initial nameservers.
    in_addr_t ip_addr;
    Zone zone = {.domain = "."};
    if (nameserver == NULL) {
        load_resolve_config(&zone);
    } else if (inet_pton(AF_INET, nameserver, &ip_addr) == 1) {
        add_nameserver(&zone, ip_addr);
    } else {
        char *nameserver_fqd = fully_qualify_domain(nameserver);
        if (nameserver_fqd == NULL) {
            if (query.verbose) fprintf(stderr, "Invalid nameserver domain \"%s\".\n", nameserver);
            goto exit;
        }
        VECTOR_PUSH(&zone.nameserver_domains, nameserver_fqd);
    }
    add_zone(&query, zone);

    char *fqd = fully_qualify_domain(domain);
    if (fqd == NULL) {
        if (query.verbose) fprintf(stderr, "Invalid domain \"%s\".\n", domain);
        goto exit;
    }

    found = resolve_rec(&query, fqd, qtype, false, result);
    free(fqd);

exit:
    close(query.fd);
    for (uint32_t i = 0; i < query.zones.length; i++) free_zone(&query.zones.data[i]);
    VECTOR_FREE(&query.zones);
    return found;
}

void free_rr_vec(RRVec rr_vec) {
    for (uint32_t i = 0; i < rr_vec.length; i++) free_rr(rr_vec.data[i]);
    VECTOR_FREE(&rr_vec);
}
