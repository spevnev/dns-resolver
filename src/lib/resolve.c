#define _POSIX_C_SOURCE 200809L
#include "resolve.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "dns.h"
#include "error.h"
#include "vector.h"

VECTOR_TYPEDEF(IP4AddrVec, in_addr_t);

typedef struct {
    bool is_being_resolved;
    char domain[DOMAIN_SIZE];
    IP4AddrVec nameserver_addrs;
    StrVec nameserver_domains;
} Zone;

VECTOR_TYPEDEF(ZoneVec, Zone);

typedef struct {
    int fd;
    uint16_t port;
    bool recursion_desired;
    bool enable_edns;
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
            VECTOR_PUSH(&zone->nameserver_addrs, ip_addr);
        }
    }
    free(line);
    fclose(fp);
    if (found) return;

not_found:
    // If no nameserver entries are present, the default is to use the local nameserver.
    result = inet_pton(AF_INET, "127.0.0.1", &ip_addr);
    assert(result == 1);
    VECTOR_PUSH(&zone->nameserver_addrs, ip_addr);
}

static bool set_timeout(int fd, uint64_t timeout_ns) {
    struct timeval tv = {
        .tv_sec = timeout_ns / NS_IN_SEC,
        .tv_usec = (timeout_ns % NS_IN_SEC) / NS_IN_US,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return false;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return false;
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
        if (!set_timeout(query->fd, query->udp_timeout_ns)) return false;
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

static void add_root_zone(ZoneVec *zones) {
    Zone zone = {
        .domain = "",
        .nameserver_addrs = {0},
        .nameserver_domains = {0},
    };

    in_addr_t ip_addr;
    for (size_t i = 0; i < ROOT_NAMESERVER_COUNT; i++) {
        int result = inet_pton(AF_INET, ROOT_NAMESERVER_IP_ADDRS[i], &ip_addr);
        assert(result == 1);
        VECTOR_PUSH(&zone.nameserver_addrs, ip_addr);
    }

    VECTOR_PUSH(zones, zone);
}

static void free_zone(Zone *zone) {
    VECTOR_FREE(&zone->nameserver_addrs);
    for (uint32_t j = 0; j < zone->nameserver_domains.length; j++) free(zone->nameserver_domains.data[j]);
    VECTOR_FREE(&zone->nameserver_domains);
}

static bool resolve_rec(Query *query, const char *domain, uint16_t qtype, bool is_subquery, RRVec *result);

static bool choose_nameserver(Query *query, const char *sname, size_t *zone_index_out, size_t *nameserver_index_out) {
    for (;;) {
        for (int i = query->zones.length - 1; i >= 0; i--) {
            Zone *zone = &query->zones.data[i];
            if (zone->is_being_resolved || strcasecmp(zone->domain, sname) != 0) continue;

            // If there are resolved nameservers, return a random one.
            if (zone->nameserver_addrs.length > 0) {
                *zone_index_out = i;
                *nameserver_index_out = rand() % zone->nameserver_addrs.length;
                return true;
            }

            // There are no resolved nameservers, try to resolve starting from a random index.
            while (zone->nameserver_domains.length > 0) {
                uint32_t index = rand() % zone->nameserver_domains.length;
                char *nameserver_domain = zone->nameserver_domains.data[index];

                zone->is_being_resolved = true;
                RRVec nameserver_addrs = {0};
                bool found = resolve_rec(query, nameserver_domain, TYPE_A, true, &nameserver_addrs);
                zone->is_being_resolved = false;

                // If removed before resolving, zone might get empty and be deleted.
                VECTOR_REMOVE(&zone->nameserver_domains, index);
                free(nameserver_domain);

                if (!found) continue;

                for (uint32_t j = 0; j < nameserver_addrs.length; j++) {
                    VECTOR_PUSH(&zone->nameserver_addrs, nameserver_addrs.data[j]->data.ip4_addr);
                }
                free_rr_vec(&nameserver_addrs);

                if (zone->nameserver_addrs.length == 0) continue;

                *zone_index_out = i;
                *nameserver_index_out = rand() % zone->nameserver_addrs.length;
                return true;
            }

            // Failed to resolve all nameservers in the zone, remove it.
            if (zone->nameserver_domains.length == 0) {
                free_zone(zone);
                VECTOR_REMOVE(&query->zones, i);
            }
        }

        // No zone for current domain, try parent domain.
        if (*sname == '\0') return false;
        while (*sname != '\0' && *sname != '.') sname++;
        if (*sname == '.') sname++;
    }
}

static void remove_nameserver(Query *query, size_t zone_index, size_t nameserver_index) {
    Zone *zone = &query->zones.data[zone_index];
    VECTOR_REMOVE(&zone->nameserver_addrs, nameserver_index);
    if (zone->nameserver_addrs.length == 0 && zone->nameserver_domains.length == 0) {
        free_zone(zone);
        VECTOR_REMOVE(&query->zones, zone_index);
    }
}

static bool is_subdomain(const char *subdomain, const char *domain) {
    size_t subdomain_length = strlen(subdomain);
    size_t domain_length = strlen(domain);
    if (subdomain_length < domain_length) return false;

    size_t subdomain_prefix_length = subdomain_length - domain_length;
    return strcasecmp(subdomain + subdomain_prefix_length, domain) == 0;
}

static bool follow_cnames(RRVec rrs, char sname[static DOMAIN_SIZE], uint16_t qtype, RRVec *result) {
    bool found = false;
    bool restart;
    do {
        restart = false;
        for (uint32_t i = 0; i < rrs.length; i++) {
            RR *rr = rrs.data[i];
            if (strcasecmp(rr->domain, sname) != 0) continue;

            // Found it.
            if (rr->type == qtype) {
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

static bool resolve_rec(Query *query, const char *domain, uint16_t qtype, bool is_subquery, RRVec *result) {
    size_t domain_len = strlen(domain);
    if (domain[domain_len - 1] == '.') domain_len--;
    if (domain_len > 0 && domain[domain_len - 1] == '.') {
        if (query->verbose) fprintf(stderr, "Invalid domain name, multiple trailing dots.\n");
        return false;
    }
    if (domain_len > MAX_DOMAIN_LENGTH) {
        if (query->verbose) fprintf(stderr, "Invalid domain name, maximum length is %d.\n", MAX_DOMAIN_LENGTH);
        return false;
    }

    char sname[DOMAIN_SIZE];
    memcpy(sname, domain, domain_len);
    sname[domain_len] = '\0';

    bool found = false;
    struct sockaddr_in request_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(query->port),
        .sin_zero = {0},
    };
    uint16_t buffer_size = EDNS_UDP_PAYLOAD_SIZE;
    uint8_t buffer[buffer_size];
    char addr_buffer[INET_ADDRSTRLEN];
    RRVec prev_rrs = {0};
    bool timed_out = false;
    DNSHeader response_header = {0};
    size_t nameserver_index;
    size_t zone_index;
    RR *rr;
    while (!found && choose_nameserver(query, sname, &zone_index, &nameserver_index)) {
        Zone *nameserver_zone = &query->zones.data[zone_index];
        in_addr_t nameserver_ip_addr = nameserver_zone->nameserver_addrs.data[nameserver_index];

        if (query->verbose) {
            printf("\n");

            const char *addr_str = inet_ntop(AF_INET, &nameserver_ip_addr, addr_buffer, sizeof(addr_buffer));
            if (addr_str == NULL) addr_str = "invalid address";
            printf("Resolving %s using %s (%s).\n", sname, addr_str, nameserver_zone->domain);
        }

        Request request = {
            .buffer = buffer,
            .size = buffer_size,
            .length = 0,
        };

        uint16_t id;
        if (!write_request(&request, query->recursion_desired, sname, qtype, query->enable_edns, buffer_size, &id)) {
            if (query->verbose) fprintf(stderr, "Request buffer is too small.\n");
            return false;
        }

        request_addr.sin_addr.s_addr = nameserver_ip_addr;
        if (!udp_send(query, request, request_addr, &timed_out)) {
            if (query->verbose) fprintf(stderr, "Request timeout.\n");
            if (timed_out) break;
            goto nameserver_error;
        }

        ssize_t response_length;
        if (!udp_receive(query, buffer, buffer_size, request_addr, &response_length, &timed_out)) {
            if (query->verbose) fprintf(stderr, "Response timeout.\n");
            if (timed_out) break;
            goto nameserver_error;
        }

        // Reuse request buffer for response.
        Response response = {
            .buffer = buffer,
            .current = 0,
            .length = response_length,
        };
        if (!read_response_header(&response, id, &response_header)) {
            if (query->verbose) fprintf(stderr, "Invalid response header.\n");
            goto nameserver_error;
        }
        if (response_header.is_truncated) {
            if (query->verbose) fprintf(stderr, "Response is truncated.\n");
            return false;
        }

        switch (response_header.rcode) {
            case RCODE_SUCCESS: break;
            case RCODE_NAME_ERROR:
                if (!response_header.is_authoritative) goto nameserver_error;
                if (query->verbose && is_subquery) printf("Domain name does not exist.\n");
                found = true;
                continue;
            case RCODE_FORMAT_ERROR:
                if (query->verbose) fprintf(stderr, "Nameserver unable to interpret query.\n");
                goto nameserver_error;
            case RCODE_SERVER_ERROR:
                if (query->verbose) fprintf(stderr, "Nameserver error.\n");
                goto nameserver_error;
            case RCODE_NOT_IMPLEMENTED:
                if (query->verbose) fprintf(stderr, "Nameserver does not support this type of query.\n");
                goto nameserver_error;
            case RCODE_REFUSED:
                if (query->verbose) fprintf(stderr, "Nameserver refused to answer.\n");
                goto nameserver_error;
            default:
                if (query->verbose) {
                    fprintf(stderr, "Invalid or unsupported response code %d.\n", response_header.rcode);
                }
                goto nameserver_error;
        }

        if (!validate_question(&response, qtype, sname)) {
            if (query->verbose) fprintf(stderr, "Invalid question in response.\n");
            goto nameserver_error;
        }

        // No answer and no referral, remove the nameserver.
        if (response_header.answer_count == 0 && response_header.authority_count == 0) {
            if (query->verbose) fprintf(stderr, "Response has empty answer and authority sections.\n");
            goto nameserver_error;
        }

        if (response_header.answer_count > 0) {
            for (uint32_t i = 0; i < prev_rrs.length; i++) free_rr(prev_rrs.data[i]);
            VECTOR_RESET(&prev_rrs);

            // If qtype is ANY, terminate search after any response with answers section.
            if (qtype == QTYPE_ANY) found = true;

            if (query->verbose) printf("Answer section:\n");
            for (uint16_t i = 0; i < response_header.answer_count; i++) {
                if (!read_rr(&response, &rr)) {
                    if (query->verbose) fprintf(stderr, "Invalid resource record.\n");
                    goto nameserver_error;
                }
                if (query->verbose) print_rr(rr);

                if (strcasecmp(rr->domain, sname) != 0) {
                    VECTOR_PUSH(&prev_rrs, rr);
                    continue;
                }

                if (rr->type == qtype || qtype == QTYPE_ANY) {
                    found = true;
                    VECTOR_PUSH(result, rr);
                    continue;
                }

                if (rr->type == TYPE_CNAME) {
                    // Change sname to the alias.
                    memcpy(sname, rr->data.domain, strlen(rr->data.domain) + 1);
                    // Check previous RRs.
                    if (follow_cnames(prev_rrs, sname, qtype, result)) found = true;
                }
                free_rr(rr);
            }

            if (found) break;
        }

        bool zone_has_domain = false;
        Zone authority_zone = {0};
        if (response_header.authority_count > 0) {
            if (query->verbose) printf("Authority section:\n");
            for (uint16_t i = 0; i < response_header.authority_count; i++) {
                if (!read_rr(&response, &rr)) {
                    if (query->verbose) fprintf(stderr, "Invalid resource record.\n");
                    goto nameserver_error;
                }
                if (query->verbose) print_rr(rr);

                if (rr->type == TYPE_NS || rr->type == TYPE_SOA) {
                    if (!zone_has_domain) {
                        zone_has_domain = true;

                        // Check that the referral is a subzone of the current nameserver.
                        if (!is_subdomain(rr->domain, nameserver_zone->domain)) {
                            if (query->verbose) fprintf(stderr, "Ignoring upward referral.\n");
                            goto nameserver_error;
                        }

                        memcpy(authority_zone.domain, rr->domain, strlen(rr->domain) + 1);
                    } else if (strcasecmp(authority_zone.domain, rr->domain) != 0) {
                        if (query->verbose) {
                            fprintf(stderr, "Authority section should refer to a single zone but found many.\n");
                        }
                        goto nameserver_error;
                    }

                    char *domain = strdup(rr->type == TYPE_NS ? rr->data.domain : rr->data.soa.master_name);
                    if (domain == NULL) OUT_OF_MEMORY();
                    VECTOR_PUSH(&authority_zone.nameserver_domains, domain);
                }
                free_rr(rr);
            }
        }

        if (response_header.additional_count > 0) {
            bool has_opt = false;
            bool printed_section = false;
            uint16_t extended_rcode = 0;
            for (uint16_t i = 0; i < response_header.additional_count; i++) {
                if (!read_rr(&response, &rr)) {
                    if (query->verbose) fprintf(stderr, "Invalid resource record.\n");
                    goto nameserver_error;
                }

                if (rr->type == TYPE_OPT) {
                    if (has_opt) {
                        if (query->verbose) fprintf(stderr, "Multiple OPT RRs in additional section.\n");
                        goto nameserver_error;
                    }
                    has_opt = true;

                    extended_rcode = (((uint16_t) rr->data.opt.extended_rcode) << 4) | response_header.rcode;
                    free_rr(rr);
                    continue;
                }

                if (query->verbose) {
                    if (!printed_section) {
                        printed_section = true;
                        printf("Additional section:\n");
                    }
                    print_rr(rr);
                }

                if (rr->type != TYPE_A) {
                    free_rr(rr);
                    continue;
                }

                for (uint32_t j = 0; j < authority_zone.nameserver_domains.length; j++) {
                    if (strcasecmp(authority_zone.nameserver_domains.data[j], rr->domain) == 0) {
                        free(authority_zone.nameserver_domains.data[j]);
                        VECTOR_REMOVE(&authority_zone.nameserver_domains, j);
                        j--;

                        VECTOR_PUSH(&authority_zone.nameserver_addrs, rr->data.ip4_addr);
                        break;
                    }
                }
                free_rr(rr);
            }

            // OPT must be sent only when EDNS is enabled.
            if (query->enable_edns != has_opt) {
                if (query->verbose) {
                    if (query->enable_edns) {
                        fprintf(stderr, "Nameserver does not support EDNS.\n");
                    } else {
                        fprintf(stderr, "Nameserver sent OPT although EDNS is disabled.\n");
                    }
                }
                free_zone(&authority_zone);
                goto nameserver_error;
            }

            switch (extended_rcode) {
                case RCODE_SUCCESS: break;
                case RCODE_BAD_VERSION:
                    if (query->verbose) fprintf(stderr, "Nameserver does not support EDNS version %d.\n", EDNS_VERSION);
                    free_zone(&authority_zone);
                    goto nameserver_error;
                default:
                    if (query->verbose) fprintf(stderr, "Invalid or unsupported response code %d.\n", extended_rcode);
                    free_zone(&authority_zone);
                    goto nameserver_error;
            }

            if (authority_zone.nameserver_addrs.length > 0 || authority_zone.nameserver_domains.length > 0) {
                VECTOR_PUSH(&query->zones, authority_zone);
            }
        }

        continue;
    nameserver_error:
        remove_nameserver(query, zone_index, nameserver_index);
    }
    if (query->verbose && is_subquery && !found) printf("Failed to resolve the domain.\n");

    free_rr_vec(&prev_rrs);
    return found;
}

bool resolve(const char *domain, uint16_t qtype, const char *nameserver, uint16_t port, uint64_t timeout_ms,
             uint32_t flags, RRVec *result) {
    if (result == NULL || domain == NULL) return false;

    srand(time(NULL));

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return false;

    // Timeout to receive/send over UDP.
    uint64_t udp_timeout_ns = MAX(timeout_ms / 5, MIN_QUERY_TIMEOUT_MS) * NS_IN_MS;
    if (!set_timeout(fd, udp_timeout_ns)) {
        close(fd);
        return false;
    }

    Query query = {
        .fd = fd,
        .port = port,
        .recursion_desired = !(flags & RESOLVE_DISABLE_RDFLAG),
        .enable_edns = !(flags & RESOLVE_DISABLE_EDNS),
        .verbose = flags & RESOLVE_VERBOSE,
        .time_ns = get_time_ns(),
        .udp_timeout_ns = udp_timeout_ns,
        .time_left_ns = timeout_ms * NS_IN_MS,
        .zones = {0},
    };

    // Load root nameservers in case provided nameserver cannot answer.
    if (!(flags & RESOLVE_NO_ROOT_NS)) add_root_zone(&query.zones);

    // Create a zone of initial nameservers.
    in_addr_t ip_addr;
    Zone zone = {
        .domain = "",  // root
        .nameserver_addrs = {0},
        .nameserver_domains = {0},
    };
    if (nameserver == NULL) {
        load_resolve_config(&zone);
    } else if (inet_pton(AF_INET, nameserver, &ip_addr) == 1) {
        VECTOR_PUSH(&zone.nameserver_addrs, ip_addr);
    } else {
        char *nameserver_dup = strdup(nameserver);
        if (nameserver_dup == NULL) OUT_OF_MEMORY();
        VECTOR_PUSH(&zone.nameserver_domains, nameserver_dup);
    }
    VECTOR_PUSH(&query.zones, zone);

    bool found = resolve_rec(&query, domain, qtype, false, result);

    for (uint32_t i = 0; i < query.zones.length; i++) free_zone(&query.zones.data[i]);
    VECTOR_FREE(&query.zones);
    close(fd);
    return found;
}

void free_rr_vec(RRVec *rr_vec) {
    for (uint32_t i = 0; i < rr_vec->length; i++) free_rr(rr_vec->data[i]);
    VECTOR_FREE(rr_vec);
}
