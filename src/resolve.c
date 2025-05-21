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

VECTOR_TYPEDEF(AddressVec, in_addr_t);

typedef struct {
    char domain[DOMAIN_SIZE];
    AddressVec ns_addresses;
    StrVec ns_domains;
} Zone;

VECTOR_TYPEDEF(ZoneVec, Zone);

typedef struct {
    int fd;
    uint16_t port;
    bool recursion_desired;
    bool enable_edns;
    bool verbose;
    bool timed_out;
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

static void set_timeout(int fd, uint64_t timeout_ns) {
    struct timeval tv = {
        .tv_sec = timeout_ns / NS_IN_SEC,
        .tv_usec = (timeout_ns % NS_IN_SEC) / NS_IN_US,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) PERROR("clock_gettime");
    return ts.tv_sec * NS_IN_SEC + ts.tv_nsec;
}

static bool update_query_timeout(Query *query) {
    uint64_t current_time_ns = get_time_ns();
    uint64_t time_diff_ns = current_time_ns - query->time_ns;
    if (time_diff_ns >= query->time_left_ns) {
        query->timed_out = true;
        return false;
    }

    query->time_left_ns -= time_diff_ns;
    query->time_ns = current_time_ns;

    if (query->time_left_ns < query->udp_timeout_ns) {
        set_timeout(query->fd, query->udp_timeout_ns);
        query->udp_timeout_ns = query->time_left_ns;
    }
    return true;
}

static bool address_equals(struct sockaddr_in a, struct sockaddr_in b) {
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

static bool is_whitespace(char ch) { return ch == ' ' || ch == '\t'; }

static void load_resolve_config(Zone *zone, bool verbose) {
    FILE *fp = fopen(RESOLV_CONF_PATH, "r");
    if (fp == NULL) ERROR("Failed to open %s", RESOLV_CONF_PATH);

    bool found = false;
    char *line = NULL;
    size_t line_size = 0;
    ssize_t line_len;
    in_addr_t ip4_addr;
    struct in6_addr ip6_addr;
    while ((line_len = getline(&line, &line_size, fp)) != -1) {
        char *ch = line;
        while (is_whitespace(*ch)) ch++;

        if (strncmp(ch, "nameserver", strlen("nameserver")) != 0) continue;
        ch += strlen("nameserver");

        // Find the beginning of the address.
        while (is_whitespace(*ch)) ch++;
        char *addr_str = ch;

        // Go to the end of the address and put null terminator.
        while (*ch != '\n' && !is_whitespace(*ch)) ch++;
        *ch = '\0';

        if (inet_pton(AF_INET, addr_str, &ip4_addr) == 1) {
            found = true;
            VECTOR_PUSH(&zone->ns_addresses, ip4_addr);
        } else if (inet_pton(AF_INET6, addr_str, &ip6_addr) == 1) {
            if (verbose) printf("IPv6 is not supported.\n");
        } else {
            ERROR("Invalid nameserver address in %s", RESOLV_CONF_PATH);
        }
    }
    if (!feof(fp)) ERROR("Failed to read %s: %s", RESOLV_CONF_PATH, strerror(errno));
    free(line);
    fclose(fp);

    // If no nameserver entries are present, the default is to use the local nameserver.
    if (!found) {
        in_addr_t ip_addr;
        int result = inet_pton(AF_INET, "127.0.0.1", &ip_addr);
        assert(result == 1);
        VECTOR_PUSH(&zone->ns_addresses, ip_addr);
    }
}

static bool follow_cnames(RRVec *result, RRVec rrs, char *sname, uint16_t qtype) {
    bool found = false;
    bool restart;
    do {
        restart = false;
        for (uint32_t i = 0; i < rrs.length; i++) {
            ResourceRecord *rr = rrs.data[i];
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

static ssize_t udp_send(Query *query, Request request, struct sockaddr_in address) {
    ssize_t result
        = sendto(query->fd, request.buffer, request.length, 0, (struct sockaddr *) &address, sizeof(address));
    if (!update_query_timeout(query)) return -1;
    return result;
}

static ssize_t udp_receive(Query *query, uint8_t *buffer, size_t buffer_size, struct sockaddr_in request_address) {
    struct sockaddr_in address;
    socklen_t address_length;
    ssize_t result;
    // Read responses until we find one from the same address and port as in request.
    do {
        address_length = sizeof(address);
        result = recvfrom(query->fd, buffer, buffer_size, 0, (struct sockaddr *) &address, &address_length);
        if (!update_query_timeout(query)) return -1;
    } while (result != -1 && (address_length != sizeof(address) || !address_equals(request_address, address)));
    return result;
}

static bool resolve_rec(RRVec *result, Query *query, const char *domain, uint16_t qtype);

static bool find_nameserver(size_t *zone_index, size_t *nameserver_index, Query *query, const char *sname) {
    for (;;) {
        for (int i = query->zones.length - 1; i >= 0; i--) {
            Zone *zone = &query->zones.data[i];
            if (strcasecmp(zone->domain, sname) != 0) continue;

            // If there are resolved nameservers, return a random one.
            if (zone->ns_addresses.length > 0) {
                *zone_index = i;
                *nameserver_index = rand() % zone->ns_addresses.length;
                return true;
            }

            // There are no resolved nameservers, try to resolve starting from a random index.
            uint32_t index = rand() % zone->ns_domains.length;
            while (zone->ns_domains.length > 0) {
                char *ns_domain = zone->ns_domains.data[index];

                VECTOR_REMOVE(&zone->ns_domains, index);
                if (index >= zone->ns_domains.length) index = 0;

                RRVec ns_addresses = {0};
                bool found = resolve_rec(&ns_addresses, query, ns_domain, TYPE_A);
                free(ns_domain);

                if (!found) continue;

                for (uint32_t i = 0; i < ns_addresses.length; i++) {
                    VECTOR_PUSH(&zone->ns_addresses, ns_addresses.data[i]->data.ip4_address);
                }
                free_rr_vec(&ns_addresses);

                if (zone->ns_addresses.length == 0) continue;

                *zone_index = i;
                *nameserver_index = rand() % zone->ns_addresses.length;
                return true;
            }

            // Failed to resolve all nameservers in the zone, remove it.
            if (zone->ns_domains.length == 0) {
                VECTOR_REMOVE(&query->zones, i);
                i++;
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
    VECTOR_REMOVE(&zone->ns_addresses, nameserver_index);
    if (zone->ns_addresses.length == 0 && zone->ns_domains.length == 0) VECTOR_REMOVE(&query->zones, zone_index);
}

static bool is_subdomain(const char *subdomain, const char *domain) {
    size_t subdomain_length = strlen(subdomain);
    size_t domain_length = strlen(domain);
    if (subdomain_length <= domain_length) return false;

    size_t subdomain_prefix_length = subdomain_length - domain_length;
    return strcasecmp(subdomain + subdomain_prefix_length, domain) == 0;
}

static void add_root_zone(ZoneVec *zones) {
    Zone zone = {
        .domain = "",
        .ns_addresses = {0},
        .ns_domains = {0},
    };

    in_addr_t ip_addr;
    for (size_t i = 0; i < ROOT_NAMESERVERS_LENGTH; i++) {
        int result = inet_pton(AF_INET, ROOT_NAMESERVER_IPS[i], &ip_addr);
        assert(result == 1);
        VECTOR_PUSH(&zone.ns_addresses, ip_addr);
    }

    VECTOR_PUSH(zones, zone);
}

static void free_zone(Zone *zone) {
    VECTOR_FREE(&zone->ns_addresses);
    for (uint32_t j = 0; j < zone->ns_domains.length; j++) free(zone->ns_domains.data[j]);
    VECTOR_FREE(&zone->ns_domains);
}

static bool resolve_rec(RRVec *result, Query *query, const char *domain, uint16_t qtype) {
    if (domain == NULL) ERROR("Domain is null");

    size_t domain_len = strlen(domain);
    if (domain[domain_len - 1] == '.') domain_len--;
    if (domain_len > 0 && domain[domain_len - 1] == '.') ERROR("Invalid domain name, multiple trailing dots");
    if (domain_len > MAX_DOMAIN_LENGTH) ERROR("Invalid domain name, maximum length is %d", MAX_DOMAIN_LENGTH);

    char sname[DOMAIN_SIZE];
    memcpy(sname, domain, domain_len);
    sname[domain_len] = '\0';

    bool found = false;
    struct sockaddr_in req_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(query->port),
        .sin_zero = {0},
    };
    uint16_t buffer_size = EDNS_UDP_PAYLOAD_SIZE;
    uint8_t buffer[buffer_size];
    char addr_buffer[INET_ADDRSTRLEN];
    RRVec prev_rrs = {0};
    size_t nameserver_index;
    size_t zone_index;
    while (!found && find_nameserver(&zone_index, &nameserver_index, query, sname)) {
        Zone *nameserver_zone = &query->zones.data[zone_index];
        in_addr_t server_ip = nameserver_zone->ns_addresses.data[nameserver_index];

        if (query->verbose) {
            printf("\n");

            if (inet_ntop(AF_INET, &server_ip, addr_buffer, sizeof(addr_buffer)) == NULL) PERROR("inet_ntop");
            printf("Resolving %s using %s (%s).\n", sname, addr_buffer, nameserver_zone->domain);
        }

        Request request = {
            .buffer = buffer,
            .size = buffer_size,
            .length = 0,
        };
        req_addr.sin_addr.s_addr = server_ip;
        uint16_t id = write_request(&request, query->recursion_desired, sname, qtype, query->enable_edns, buffer_size);
        if (udp_send(query, request, req_addr) != request.length) {
            if (query->timed_out) break;

            if (errno == EAGAIN) {
                if (query->verbose) fprintf(stderr, "Request timeout.\n");
                remove_nameserver(query, zone_index, nameserver_index);
                continue;
            } else {
                PERROR("sendto");
            }
        }

        ssize_t response_length = udp_receive(query, buffer, buffer_size, req_addr);
        if (response_length == -1) {
            if (query->timed_out) break;

            if (errno == EAGAIN) {
                if (query->verbose) fprintf(stderr, "Response timeout.\n");
                remove_nameserver(query, zone_index, nameserver_index);
                continue;
            } else {
                PERROR("recvfrom");
            }
        }

        // Reuse request buffer for response.
        Response response = {
            .buffer = buffer,
            .current = 0,
            .length = response_length,
        };

        DNSHeader res_header = read_response_header(&response, id);
        if (res_header.is_truncated) ERROR("Response is truncated");

        switch (res_header.response_code) {
            case RCODE_SUCCESS: break;
            case RCODE_NAME_ERROR:
                if (!res_header.is_authoritative) ERROR("Name error");
                found = true;
                continue;
            case RCODE_FORMAT_ERROR:
                if (query->verbose) fprintf(stderr, "Nameserver unable to interpret query.\n");
                remove_nameserver(query, zone_index, nameserver_index);
                continue;
            case RCODE_SERVER_ERROR:
                if (query->verbose) fprintf(stderr, "Nameserver error.\n");
                remove_nameserver(query, zone_index, nameserver_index);
                continue;
            case RCODE_NOT_IMPLEMENTED:
                if (query->verbose) fprintf(stderr, "Nameserver does not support this type of query.\n");
                remove_nameserver(query, zone_index, nameserver_index);
                continue;
            case RCODE_REFUSED:
                if (query->verbose) fprintf(stderr, "Nameserver refused to answer.\n");
                remove_nameserver(query, zone_index, nameserver_index);
                continue;
            default: ERROR("Invalid or unsupported response code %d", res_header.response_code);
        }

        validate_question(&response, qtype, sname);

        // Read resource records.
        if (res_header.answer_count > 0) {
            if (query->verbose) printf("Answer section:\n");

            for (uint32_t i = 0; i < prev_rrs.length; i++) free_resource_record(prev_rrs.data[i]);
            VECTOR_RESET(&prev_rrs);

            for (uint16_t i = 0; i < res_header.answer_count; i++) {
                ResourceRecord *rr = read_resource_record(&response);
                if (query->verbose) print_resource_record(rr);

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
                    if (follow_cnames(result, prev_rrs, sname, qtype)) found = true;
                }
                free_resource_record(rr);
            }

            // If qtype is ANY, terminate search after any response with answers section.
            if (qtype == QTYPE_ANY) found = true;
            if (found) break;
        }

        bool zone_has_domain = false;
        Zone authority_zone = {0};
        if (res_header.authority_count > 0) {
            if (query->verbose) printf("Authority section:\n");
            for (uint16_t i = 0; i < res_header.authority_count; i++) {
                ResourceRecord *rr = read_resource_record(&response);
                if (query->verbose) print_resource_record(rr);

                if (rr->type == TYPE_NS) {
                    if (!zone_has_domain) {
                        zone_has_domain = true;

                        // Check that the referral is a subzone of the current nameserver.
                        if (!is_subdomain(rr->domain, nameserver_zone->domain)) {
                            if (query->verbose) fprintf(stderr, "Ignoring upward referral.\n");
                            remove_nameserver(query, zone_index, nameserver_index);
                            continue;
                        }

                        memcpy(authority_zone.domain, rr->domain, strlen(rr->domain) + 1);
                    } else if (strcasecmp(authority_zone.domain, rr->domain) != 0) {
                        ERROR("Authority section should refer to a single zone but found many");
                    }

                    char *domain = strdup(rr->data.domain);
                    if (domain == NULL) OUT_OF_MEMORY();
                    VECTOR_PUSH(&authority_zone.ns_domains, domain);
                }
                free_resource_record(rr);
            }
        }

        if (res_header.additional_count > 0) {
            bool contains_opt = false;
            bool printed_section = false;
            uint16_t extended_response_code = 0;
            for (uint16_t i = 0; i < res_header.additional_count; i++) {
                ResourceRecord *rr = read_resource_record(&response);
                if (rr->type == TYPE_OPT) {
                    contains_opt = true;
                    extended_response_code = (((uint16_t) rr->data.opt.extended_rcode) << 4) | res_header.response_code;
                    free_resource_record(rr);
                    continue;
                }

                if (query->verbose) {
                    if (!printed_section) {
                        printed_section = true;
                        printf("Additional section:\n");
                    }
                    print_resource_record(rr);
                }

                if (rr->type != TYPE_A) {
                    free_resource_record(rr);
                    continue;
                }

                for (uint32_t j = 0; j < authority_zone.ns_domains.length; j++) {
                    if (strcasecmp(authority_zone.ns_domains.data[j], rr->domain) == 0) {
                        free(authority_zone.ns_domains.data[j]);
                        VECTOR_REMOVE(&authority_zone.ns_domains, j);
                        j--;

                        VECTOR_PUSH(&authority_zone.ns_addresses, rr->data.ip4_address);
                        break;
                    }
                }
                free_resource_record(rr);
            }

            if (!query->enable_edns && contains_opt) ERROR("Nameserver sent OPT although EDNS is disabled");
            if (query->enable_edns && !contains_opt) {
                if (query->verbose) fprintf(stderr, "Nameserver does not support EDNS.\n");
                remove_nameserver(query, zone_index, nameserver_index);
                free_zone(&authority_zone);
                continue;
            }

            switch (extended_response_code) {
                case RCODE_SUCCESS: break;
                case RCODE_BAD_VERSION:
                    if (query->verbose) fprintf(stderr, "Nameserver does not support EDNS version %d.\n", EDNS_VERSION);
                    remove_nameserver(query, zone_index, nameserver_index);
                    free_zone(&authority_zone);
                    continue;
                default: ERROR("Invalid or unsupported response code %d", extended_response_code);
            }

            VECTOR_PUSH(&query->zones, authority_zone);
        }
    }

    free_rr_vec(&prev_rrs);
    return found;
}

bool resolve(RRVec *result, const char *domain, uint16_t qtype, const char *nameserver, uint16_t port,
             uint64_t timeout_ms, uint32_t flags) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) PERROR("socket");

    srand(time(NULL));

    // Timeout to receive/send over UDP.
    uint64_t udp_timeout_ns = MAX(timeout_ms / 5, MIN_QUERY_TIMEOUT_MS) * NS_IN_MS;
    set_timeout(fd, udp_timeout_ns);

    Query query = {
        .fd = fd,
        .port = port,
        .recursion_desired = !(flags & RESOLVE_DISABLE_RDFLAG),
        .enable_edns = !(flags & RESOLVE_DISABLE_EDNS),
        .verbose = flags & RESOLVE_VERBOSE,
        .timed_out = false,
        .time_ns = get_time_ns(),
        .udp_timeout_ns = udp_timeout_ns,
        .time_left_ns = timeout_ms * NS_IN_MS,
        .zones = {0},
    };

    // Load root nameservers in case provided nameserver cannot answer.
    add_root_zone(&query.zones);

    // Create a zone of initial nameservers.
    in_addr_t ip_addr;
    Zone zone = {
        .domain = "",  // root
        .ns_addresses = {0},
        .ns_domains = {0},
    };
    if (nameserver == NULL) {
        load_resolve_config(&zone, true);
    } else if (inet_pton(AF_INET, nameserver, &ip_addr) == 1) {
        VECTOR_PUSH(&zone.ns_addresses, ip_addr);
    } else {
        char *nameserver_dup = strdup(nameserver);
        if (nameserver_dup == NULL) OUT_OF_MEMORY();
        VECTOR_PUSH(&zone.ns_domains, nameserver_dup);
    }
    VECTOR_PUSH(&query.zones, zone);

    bool found = resolve_rec(result, &query, domain, qtype);

    for (uint32_t i = 0; i < query.zones.length; i++) free_zone(&query.zones.data[i]);
    VECTOR_FREE(&query.zones);
    close(fd);
    return found;
}

void free_rr_vec(RRVec *rr_vec) {
    for (uint32_t i = 0; i < rr_vec->length; i++) free_resource_record(rr_vec->data[i]);
    VECTOR_FREE(rr_vec);
}
