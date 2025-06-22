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
    bool sent_bad_cookie;
    DNSCookies cookies;
} Nameserver;

VECTOR_TYPEDEF(NameserverVec, Nameserver);

typedef struct {
    bool is_being_resolved;
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
    bool recursion_desired;
    bool enable_edns;
    bool enable_cookie;
    bool enable_dnssec;
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

    VECTOR_PUSH(&query->zones, zone);
    return true;
error:
    free_zone(&zone);
    return false;
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

static bool resolve_rec(Query *query, const char *domain, uint16_t qtype, bool is_subquery, RRVec *result);

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

static bool follow_cnames(RRVec *rrs, char sname[static DOMAIN_SIZE], uint16_t qtype, RRVec *result) {
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

static size_t domain_to_canonical(const char *domain, uint8_t output_buffer[static DOMAIN_SIZE]) {
    if (is_root_domain(domain)) {
        *output_buffer = 0;
        return 1;
    }

    uint8_t *out = output_buffer;
    const char *start = domain;
    for (const char *cur = domain; *cur != '\0'; cur++) {
        if (*cur == '.') {
            uint8_t length = cur - start;
            *out++ = length;
            memcpy(out, start, length);
            out += length;
            start = cur + 1;
        }
    }
    *out++ = 0;

    return out - output_buffer;
}

static uint8_t get_domain_labels_num(const char *domain) {
    if (is_root_domain(domain)) return 0;

    uint8_t labels = 0;
    for (const char *cur = domain; *cur != '\0'; cur++) {
        if (*cur == '.') labels++;
    }
    return labels;
}

static bool get_dnskeys(Query *query, Zone *zone) {
    if (zone->dss.length == 0) return false;

    bool result = false;
    RRVec dnskeys = {0};
    RR *rrsig_rr = NULL;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *ds_digest_algorithm = NULL;
    unsigned char *digest = NULL;
    const EVP_MD *rrsig_digest_algorithm = NULL;
    EVP_PKEY *pkey = NULL;

    if (!resolve_rec(query, zone->domain, TYPE_DNSKEY, true, &dnskeys)) goto exit;

    for (uint32_t i = 0; i < dnskeys.length; i++) {
        if (dnskeys.data[i]->type == TYPE_RRSIG) {
            rrsig_rr = dnskeys.data[i];
            VECTOR_REMOVE(&dnskeys, i);
            break;
        }
    }
    if (rrsig_rr == NULL) goto exit;
    RRSIG *rrsig = &rrsig_rr->data.rrsig;

    assert(zone->dss.length == 1);
    RR *ds = zone->dss.data[0];

    if ((ctx = EVP_MD_CTX_new()) == NULL) goto exit;
    if ((ds_digest_algorithm = get_ds_digest_algorithm(ds->data.ds.digest_algorithm)) == NULL) goto exit;
    if ((digest = OPENSSL_malloc(EVP_MD_get_size(ds_digest_algorithm))) == NULL) goto exit;

    RR *verified_dnskey_rr = NULL;
    unsigned int digest_size;
    uint8_t canonical_domain[DOMAIN_SIZE];
    for (uint32_t i = 0; i < dnskeys.length; i++) {
        RR *dnskey_rr = dnskeys.data[i];
        DNSKEY *dnskey = &dnskey_rr->data.dnskey;

        if (dnskey->key_tag != ds->data.ds.key_tag) continue;
        if (!dnskey->is_zone_key) continue;

        size_t canonical_length = domain_to_canonical(dnskey_rr->domain, canonical_domain);
        if (!EVP_DigestInit_ex(ctx, ds_digest_algorithm, NULL)
            || !EVP_DigestUpdate(ctx, canonical_domain, canonical_length)
            || !EVP_DigestUpdate(ctx, dnskey->rdata, dnskey->rdata_length)
            || !EVP_DigestFinal_ex(ctx, digest, &digest_size)) {
            goto exit;
        }

        if (ds->data.ds.digest_size == digest_size && memcmp(digest, ds->data.ds.digest, digest_size) == 0) {
            verified_dnskey_rr = dnskey_rr;
            break;
        }
    }
    if (verified_dnskey_rr == NULL) goto exit;
    DNSKEY *verified_dnskey = &verified_dnskey_rr->data.dnskey;

    time_t time_now = time(NULL);
    if (!(rrsig->inception_time <= time_now && time_now <= rrsig->expiration_time)) goto exit;
    if (strcmp(rrsig_rr->domain, verified_dnskey_rr->domain) != 0) goto exit;
    if (rrsig->type_covered != TYPE_DNSKEY) goto exit;
    if (strcmp(rrsig->signer_name, zone->domain) != 0) goto exit;
    if (rrsig->algorithm != verified_dnskey->algorithm) goto exit;
    if (rrsig->key_tag != verified_dnskey->key_tag) goto exit;
    if (strcmp(rrsig_rr->domain, verified_dnskey_rr->domain) != 0) goto exit;
    if (rrsig->labels > get_domain_labels_num(verified_dnskey_rr->domain)) goto exit;

    if ((rrsig_digest_algorithm = get_rrsig_digest_algorithm(verified_dnskey->algorithm)) == NULL) goto exit;
    if ((pkey = load_dnskey(verified_dnskey)) == NULL) goto exit;
    if (EVP_DigestVerifyInit(ctx, NULL, rrsig_digest_algorithm, NULL, pkey) != 1) goto exit;
    if (EVP_DigestVerifyUpdate(ctx, rrsig->rdata, rrsig->rdata_length) != 1) goto exit;

    if (!sort_rr_vec_canonically(dnskeys)) goto exit;

    for (uint32_t i = 0; i < dnskeys.length; i++) {
        RR *dnskey_rr = dnskeys.data[i];
        DNSKEY *dnskey = &dnskey_rr->data.dnskey;

        size_t canonical_length = domain_to_canonical(dnskey_rr->domain, canonical_domain);
        uint16_t type_net = htons(dnskey_rr->type);
        uint16_t class_net = htons(CLASS_IN);
        uint32_t ttl_net = htonl(rrsig->original_ttl);
        uint16_t rdata_length_net = htons(dnskey->rdata_length);

        if (EVP_DigestVerifyUpdate(ctx, canonical_domain, canonical_length) != 1
            || EVP_DigestVerifyUpdate(ctx, &type_net, sizeof(type_net)) != 1
            || EVP_DigestVerifyUpdate(ctx, &class_net, sizeof(class_net)) != 1
            || EVP_DigestVerifyUpdate(ctx, &ttl_net, sizeof(ttl_net)) != 1
            || EVP_DigestVerifyUpdate(ctx, &rdata_length_net, sizeof(rdata_length_net)) != 1
            || EVP_DigestVerifyUpdate(ctx, dnskey->rdata, dnskey->rdata_length) != 1) {
            goto exit;
        }
    }

    size_t signature_length;
    unsigned char *signature = load_signature(rrsig, &signature_length);
    if (signature == NULL) goto exit;

    if (EVP_DigestVerifyFinal(ctx, signature, signature_length) == 1) {
        result = true;

        // Move keys to the zone and reset `dnskeys` to avoid freeing them.
        zone->dnskeys = dnskeys;
        memset(&dnskeys, 0, sizeof(dnskeys));
    }

    free_signature(rrsig, signature);

exit:
    EVP_PKEY_free(pkey);
    free_rr(rrsig_rr);
    free_rr_vec(dnskeys);
    OPENSSL_free(digest);
    EVP_MD_CTX_free(ctx);
    return result;
}

static bool resolve_rec(Query *query, const char *domain, uint16_t qtype, bool is_subquery, RRVec *result) {
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
    uint16_t buffer_size = query->enable_edns ? EDNS_UDP_PAYLOAD_SIZE : STANDARD_UDP_PAYLOAD_SIZE;
    uint8_t buffer[buffer_size];
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

        if (query->enable_dnssec && zone->dnskeys.length == 0 && qtype != TYPE_DNSKEY) {
            if (!get_dnskeys(query, zone)) NAMESERVER_ERROR("Failed to get DNSKEYs for zone \"%s\".\n", zone->domain);
        }

        if (query->verbose) {
            printf("\n");

            const char *addr_str = inet_ntop(AF_INET, &nameserver->addr, addr_buffer, sizeof(addr_buffer));
            if (addr_str == NULL) addr_str = "invalid address";
            printf("Resolving %s using %s (%s).\n", sname, addr_str, zone->domain);
        }

        Request request = {
            .buffer = buffer,
            .size = buffer_size,
            .length = 0,
        };
        if (!write_request(&request, query->recursion_desired, sname, qtype, query->enable_edns, query->enable_cookie,
                           query->enable_dnssec, buffer_size, &nameserver->cookies, &id)) {
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
            default:                    unknown_rcode = true; break;
        }

        if (!validate_question(&response, qtype, sname)) NAMESERVER_ERROR("Invalid question in response.\n");

        if (response_header.answer_count > 0) {
            for (uint32_t i = 0; i < prev_rrs.length; i++) free_rr(prev_rrs.data[i]);
            VECTOR_RESET(&prev_rrs);

            // If qtype is ANY, terminate search after any response with answers section.
            if (qtype == QTYPE_ANY) found = true;

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

                if (rr->type == qtype || qtype == QTYPE_ANY || (qtype == TYPE_DNSKEY && rr->type == TYPE_RRSIG)) {
                    VECTOR_PUSH(result, rr);
                    // Set to NULL to avoid freeing it.
                    rr = NULL;
                    found = true;
                    continue;
                }

                if (rr->type == TYPE_CNAME) {
                    // Change sname to the alias.
                    memcpy(sname, rr->data.domain, strlen(rr->data.domain) + 1);
                    // Check previous RRs.
                    if (follow_cnames(&prev_rrs, sname, qtype, result)) found = true;
                }
            }
        }

        bool zone_has_domain = false;
        if (response_header.authority_count > 0) {
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
                } else if (rr->type == TYPE_DS) {
                    VECTOR_PUSH(&authority_zone.dss, rr);
                    // Set to NULL to avoid freeing it.
                    rr = NULL;
                }
            }
        }

        if (response_header.additional_count > 0) {
            bool has_opt = false;
            bool printed_section = false;
            uint16_t extended_rcode = 0;
            for (uint16_t i = 0; i < response_header.additional_count; i++) {
                if (!read_rr(&response, &rr)) NAMESERVER_ERROR("Invalid resource record.\n");

                if (rr->type == TYPE_OPT) {
                    if (!query->enable_edns) NAMESERVER_ERROR("Nameserver sent OPT although EDNS is disabled.\n");

                    if (has_opt) NAMESERVER_ERROR("Multiple OPT RRs in additional section.\n");
                    has_opt = true;

                    extended_rcode = (((uint16_t) rr->data.opt.extended_rcode) << 4) | response_header.rcode;

                    if (query->enable_cookie) {
                        if (nameserver->cookies.client != rr->data.opt.cookies.client) {
                            NAMESERVER_ERROR("Invalid client cookie.\n");
                        }

                        nameserver->cookies.server_size = rr->data.opt.cookies.server_size;
                        memcpy(nameserver->cookies.server, rr->data.opt.cookies.server,
                               nameserver->cookies.server_size);
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

            if (query->enable_edns && !has_opt) NAMESERVER_ERROR("Nameserver does not support EDNS.\n");

            unknown_rcode = false;
            switch (extended_rcode) {
                case RCODE_SUCCESS:
                case RCODE_NAME_ERROR: break;
                case RCODE_BAD_VERSION:
                    NAMESERVER_ERROR("Nameserver does not support EDNS version %d.\n", EDNS_VERSION);
                case RCODE_BAD_COOKIE:
                    // Retry with the new server cookie once before removing the nameserver.
                    if (nameserver->sent_bad_cookie) NAMESERVER_ERROR("Bad server cookie.\n");
                    nameserver->sent_bad_cookie = true;
                    continue;
                default: NAMESERVER_ERROR("Invalid or unsupported response code %d.\n", extended_rcode);
            }

            if (authority_zone.nameservers.length > 0 || authority_zone.nameserver_domains.length > 0) {
                VECTOR_PUSH(&query->zones, authority_zone);
                memset(&authority_zone, 0, sizeof(authority_zone));
            }
        } else if (query->enable_edns) {
            // Response does not have additional sections, and thus no OPT.
            NAMESERVER_ERROR("Nameserver does not support EDNS.\n");
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
    free_rr_vec(prev_rrs);
    free_rr(rr);
    free_zone(&authority_zone);
    return found;

#undef QUERY_ERROR
#undef NAMESERVER_ERROR
}

bool resolve(const char *domain, uint16_t qtype, const char *nameserver, uint16_t port, uint64_t timeout_ms,
             uint32_t flags, RRVec *result) {
    if (result == NULL || domain == NULL) return false;

    bool found = false;
    Query query = {
        .fd = -1,
        .port = port,
        .recursion_desired = !(flags & RESOLVE_DISABLE_RDFLAG),
        .enable_edns = !(flags & RESOLVE_DISABLE_EDNS),
        .enable_cookie = !(flags & RESOLVE_DISABLE_COOKIE),
        .enable_dnssec = !(flags & RESOLVE_DISABLE_DNSSEC),
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
    VECTOR_PUSH(&query.zones, zone);

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
