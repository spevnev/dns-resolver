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

VECTOR_TYPEDEF(IPVec, in_addr_t);

typedef struct {
    int fd;
    uint64_t time_ns;
    uint64_t udp_timeout_ns;
    uint64_t time_left_ns;
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

static void update_time(Query *query) {
    uint64_t current_time_ns = get_time_ns();
    uint64_t time_diff_ns = current_time_ns - query->time_ns;
    if (time_diff_ns >= query->time_left_ns) ERROR("Timeout");

    query->time_left_ns -= time_diff_ns;
    query->time_ns = current_time_ns;

    if (query->time_left_ns < query->udp_timeout_ns) {
        set_timeout(query->fd, query->udp_timeout_ns);
        query->udp_timeout_ns = query->time_left_ns;
    }
}

static bool address_equals(struct sockaddr_in a, struct sockaddr_in b) {
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

static void add_nameserver(IPVec *servers, const char *ip_str) {
    in_addr_t ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) ERROR("Invalid IP address: %s", ip_str);
    VECTOR_PUSH(servers, ip);
}

static bool is_whitespace(char ch) { return ch == ' ' || ch == '\t'; }

static void load_resolve_config(IPVec *servers, bool verbose) {
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
            VECTOR_PUSH(servers, ip4_addr);
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
    if (!found) add_nameserver(servers, "127.0.0.1");
}

static bool check_rrs(RRVec *result, RRVec rrs, char *sname, uint16_t qtype) {
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
    update_time(query);
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
        update_time(query);
    } while (result != -1 && (address_length != sizeof(address) || !address_equals(request_address, address)));
    return result;
}

static RRVec resolve_rec(Query *query, const char *domain, uint16_t qtype, const char *nameserver_ip, uint16_t port,
                         uint32_t flags) {
    bool recursion_desired = flags & RESOLVE_RECURSION_DESIRED;
    bool enable_edns = flags & RESOLVE_EDNS;
    bool verbose = flags & RESOLVE_VERBOSE;

    // Create list of nameservers.
    IPVec servers = {0};
    if (nameserver_ip != NULL) {
        add_nameserver(&servers, nameserver_ip);
    } else {
        load_resolve_config(&servers, true);
    }

    // Set initial search name.
    char sname[DOMAIN_SIZE];
    if (domain == NULL) ERROR("Domain is null");
    size_t domain_len = strlen(domain);
    // Remove trailing dot.
    if (domain[domain_len - 1] == '.') domain_len--;
    if (domain_len > 0 && domain[domain_len - 1] == '.') ERROR("Invalid domain name, multiple trailing dots");
    if (domain_len > MAX_DOMAIN_LENGTH) ERROR("Invalid domain name, maximum length is %d", MAX_DOMAIN_LENGTH);

    memcpy(sname, domain, domain_len);
    sname[domain_len] = '\0';

    bool found = false;
    StrVec authority_domains = {0};
    RRVec result = {0};
    struct sockaddr_in req_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_zero = {0},
    };
    uint16_t buffer_size = EDNS_UDP_PAYLOAD_SIZE;
    uint8_t buffer[buffer_size];
    char addr_buffer[INET_ADDRSTRLEN];
    while (!found && servers.length > 0) {
        for (uint32_t i = 0; i < authority_domains.length; i++) free(authority_domains.data[i]);
        VECTOR_RESET(&authority_domains);

        // Get nameserver IP.
        in_addr_t server_ip = VECTOR_POP(&servers);
        req_addr.sin_addr.s_addr = server_ip;

        if (inet_ntop(AF_INET, &server_ip, addr_buffer, sizeof(addr_buffer)) == NULL) PERROR("inet_ntop");
        if (verbose) printf("Resolving %s using %s.\n", sname, addr_buffer);

        // Send request.
        Request request = {
            .buffer = buffer,
            .size = buffer_size,
            .length = 0,
        };
        uint16_t id = write_request(&request, recursion_desired, sname, qtype, enable_edns, buffer_size);
        if (udp_send(query, request, req_addr) != request.length) {
            if (errno == EAGAIN) {
                // Try other nameserver.
                if (verbose) fprintf(stderr, "Request timeout.\n");
                continue;
            } else {
                PERROR("sendto");
            }
        }

        ssize_t response_length = udp_receive(query, buffer, buffer_size, req_addr);
        if (response_length == -1) {
            if (errno == EAGAIN) {
                // Try other nameserver.
                if (verbose) fprintf(stderr, "Request timeout.\n");
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

        // Read response header.
        DNSHeader res_header = read_response_header(&response, id);
        if (res_header.is_truncated) ERROR("Response is truncated");

        // Check response code.
        switch (res_header.response_code) {
            case RCODE_SUCCESS: break;
            case RCODE_NAME_ERROR:
                if (!res_header.is_authoritative) ERROR("Name error");
                printf("Domain name does not exist.\n");
                found = true;
                break;
            case RCODE_FORMAT_ERROR: ERROR("Format error");
            case RCODE_SERVER_ERROR:
                // Try other nameserver.
                if (verbose) fprintf(stderr, "Nameserver error.\n");
                continue;
            case RCODE_NOT_IMPLEMENTED:
                // Try other nameserver.
                if (verbose) fprintf(stderr, "Nameserver does not support this type of query.\n");
                continue;
            case RCODE_REFUSED:
                // Try other nameserver.
                if (verbose) fprintf(stderr, "Nameserver refused to answer.\n");
                continue;
            default: ERROR("Invalid or unsupported response code %d", res_header.response_code);
        }
        if (found) break;

        // Validate response question.
        validate_question(&response, qtype, sname);

        // Read resource records.
        if (res_header.answer_count > 0) {
            // If qtype is ANY, terminate search after any response with answers section.
            if (qtype == QTYPE_ANY) found = true;

            RRVec prev_rrs = {0};
            if (verbose) printf("Answer section:\n");
            for (uint16_t i = 0; i < res_header.answer_count; i++) {
                ResourceRecord *rr = read_resource_record(&response);
                if (verbose) print_resource_record(rr);

                if (strcasecmp(rr->domain, sname) != 0) {
                    VECTOR_PUSH(&prev_rrs, rr);
                    continue;
                }

                if (rr->type == qtype || qtype == QTYPE_ANY) {
                    // RR has matching domain and type. Set `found` and print the rest of the response.
                    found = true;
                    VECTOR_PUSH(&result, rr);
                    continue;
                }

                if (rr->type == TYPE_CNAME) {
                    // Change sname to the alias.
                    memcpy(sname, rr->data.domain, strlen(rr->data.domain) + 1);
                    // Check previous RRs.
                    if (check_rrs(&result, prev_rrs, sname, qtype)) found = true;
                }
                free_rr(rr);
            }
            free_rr_vec(&prev_rrs);
        }

        if (res_header.authority_count > 0) {
            if (verbose) printf("Authority section:\n");
            for (uint16_t i = 0; i < res_header.authority_count; i++) {
                ResourceRecord *rr = read_resource_record(&response);
                if (verbose) print_resource_record(rr);

                if (rr->type == TYPE_NS) {
                    size_t domain_length = strlen(rr->data.domain) + 1;
                    char *domain = malloc(domain_length * sizeof(*domain));
                    if (domain == NULL) OUT_OF_MEMORY();
                    memcpy(domain, rr->data.domain, domain_length);
                    VECTOR_PUSH(&authority_domains, domain);
                }
                free_rr(rr);
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
                    free_rr(rr);
                    continue;
                }

                if (verbose) {
                    if (!printed_section) {
                        printed_section = true;
                        printf("Additional section:\n");
                    }
                    print_resource_record(rr);
                }

                if (rr->type != TYPE_A) {
                    free_rr(rr);
                    continue;
                }

                for (uint32_t j = 0; j < authority_domains.length; j++) {
                    if (strcasecmp(authority_domains.data[j], rr->domain) == 0) {
                        VECTOR_PUSH(&servers, rr->data.ip4_address);
                        free(authority_domains.data[j]);
                        // Delete current element by overwriting it with the last one.
                        // If we are deleting the last one, we end up reassigning it
                        // to itself and decreasing length.
                        authority_domains.data[j] = VECTOR_POP(&authority_domains);
                        break;
                    }
                }
                free_rr(rr);
            }
            if (!enable_edns && contains_opt) ERROR("Nameserver sent OPT although EDNS is disabled");
            if (enable_edns && !contains_opt) {
                // Try other nameserver.
                if (verbose) fprintf(stderr, "Nameserver does not support EDNS.\n");
                continue;
            }

            switch (extended_response_code) {
                case RCODE_SUCCESS: break;
                case RCODE_BAD_VERSION:
                    // Try other nameserver.
                    if (verbose) fprintf(stderr, "Nameserver does not support EDNS version %d.\n", EDNS_VERSION);
                    continue;
                default: ERROR("Invalid or unsupported response code %d", extended_response_code);
            }
        }
        if (verbose) printf("\n");

        for (uint32_t i = 0; i < authority_domains.length; i++) {
            RRVec authority_addresses
                = resolve_rec(query, authority_domains.data[i], TYPE_A, nameserver_ip, port, flags);
            for (uint32_t j = 0; j < authority_addresses.length; j++) {
                VECTOR_PUSH(&servers, authority_addresses.data[j]->data.ip4_address);
            }
            free_rr_vec(&authority_addresses);
        }
    }
    if (!found) printf("Failed to resolve the domain.\n");

    VECTOR_FREE(&servers);
    for (uint32_t i = 0; i < authority_domains.length; i++) free(authority_domains.data[i]);
    VECTOR_FREE(&authority_domains);

    return result;
}

RRVec resolve(const char *domain, uint16_t qtype, const char *nameserver_ip, uint16_t port, uint64_t timeout_ms,
              uint32_t flags) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) PERROR("socket");

    // Timeout to receive/send over UDP.
    uint64_t udp_timeout_ns = MAX(timeout_ms / 5, MIN_QUERY_TIMEOUT_MS) * NS_IN_MS;
    set_timeout(fd, udp_timeout_ns);

    Query query = {
        .fd = fd,
        .time_ns = get_time_ns(),
        .udp_timeout_ns = udp_timeout_ns,
        .time_left_ns = timeout_ms * NS_IN_MS,
    };
    RRVec result = resolve_rec(&query, domain, qtype, nameserver_ip, port, flags);
    close(fd);

    return result;
}

void free_rr_vec(RRVec *rr_vec) {
    for (uint32_t i = 0; i < rr_vec->length; i++) free_rr(rr_vec->data[i]);
    VECTOR_FREE(rr_vec);
}
