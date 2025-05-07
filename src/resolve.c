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
#include <unistd.h>
#include "dns.h"
#include "error.h"
#include "vector.h"

VECTOR_TYPEDEF(IPVec, in_addr_t);

#define RESOLV_CONF_PATH "/etc/resolv.conf"

static bool address_equals(struct sockaddr_in a, struct sockaddr_in b) {
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

static void add_ns(IPVec *servers, const char *ip_str) {
    in_addr_t ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) ERROR("Invalid IP address: %s", ip_str);
    VECTOR_PUSH(servers, ip);
}

static bool is_whitespace(char ch) { return ch == ' ' || ch == '\t'; }

static void load_resolve_config(IPVec *servers, bool trace) {
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
            if (trace) printf("IPv6 is not supported.\n");
        } else {
            ERROR("Invalid nameserver address in %s", RESOLV_CONF_PATH);
        }
    }
    if (!feof(fp)) ERROR("Failed to read %s: %s", RESOLV_CONF_PATH, strerror(errno));
    free(line);
    fclose(fp);

    // If no nameserver entries are present, the default is to use the local nameserver.
    if (!found) add_ns(servers, "127.0.0.1");
}

static bool check_rrs(RRVec *results, RRVec rrs, char *sname, uint16_t qtype) {
    bool found = false;
    bool restart;
    do {
        restart = false;
        for (uint32_t i = 0; i < rrs.length; i++) {
            ResourceRecord *rr = &rrs.data[i];
            if (strcasecmp(rr->domain, sname) != 0) continue;

            // Found it.
            if (rr->type == qtype) {
                VECTOR_PUSH(results, *rr);
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

RRVec resolve(const char *domain, uint16_t qtype, const char *nameserver_ip, uint16_t port, int timeout_sec,
              uint32_t flags) {
    assert(domain != NULL && timeout_sec > 0);

    bool recursion_desired = flags & RESOLVE_RECURSION_DESIRED;
    bool enable_edns = flags & RESOLVE_EDNS;
    bool trace = flags & RESOLVE_TRACE;

    // Open IPv4 UDP socket.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) PERROR("socket");

    // Set receive and send timeout.
    struct timeval tv = {.tv_sec = timeout_sec, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");

    // Create list of nameservers.
    IPVec servers = {0};
    if (nameserver_ip != NULL) {
        add_ns(&servers, nameserver_ip);
    } else {
        load_resolve_config(&servers, true);
    }

    // Set initial search name.
    char sname[DOMAIN_SIZE];
    size_t domain_len = strlen(domain);
    // Remove trailing dot.
    if (domain[domain_len - 1] == '.') domain_len--;
    if (domain_len > 0 && domain[domain_len - 1] == '.') ERROR("Invalid domain name, multiple trailing dots");
    if (domain_len > MAX_DOMAIN_LENGTH) ERROR("Invalid domain name, maximum length is %d", MAX_DOMAIN_LENGTH);

    memcpy(sname, domain, domain_len);
    sname[domain_len] = '\0';

    bool found = false;
    RRVec results = {0};
    ResourceRecord rr = {0};
    struct sockaddr_in req_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_zero = {0},
    };
    uint16_t buffer_size = EDNS_UDP_PAYLOAD_SIZE;
    uint8_t buffer[buffer_size];
    while (!found && servers.length > 0) {
        // Get nameserver IP.
        in_addr_t server_ip = VECTOR_POP(&servers);
        req_addr.sin_addr.s_addr = server_ip;

        char addr_buffer[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &server_ip, addr_buffer, sizeof(addr_buffer)) == NULL) PERROR("inet_ntop");
        if (trace) printf("Resolving %s using %s.\n", sname, addr_buffer);

        // Send request.
        Request request = {
            .buffer = buffer,
            .size = buffer_size,
            .length = 0,
        };
        uint16_t id = write_request(&request, recursion_desired, sname, qtype, buffer_size, enable_edns);
        if (sendto(fd, request.buffer, request.length, 0, (struct sockaddr *) &req_addr, sizeof(req_addr))
            != request.length) {
            if (errno == EAGAIN) {
                // Try other nameserver.
                if (trace) fprintf(stderr, "Request timeout.\n");
                continue;
            } else {
                PERROR("sendto");
            }
        }

        // Read responses until we find one from the same address and port as in request.
        struct sockaddr_in response_address;
        socklen_t response_address_length;
        ssize_t response_length;
        bool timed_out = false;
        do {
            response_address_length = sizeof(response_address);
            response_length = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &response_address,
                                       &response_address_length);
            if (response_length == -1) {
                if (errno == EAGAIN) {
                    timed_out = true;
                    break;
                } else {
                    PERROR("recvfrom");
                }
            }
        } while (response_address_length != sizeof(response_address) || !address_equals(req_addr, response_address));
        if (timed_out) {
            // Try other nameserver.
            if (trace) fprintf(stderr, "Request timeout.\n");
            continue;
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
                if (trace) fprintf(stderr, "Nameserver error.\n");
                continue;
            case RCODE_NOT_IMPLEMENTED:
                // Try other nameserver.
                if (trace) fprintf(stderr, "Nameserver does not support this type of query.\n");
                continue;
            case RCODE_REFUSED:
                // Try other nameserver.
                if (trace) fprintf(stderr, "Nameserver refused to answer.\n");
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
            if (trace) printf("Answer section:\n");
            for (uint16_t i = 0; i < res_header.answer_count; i++) {
                read_resource_record(&response, &rr);
                if (trace) print_resource_record(&rr);

                if (strcasecmp(rr.domain, sname) != 0) {
                    VECTOR_PUSH(&prev_rrs, rr);
                    continue;
                }

                if (rr.type == qtype || qtype == QTYPE_ANY) {
                    // RR has matching domain and type. Set `found` and print the rest of the response.
                    found = true;
                    VECTOR_PUSH(&results, rr);
                } else if (rr.type == TYPE_CNAME) {
                    // Change sname to the alias.
                    memcpy(sname, rr.data.domain, strlen(rr.data.domain) + 1);
                    // Check previous RRs.
                    if (check_rrs(&results, prev_rrs, sname, qtype)) found = true;
                }
            }
            VECTOR_FREE(&prev_rrs);
        }

        CstrVec authority_domains = {0};
        if (res_header.authority_count > 0) {
            if (trace) printf("Authority section:\n");
            for (uint16_t i = 0; i < res_header.authority_count; i++) {
                read_resource_record(&response, &rr);
                if (trace) print_resource_record(&rr);

                if (rr.type == TYPE_NS) {
                    char *domain = malloc(DOMAIN_SIZE * sizeof(*domain));
                    if (domain == NULL) OUT_OF_MEMORY();
                    memcpy(domain, rr.data.domain, strlen(rr.data.domain) + 1);
                    VECTOR_PUSH(&authority_domains, domain);
                }
            }
        }

        if (res_header.additional_count > 0) {
            bool contains_opt = false;
            bool printed_section = false;
            uint16_t extended_response_code = 0;
            for (uint16_t i = 0; i < res_header.additional_count; i++) {
                read_resource_record(&response, &rr);
                if (rr.type == TYPE_OPT) {
                    contains_opt = true;
                    extended_response_code = (((uint16_t) rr.data.opt.extended_rcode) << 4) | res_header.response_code;
                    continue;
                }

                if (trace) {
                    if (!printed_section) {
                        printed_section = true;
                        printf("Additional section:\n");
                    }
                    print_resource_record(&rr);
                }

                if (rr.type != TYPE_A) continue;
                for (uint32_t j = 0; j < authority_domains.length; j++) {
                    if (strcasecmp(authority_domains.data[j], rr.domain) == 0) {
                        VECTOR_PUSH(&servers, rr.data.ip4_address);
                        // Delete current element by overwriting it with the last one.
                        // If we are deleting the last one, we end up reassigning it
                        // to itself and decreasing length.
                        authority_domains.data[j] = VECTOR_POP(&authority_domains);
                        break;
                    }
                }
            }
            if (!enable_edns && contains_opt) ERROR("Nameserver sent OPT although EDNS is disabled");
            if (enable_edns && !contains_opt) {
                // Try other nameserver.
                if (trace) fprintf(stderr, "Nameserver does not support EDNS.\n");
                continue;
            }

            switch (extended_response_code) {
                case RCODE_SUCCESS: break;
                case RCODE_BAD_VERSION:
                    // Try other nameserver.
                    if (trace) fprintf(stderr, "Nameserver does not support EDNS version %d.\n", EDNS_VERSION);
                    continue;
                default: ERROR("Invalid or unsupported response code %d", extended_response_code);
            }
        }
        if (trace) printf("\n");

        for (uint32_t i = 0; i < authority_domains.length; i++) {
            RRVec ns_addr = resolve(authority_domains.data[i], TYPE_A, nameserver_ip, port, timeout_sec, flags);
            for (uint32_t j = 0; j < ns_addr.length; j++) VECTOR_PUSH(&servers, ns_addr.data[j].data.ip4_address);
        }
        VECTOR_FREE(&authority_domains);
    }
    if (!found) printf("Failed to resolve the domain.\n");

    VECTOR_FREE(&servers);
    close(fd);

    return results;
}
