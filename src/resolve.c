#include "resolve.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
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

// https://www.iana.org/domains/root/servers
static const char *ROOT_NAMESERVER_IPS[] = {
    "198.41.0.4",    "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10", "192.5.5.241",  "192.112.36.4",
    "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",    "202.12.27.33",
};

static bool address_equals(struct sockaddr_in a, struct sockaddr_in b) {
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

static void add_domain(IPVec *servers, const char *ip_str) {
    in_addr_t ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) ERROR("Invalid IP address: %s", ip_str);
    VECTOR_PUSH(servers, ip);
}

static void add_root_servers(IPVec *servers) {
    // TODO: randomize order of servers?
    for (uint32_t i = 0; i < sizeof(ROOT_NAMESERVER_IPS) / sizeof(*ROOT_NAMESERVER_IPS); i++) {
        add_domain(servers, ROOT_NAMESERVER_IPS[i]);
    }
}

static void set_sname(const char *domain, char *sname) {
    size_t domain_len = strlen(domain);
    // Remove trailing dot.
    if (domain[domain_len - 1] == '.') domain_len--;

    // Check length.
    if (domain_len == 0) ERROR("Domain name is empty");
    if (domain_len > MAX_DOMAIN_LENGTH) ERROR("Invalid domain name, maximum length is %d", MAX_DOMAIN_LENGTH);

    memcpy(sname, domain, domain_len);
    sname[domain_len] = '\0';
}

static bool check_rrs(RRVec rrs, char *sname, uint16_t qtype) {
    bool restart;
    do {
        restart = false;
        for (uint32_t i = 0; i < rrs.length; i++) {
            ResourceRecord *rr = &rrs.data[i];
            if (strcasecmp(rr->domain, sname) != 0) continue;

            // Found it.
            if (rr->type == qtype) return true;

            // Follow CNAME and restart search with new name.
            if (rr->type == TYPE_CNAME) {
                set_sname(rr->data.domain, sname);
                restart = true;
                break;
            }
        }
    } while (restart);
    return false;
}

void resolve(const char *domain, const char *nameserver_ip, uint16_t port, uint16_t qtype, int timeout_sec,
             bool recursion_desired) {
    assert(domain != NULL && timeout_sec > 0);

    // Open IPv4 UDP socket.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) PERROR("socket");

    // Set receive and send timeout.
    struct timeval tv = {.tv_sec = timeout_sec, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");

    // Create list of nameservers.
    IPVec servers = {0};
    add_root_servers(&servers);
    if (nameserver_ip != NULL) add_domain(&servers, nameserver_ip);

    // Set initial search name.
    char sname[MAX_DOMAIN_LENGTH + 1];
    set_sname(domain, sname);

    bool found = false;
    ResourceRecord rr = {0};
    uint8_t buffer[MAX_UDP_PAYLOAD_SIZE];
    struct sockaddr_in req_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_zero = {0},
    };
    while (!found && servers.length > 0) {
        // Get nameserver IP.
        in_addr_t server_ip = VECTOR_POP(&servers);
        req_addr.sin_addr.s_addr = server_ip;

        char addr_buffer[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &server_ip, addr_buffer, sizeof(addr_buffer)) == NULL) PERROR("inet_ntop");
        printf("Resolving %s using %s.\n", sname, addr_buffer);

        // Send request.
        uint16_t id;
        ssize_t req_len = write_request(buffer, recursion_desired, sname, qtype, &id);
        if (sendto(fd, buffer, req_len, 0, (struct sockaddr *) &req_addr, sizeof(req_addr)) != req_len) {
            if (errno == EAGAIN) {  // timeout
                // Try other nameserver.
                fprintf(stderr, "Request timeout.\n");
                continue;
            } else {
                PERROR("sendto");
            }
        }

        // Read responses until we find one from the same address and port as in request.
        struct sockaddr_in res_addr;
        socklen_t res_addr_len;
        ssize_t res_len;
        bool retry = false;
        do {
            res_addr_len = sizeof(res_addr);
            res_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &res_addr, &res_addr_len);
            if (res_len == -1) {
                if (errno == EAGAIN) {  // timeout
                    retry = true;
                    break;
                } else {
                    PERROR("recvfrom");
                }
            }
        } while (res_addr_len != sizeof(res_addr) || !address_equals(req_addr, res_addr));
        if (retry) {
            // Try other nameserver.
            fprintf(stderr, "Request timeout.\n");
            continue;
        }

        // Reuse request buffer for response.
        const uint8_t *ptr = buffer;
        const uint8_t *buffer_end = buffer + res_len;

        // Read response header.
        DNSHeader res_header;
        ptr = read_response_header(ptr, buffer_end, &res_header, id);
        if (res_header.is_truncated) ERROR("TODO: truncated");

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
                fprintf(stderr, "Nameserver error.\n");
                continue;
            case RCODE_NOT_IMPLEMENTED:
                // Try other nameserver.
                fprintf(stderr, "Nameserver does not support this type of query.\n");
                continue;
            case RCODE_REFUSED:
                // Try other nameserver.
                fprintf(stderr, "Nameserver refused to answer.\n");
                continue;
            default: ERROR("Invalid or unsupported response code %d", res_header.response_code);
        }
        if (found) break;

        // Validate response question.
        ptr = validate_question(buffer, ptr, buffer_end, qtype, sname);

        // Read resource records.
        if (res_header.answer_count > 0) {
            RRVec prev_rrs = {0};
            printf("Answer section:\n");
            for (uint16_t i = 0; i < res_header.answer_count; i++) {
                ptr = read_resource_record(buffer, ptr, buffer_end, &rr);
                print_rr(&rr);

                if (strcasecmp(rr.domain, sname) != 0) {
                    VECTOR_PUSH(&prev_rrs, rr);
                    continue;
                }

                if (rr.type == qtype) {
                    // RR has matching domain and type. Set `found` and print the rest of the response.
                    found = true;
                } else if (rr.type == TYPE_CNAME) {
                    // Change sname to the alias.
                    set_sname(rr.data.domain, sname);
                    // Check previous RRs.
                    if (check_rrs(prev_rrs, sname, qtype)) found = true;
                }
                free_rr(&rr);
            }
            free_rrs(&prev_rrs);
        }

        CstrVec authority_domains = {0};
        if (res_header.authority_count > 0) {
            printf("Authority section:\n");
            for (uint16_t i = 0; i < res_header.authority_count; i++) {
                ptr = read_resource_record(buffer, ptr, buffer_end, &rr);
                print_rr(&rr);
                if (rr.type == TYPE_NS) {
                    char *domain = malloc(MAX_DOMAIN_LENGTH + 1);
                    if (domain == NULL) OUT_OF_MEMORY();
                    memcpy(domain, rr.data.domain, strlen(rr.data.domain) + 1);
                    VECTOR_PUSH(&authority_domains, domain);
                }
            }
        }

        if (res_header.additional_count > 0) {
            printf("Additional section:\n");
            for (uint16_t i = 0; i < res_header.additional_count; i++) {
                ptr = read_resource_record(buffer, ptr, buffer_end, &rr);
                print_rr(&rr);

                if (rr.type != TYPE_A) continue;

                for (uint32_t j = 0; j < authority_domains.length; j++) {
                    if (strcasecmp(authority_domains.data[j], rr.domain) == 0) {
                        VECTOR_PUSH(&servers, rr.data.ip4_address);
                        break;
                    }
                }
            }
        }
        VECTOR_FREE(&authority_domains);

        printf("\n");
    }
    if (!found) printf("Cannot resolve domain.\n");

    VECTOR_FREE(&servers);
    close(fd);
}
