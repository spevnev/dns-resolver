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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "dns.h"
#include "error.h"

static void print_resource_record(ResourceRecord rr) {
    char buffer[16];
    struct in_addr addr = {.s_addr = rr.data.ip4_address};
    if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == NULL) PERROR("inet_ntop");
    printf("%s - %s\n", rr.domain, buffer);
}

void resolve(char *domain, const char *nameserver_ip, uint16_t qtype, int timeout_sec, bool recursion_desired) {
    assert(domain != NULL && nameserver_ip != NULL && timeout_sec > 0);

    printf("Resolving %s using %s\n", domain, nameserver_ip);

    // Check domain.
    size_t domain_len = strlen(domain);
    if (domain_len == 0) ERROR("Domain name is empty");
    if (domain[domain_len - 1] == '.') {
        // Remove trailing dot.
        domain[domain_len - 1] = '\0';
        domain_len--;
    }
    if (domain_len > MAX_DOMAIN_LENGTH) ERROR("Invalid domain name, maximum length is %d", MAX_DOMAIN_LENGTH);

    // Get nameserver's address.
    struct sockaddr_in req_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_zero = {0},
    };
    if (inet_pton(AF_INET, nameserver_ip, &req_addr.sin_addr) != 1) {
        ERROR("Invalid nameserver IP address: %s", nameserver_ip);
    }

    // Open IPv4 UDP socket.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) PERROR("socket");

    // Set receive and send timeout.
    struct timeval tv = {.tv_sec = timeout_sec, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) PERROR("setsockopt");

    // Send request.
    uint8_t buffer[MAX_UDP_PAYLOAD_SIZE];
    uint16_t id;
    ssize_t req_len = write_request(buffer, recursion_desired, domain, qtype, &id);
    if (sendto(fd, buffer, req_len, 0, (struct sockaddr *) &req_addr, sizeof(req_addr)) != req_len) {
        if (errno == EAGAIN) {
            ERROR("Request timeout");
            // TODO: retry
        } else {
            PERROR("sendto");
        }
    }

    // Read responses until we find one from the same address and port as in request.
    struct sockaddr_in res_addr;
    socklen_t res_addr_len;
    ssize_t res_len;
    do {
        res_addr_len = sizeof(res_addr);
        res_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &res_addr, &res_addr_len);
        if (res_len == -1) {
            if (errno == EAGAIN) {
                ERROR("Response timeout");
                // TODO: retry
            } else {
                PERROR("recvfrom");
            }
        }
    } while (res_addr_len != sizeof(res_addr) || req_addr.sin_addr.s_addr != res_addr.sin_addr.s_addr
             || req_addr.sin_port != res_addr.sin_port);

    // Reuse request buffer for response.
    const uint8_t *ptr = buffer;
    const uint8_t *buffer_end = buffer + res_len;

    // Read header.
    DNSHeader res_header;
    ptr = read_response_header(ptr, buffer_end, &res_header, id);
    if (res_header.is_truncated) ERROR("TODO: truncated");

    // Check errors.
    switch (res_header.response_code) {
        case RCODE_SUCCESS: break;
        case RCODE_NAME_ERROR:
            if (res_header.is_authoritative) {
                printf("Domain name does not exist");
                return;
            } else {
                ERROR("Name error");
            }
        case RCODE_FORMAT_ERROR:    ERROR("Format error");
        case RCODE_SERVER_ERROR:    ERROR("Nameserver error");                                // TODO: retry
        case RCODE_NOT_IMPLEMENTED: ERROR("Nameserver does not support this type of query");  // TODO: retry
        case RCODE_REFUSED:         ERROR("Nameserver refused to answer");                    // TODO: retry
        default:                    ERROR("Invalid or unsupported response code %d", res_header.response_code);
    }

    printf("Is authoritative: %s\n", res_header.is_authoritative ? "true" : "false");

    ptr = validate_question(buffer, ptr, buffer_end, qtype, domain);

    // Read resource records.
    ResourceRecord rr;
    if (res_header.answer_count > 0) printf("Answers:\n");
    for (uint16_t i = 0; i < res_header.answer_count; i++) {
        ptr = read_resource_record(buffer, ptr, buffer_end, &rr);
        print_resource_record(rr);
    }
    if (res_header.authority_count > 0) printf("Authoritative name servers:\n");
    for (uint16_t i = 0; i < res_header.authority_count; i++) {
        ptr = read_resource_record(buffer, ptr, buffer_end, &rr);
        print_resource_record(rr);
    }
    if (res_header.additional_count > 0) printf("Additional information:\n");
    for (uint16_t i = 0; i < res_header.additional_count; i++) {
        ptr = read_resource_record(buffer, ptr, buffer_end, &rr);
        print_resource_record(rr);
    }

    close(fd);
}
