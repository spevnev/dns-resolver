#define _POSIX_C_SOURCE 200112L
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
#include <sys/types.h>
#include <unistd.h>
#include "dns.h"
#include "error.h"


static const char *NS_ADDRESS = "216.239.38.10";

static void usage(FILE *out_stream, const char *program) { fprintf(out_stream, "usage: %s domain\n", program); }

static void print_resource_record(ResourceRecord rr) {
    struct in_addr address = {.s_addr = rr.data.ip4_address};
    char buffer[16];
    if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == NULL) ERROR("Error in inet_ntop: %s", strerror(errno));
    printf("%s - %s\n", rr.domain, buffer);
}

static void resolve(const char *domain) {
    printf("Resolving %s\n", domain);

    // Get nameserver's address.
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_zero = {0},
    };
    if (inet_pton(AF_INET, NS_ADDRESS, &addr.sin_addr) != 1) ERROR("Error in inet_pton: %s", strerror(errno));

    // Open IPv4 UDP socket.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) ERROR("Error in socket: %s", strerror(errno));

    // Send request.
    uint8_t buffer[MAX_UDP_PAYLOAD_SIZE];
    ssize_t request_length = 0;

    uint16_t request_id = write_request_header(buffer + request_length, false, OPCODE_QUERY, 1);
    request_length += sizeof(DNSHeader);

    write_question(buffer + request_length, domain, TYPE_A);
    request_length += strlen(domain) + 6;

    if (sendto(fd, buffer, request_length, 0, (struct sockaddr *) &addr, sizeof(addr)) != request_length) {
        ERROR("Error in sendto: %s", strerror(errno));
    }

    // Read response.
    struct sockaddr_in response_addr;
    socklen_t response_addr_len = sizeof(response_addr);
    ssize_t response_length
        = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &response_addr, &response_addr_len);
    if (response_length == -1) ERROR("Error in recvfrom: %s", strerror(errno));

    if (response_addr_len != sizeof(response_addr) || addr.sin_addr.s_addr != response_addr.sin_addr.s_addr
        || addr.sin_port != response_addr.sin_port) {
        ERROR("TODO");
    }

    uint8_t *ptr = buffer;
    DNSHeader response_header;
    ptr = read_response_header(ptr, &response_header);

    // Validate response.
    if (!response_header.is_response) ERROR("Response is not an answer");
    if (response_header.id != request_id) ERROR("Request and response ids do not match");
    if (response_header.opcode != OPCODE_QUERY) ERROR("Request and response opcodes do not match");
    if (response_header.is_truncated) ERROR("TODO: truncated");
    if (response_header.question_count != 1) ERROR("TODO: server did not answer all questions");

    // Check errors.
    switch (response_header.response_code) {
        case RCODE_SUCCESS: break;
        case RCODE_NAME_ERROR:
            if (response_header.is_authoritative) {
                printf("Domain name does not exist");
                return;
            } else {
                ERROR("Name error");
            }
        case RCODE_FORMAT_ERROR:    ERROR("Format error");
        case RCODE_SERVER_ERROR:    ERROR("Server error");                       // TODO: retry
        case RCODE_NOT_IMPLEMENTED: ERROR("Server does not support the query");  // TODO: retry
        case RCODE_REFUSED:         ERROR("Server refused to answer");           // TODO: retry
        default:                    UNREACHABLE();
    }

    // Skip questions.
    for (uint16_t i = 0; i < response_header.question_count; i++) ptr = read_question(buffer, ptr);

    // Read resource records.
    ResourceRecord rr;
    if (response_header.answer_count > 0) printf("Answers:\n");
    for (uint16_t i = 0; i < response_header.answer_count; i++) {
        ptr = read_resource_record(buffer, ptr, &rr);
        print_resource_record(rr);
    }
    if (response_header.authority_count > 0) printf("Authoritative name servers:\n");
    for (uint16_t i = 0; i < response_header.authority_count; i++) {
        ptr = read_resource_record(buffer, ptr, &rr);
        print_resource_record(rr);
    }
    if (response_header.additional_count > 0) printf("Additional information:\n");
    for (uint16_t i = 0; i < response_header.additional_count; i++) {
        ptr = read_resource_record(buffer, ptr, &rr);
        print_resource_record(rr);
    }
}

int main(int argc, char **argv) {
    assert(argc > 0);
    const char *program = argv[0];

    if (argc != 2) {
        usage(stderr, program);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout, program);
    } else {
        resolve(argv[1]);
    }

    return EXIT_SUCCESS;
}
