#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>
#include "config.h"
#include "dns.h"
#include "mock_config.h"

static size_t get_domain_length(const uint8_t *buffer) {
    size_t length = 1;

    while (*buffer != 0) {
        assert(*buffer < 64);
        uint8_t len = *buffer + 1;

        length += len;
        buffer += len;
    }

    return length;
}

ssize_t recvfrom(int fd, void *buffer, size_t buffer_size, int flags, struct sockaddr *addr, socklen_t *addr_len) {
    (void) fd;
    (void) flags;

    ssize_t initial_buffer_size = buffer_size;
    const uint8_t *request_current = request_buffer;

    struct sockaddr_in ip_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_PORT),
        .sin_zero = {0},
    };
    int result = inet_pton(AF_INET, TEST_IP, &ip_addr.sin_addr);
    assert(result == 1);

    memcpy(addr, &ip_addr, sizeof(ip_addr));
    *addr_len = sizeof(ip_addr);

    DNSHeader request_header = {0};
    assert(request_length >= sizeof(request_header));
    request_length -= sizeof(request_header);
    memcpy(&request_header, request_current, sizeof(request_header));
    request_current += sizeof(request_header);

    bool opt_count = ntohs(request_header.additional_count);
    bool copy_questions = mock_response.questions == NULL;

    DNSHeader header = {
        .id = request_header.id + mock_response.set_wrong_id,
        .recursion_desired = request_header.recursion_desired,
        .is_truncated = mock_response.is_truncated,
        .is_authoritative = mock_response.is_authoritative,
        .opcode = mock_response.opcode,
        .is_response = !mock_response.set_is_query,
        .rcode = mock_response.rcode,
        .checking_disabled = request_header.checking_disabled,
        .authentic_data = mock_response.authentic_data,
        ._reserved = 0,
        .recursion_available = mock_response.recursion_available,
        .question_count = copy_questions ? request_header.question_count : htons(mock_response.questions_count),
        .answer_count = htons(mock_response.answers_count),
        .authority_count = htons(mock_response.authority_count),
        .additional_count = htons(mock_response.additional_count + (mock_response.disable_copy_opt ? 0 : opt_count)),
    };

    uint8_t *current = buffer;

#define COPY(src, src_size)                                                     \
    do {                                                                        \
        if (buffer_size < (src_size)) return initial_buffer_size - buffer_size; \
        buffer_size -= src_size;                                                \
        memcpy(current, (src), (src_size));                                     \
        current += src_size;                                                    \
    } while (0)

    COPY(&header, sizeof(header));

    assert(htons(request_header.question_count) == 1);
    size_t question_size = get_domain_length(current) + sizeof(uint16_t) + sizeof(uint16_t);
    if (copy_questions) {
        COPY(request_current, question_size);
    } else {
        COPY(mock_response.questions, mock_response.questions_length);
    }
    request_current += question_size;
    assert(request_length >= question_size);
    request_length -= question_size;

    COPY(mock_response.answers, mock_response.answers_length);
    COPY(mock_response.authority, mock_response.authority_length);

    // OPT should come last so copy the remaining part of the request.
    if (!mock_response.disable_copy_opt) {
        // Check whether request has cookies enabled, and whether server cookie was sent.
        bool has_cookies = false;
        bool has_server_cookie = false;
        if (request_length >= 23) {
            uint16_t cookie_opt = htons(OPT_COOKIE);
            if (memcmp(request_current + 11, &cookie_opt, sizeof(cookie_opt)) == 0) has_cookies = true;

            uint16_t opt_length_net;
            memcpy(&opt_length_net, request_current + 13, sizeof(opt_length_net));
            if (ntohs(opt_length_net) > 8) has_server_cookie = true;
        }

        uint8_t *opt_length_ptr = current + 9;
        uint8_t *cookies_length_ptr = current + 13;
        uint8_t *cookies_client_ptr = current + 15;
        COPY(request_current, request_length);
        request_current += request_length;
        request_length = 0;

        if (mock_response.set_wrong_cookie && has_cookies) *cookies_client_ptr = *cookies_client_ptr + 1;

        // Append a server cookie to the response, adjust lengths.
        if (!mock_response.disable_server_cookie && has_cookies && !has_server_cookie) {
            uint64_t server_cookie;
            int result = getrandom(&server_cookie, sizeof(server_cookie), 0);
            assert(result == sizeof(server_cookie));
            COPY(&server_cookie, sizeof(server_cookie));

            // Update OPT data length.
            uint16_t current_opt_length_net;
            memcpy(&current_opt_length_net, opt_length_ptr, sizeof(current_opt_length_net));
            uint16_t new_opt_length_net = htons(ntohs(current_opt_length_net) + sizeof(server_cookie));
            memcpy(opt_length_ptr, &new_opt_length_net, sizeof(new_opt_length_net));

            // Update COOKIE length.
            uint16_t new_cookies_length_net = htons(16);
            memcpy(cookies_length_ptr, &new_cookies_length_net, sizeof(new_cookies_length_net));
        }
    }
    COPY(mock_response.additional, mock_response.additional_length);

    return initial_buffer_size - buffer_size;
}
