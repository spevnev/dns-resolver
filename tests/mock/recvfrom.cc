#include <arpa/inet.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>
#include "config.hh"
#include "dns.hh"
#include "mock_config.hh"

namespace {
class buffer_overflow_error : std::runtime_error {
public:
    buffer_overflow_error() : std::runtime_error("Buffer is too small") {}
};

size_t get_domain_length(const uint8_t *buffer) {
    size_t length = 1;

    while (*buffer != 0) {
        assert(*buffer <= MAX_LABEL_LENGTH);
        uint8_t len = *buffer + 1;

        length += len;
        buffer += len;
    }

    return length;
}

void copy(const uint8_t *&src, size_t &src_size, uint8_t *&dest, size_t &dest_size, size_t length) {
    assert(length <= src_size);
    if (length > dest_size) throw buffer_overflow_error();
    std::memcpy(dest, src, length);
    src += length;
    src_size -= length;
    dest += length;
    dest_size -= length;
}

void copy(const std::vector<uint8_t> &src, uint8_t *&dest, size_t &dest_size) {
    if (src.size() > dest_size) throw buffer_overflow_error();
    std::memcpy(dest, src.data(), src.size());
    dest += src.size();
    dest_size -= src.size();
}

template <typename T>
void write(T src, uint8_t *&dest, size_t &dest_size) {
    if (sizeof(T) > dest_size) throw buffer_overflow_error();
    std::memcpy(dest, &src, sizeof(T));
    dest += sizeof(T);
    dest_size -= sizeof(T);
}

template <typename T>
    requires std::is_trivially_copyable_v<T>
T read(const uint8_t *&src, size_t &src_size) {
    assert(sizeof(T) <= src_size);
    T dest;
    std::memcpy(&dest, src, sizeof(T));
    src += sizeof(T);
    src_size -= sizeof(T);
    return dest;
}

void skip(const uint8_t *&src, size_t &src_size, size_t length) {
    assert(length <= src_size);
    src += length;
    src_size -= length;
}
}  // namespace

extern "C" {
ssize_t recvfrom(int _fd, void *buf, size_t n, int _flags, struct sockaddr *addr, socklen_t *addr_len) {
    (void) _fd;
    (void) _flags;

    const uint8_t *src = request_buffer.data();
    auto src_size = request_buffer.size();
    auto *dest = reinterpret_cast<uint8_t *>(buf);
    auto dest_size = n;

    struct sockaddr_in ip_addr;
    ip_addr.sin_family = AF_INET;
    ip_addr.sin_port = htons(TEST_RESOLVER_CONFIG.port);

    auto result = inet_pton(AF_INET, TEST_RESOLVER_CONFIG.nameserver->c_str(), &ip_addr.sin_addr);
    assert(result == 1);

    assert(addr_len != nullptr && addr != nullptr);
    assert(*addr_len >= sizeof(ip_addr));
    auto *ip_addr_out = reinterpret_cast<struct sockaddr_in *>(addr);
    *ip_addr_out = ip_addr;
    *addr_len = sizeof(ip_addr);

    try {
        if (mock_response.set_wrong_id) {
            auto id = read<uint16_t>(src, src_size);
            write(id + 1, dest, dest_size);
        } else {
            copy(src, src_size, dest, dest_size, 2);
        }

        skip(src, src_size, 2);
        uint16_t flags
            = (static_cast<uint16_t>(mock_response.opcode) << 11) | (std::to_underlying(mock_response.rcode) & 0b1111);
        if (mock_response.is_response) flags |= 1 << 15;
        if (mock_response.is_truncated) flags |= 1 << 9;
        write(htons(flags), dest, dest_size);

        auto request_question_count = ntohs(read<uint16_t>(src, src_size));
        auto question_count
            = mock_response.questions_count > 0 ? mock_response.questions_count : request_question_count;
        write(htons(question_count), dest, dest_size);

        skip(src, src_size, 2);
        write(htons(mock_response.answers_count), dest, dest_size);

        skip(src, src_size, 2);
        write(htons(mock_response.authority_count), dest, dest_size);

        auto request_additional_count = ntohs(read<uint16_t>(src, src_size));
        uint16_t additional_count
            = mock_response.additional_count + (mock_response.copy_opt ? request_additional_count : 0);
        write(htons(additional_count), dest, dest_size);

        auto question_size = get_domain_length(src) + 4;
        if (mock_response.questions_count > 0) {
            copy(mock_response.questions, dest, dest_size);
            skip(src, src_size, question_size);
        } else {
            copy(src, src_size, dest, dest_size, question_size);
        }

        copy(mock_response.answers, dest, dest_size);
        copy(mock_response.authority, dest, dest_size);

        // OPT should come last so copy the remaining part of the request.
        if (mock_response.copy_opt) {
            // Check whether request has cookies enabled, and whether server cookie was sent.
            bool has_cookies = false;
            bool has_server_cookie = false;
            if (src_size >= 23) {
                auto cookie_opt = htons(std::to_underlying(OptionCode::Cookies));
                if (std::memcmp(src + 11, &cookie_opt, sizeof(cookie_opt)) == 0) has_cookies = true;

                uint16_t opt_length_net;
                std::memcpy(&opt_length_net, src + 13, sizeof(opt_length_net));
                if (ntohs(opt_length_net) > 8) has_server_cookie = true;
            }

            auto *extended_rcode_ptr = dest + 5;
            auto *opt_length_ptr = dest + 9;
            auto *cookies_length_ptr = dest + 13;
            auto *cookies_client_ptr = dest + 15;
            copy(src, src_size, dest, dest_size, src_size);

            *extended_rcode_ptr = std::to_underlying(mock_response.rcode) >> 4;
            if (mock_response.set_wrong_client_cookie && has_cookies) *cookies_client_ptr = *cookies_client_ptr + 1;

            // Append a server cookie to the response, adjust the lengths.
            if (mock_response.add_server_cookie && has_cookies && !has_server_cookie) {
                uint64_t server_cookie;
                int result = getrandom(&server_cookie, sizeof(server_cookie), 0);
                assert(result == sizeof(server_cookie));
                write(server_cookie, dest, dest_size);

                // Update OPT data length.
                uint16_t current_opt_length_net;
                std::memcpy(&current_opt_length_net, opt_length_ptr, sizeof(current_opt_length_net));
                uint16_t new_opt_length_net = htons(ntohs(current_opt_length_net) + sizeof(server_cookie));
                std::memcpy(opt_length_ptr, &new_opt_length_net, sizeof(new_opt_length_net));

                // Update COOKIE length.
                uint16_t new_cookies_length_net = htons(16);
                std::memcpy(cookies_length_ptr, &new_cookies_length_net, sizeof(new_cookies_length_net));
            }
        }
        copy(mock_response.additional, dest, dest_size);
    } catch (const buffer_overflow_error &) {
    }
    return n - dest_size;
}
}
