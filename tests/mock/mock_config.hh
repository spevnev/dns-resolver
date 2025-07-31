#include <cstdint>
#include "dns.hh"

struct MockResponse {
    bool set_wrong_id{false};
    bool is_truncated{false};
    OpCode opcode{OpCode::Query};
    bool is_response{true};
    RCode rcode{RCode::Success};
    bool copy_opt{true};
    bool set_wrong_client_cookie{false};
    bool add_server_cookie{true};

    std::vector<uint8_t> questions{};
    uint16_t questions_count{0};
    std::vector<uint8_t> answers{};
    uint16_t answers_count{0};
    std::vector<uint8_t> authority{};
    uint16_t authority_count{0};
    std::vector<uint8_t> additional{};
    uint16_t additional_count{0};
};

// Declared in each test case, defines the behavior of mocked functions.
extern MockResponse mock_response;

extern std::vector<uint8_t> request_buffer;
