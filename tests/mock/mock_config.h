#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    bool set_wrong_id;
    bool is_truncated;
    bool is_authoritative;
    uint8_t opcode;
    bool set_is_query;
    uint8_t rcode;
    bool authentic_data;
    bool recursion_available;
    bool disable_copy_opt;
    bool set_wrong_cookie;
    bool disable_server_cookie;

    const uint8_t *questions;
    size_t questions_length;
    uint16_t questions_count;
    const uint8_t *answers;
    size_t answers_length;
    uint16_t answers_count;
    const uint8_t *authority;
    size_t authority_length;
    uint16_t authority_count;
    const uint8_t *additional;
    size_t additional_length;
    uint16_t additional_count;
} MockResponse;

// Declared in each test case, defines behaviour of mocked functions.
extern MockResponse mock_response;

// Set and declared in sendto.
extern uint8_t request_buffer[];
extern size_t request_length;
