#ifndef DNS_H
#define DNS_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include "vector.h"

#define DNS_PORT 53

#define MAX_DOMAIN_LENGTH 255
#define DOMAIN_SIZE (MAX_DOMAIN_LENGTH + 1)
#define CANONICAL_DOMAIN_SIZE 257

// Maximum allowed TTL (RFC2181).
#define MAX_TTL 2147483647

// Max payload size when using UDP without EDNS (RFC1035).
#define STANDARD_UDP_PAYLOAD_SIZE 512
// Recommended request payload size when using UDP with EDNS (RFC6891).
#define EDNS_UDP_PAYLOAD_SIZE 1280

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
#define CLASS_IN 1

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#define OPCODE_QUERY 0

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_SOA 6
#define TYPE_HINFO 13
#define TYPE_TXT 16
#define TYPE_AAAA 28
#define TYPE_OPT 41
#define TYPE_DS 43
#define TYPE_RRSIG 46
#define TYPE_DNSKEY 48
#define QTYPE_ANY 255

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
#define RCODE_SUCCESS 0
#define RCODE_FORMAT_ERROR 1
#define RCODE_SERVER_ERROR 2
#define RCODE_NAME_ERROR 3
#define RCODE_NOT_IMPLEMENTED 4
#define RCODE_REFUSED 5
#define RCODE_BAD_VERSION 16
#define RCODE_BAD_COOKIE 23

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
#define EDNS_VERSION 0

#define OPTION_HEADER_SIZE 4

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
#define OPT_COOKIE 10

// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
#define SECURITY_RSASHA1 5
#define SECURITY_RSASHA1NSEC3SHA1 7
#define SECURITY_RSASHA256 8
#define SECURITY_RSASHA512 10
#define SECURITY_ECDSAP256SHA256 13

// https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
#define DIGEST_SHA1 1
#define DIGEST_SHA256 2

#define DNSKEY_PROTOCOL 3

typedef struct {
    uint16_t id;
    union {
        uint16_t flags;
        struct {
            uint8_t recursion_desired : 1;
            uint8_t is_truncated : 1;
            uint8_t is_authoritative : 1;
            uint8_t opcode : 4;
            uint8_t is_response : 1;
            uint8_t rcode : 4;
            uint8_t checking_disabled : 1;
            uint8_t authentic_data : 1;
            uint8_t : 1;
            uint8_t recursion_available : 1;
        };
    };
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} DNSHeader;

typedef struct {
    char *buffer;
    uint32_t length;
    uint32_t capacity;
    // Dynamic array of string which are stored in the buffer.
    char **data;
} TXT;

// Struct to interpret OPT RR's ttl field (in network order).
typedef struct {
    uint8_t extended_rcode;
    uint8_t version;
    uint8_t : 7;
    uint8_t dnssec_ok : 1;
    uint8_t : 8;
} OptTtlFields;

typedef struct {
    uint64_t client;
    bool is_client_set;
    int server_size;
    uint8_t server[32];
} DNSCookies;

typedef struct {
    uint16_t udp_payload_size;
    uint8_t extended_rcode;
    DNSCookies cookies;
} OPT;

typedef struct {
    char *domain;
    uint16_t type;
    uint32_t ttl;
    union {
        in_addr_t ip4_addr;
        char *domain;
        struct {
            char *master_name;
            char *rname;
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t negative_ttl;
        } soa;
        struct {
            char *cpu;
            char *os;
        } hinfo;
        TXT txt;
        struct in6_addr ip6_addr;
        OPT opt;
        struct {
            uint16_t key_tag;
            uint8_t algorithm;
            uint8_t digest_type;
            uint8_t *digest;
            size_t digest_size;
        } ds;
        struct {
            uint16_t type_covered;
            uint8_t algorithm;
            uint8_t labels;
            uint32_t original_ttl;
            uint32_t expiration_time;
            uint32_t inception_time;
            uint16_t key_tag;
            char *signer_name;
            uint8_t *signature;
            size_t signature_size;
            uint8_t *rdata;
            uint16_t rdata_length;
        } rrsig;
        struct {
            union {
                uint16_t flags;
                struct {
                    uint8_t is_zone_key : 1;
                    uint8_t : 7;
                    uint8_t is_secure_entry : 1;
                    uint8_t : 7;
                };
            };
            uint8_t protocol;
            uint8_t algorithm;
            uint8_t *public_key;
            size_t public_key_size;
            uint16_t key_tag;
            uint8_t *rdata;
            uint16_t rdata_length;
        } dnskey;
    } data;
} RR;

VECTOR_TYPEDEF(RRVec, RR *);

typedef struct {
    uint8_t *buffer;
    uint32_t size;
    uint32_t length;
} Request;

typedef struct {
    const uint8_t *buffer;
    uint32_t length;
    uint32_t current;
} Response;

void print_rr(RR *rr);
void free_rr(RR *rr);

bool write_request(Request *request, bool recursion_desired, const char *domain, uint16_t qtype, bool enable_edns,
                   bool enable_cookie, bool enable_dnssec, uint16_t udp_payload_size, DNSCookies *cookies,
                   uint16_t *id_out);

bool read_response_header(Response *response, uint16_t request_id, DNSHeader *header_out);
bool validate_question(Response *response, uint16_t request_qtype, const char *request_domain);
bool read_rr(Response *response, RR **rr_out);

#endif  // DNS_H
