#include "resolve.hh"

#define UNSIGNED_DOMAIN "unsigned.com."
static const ResolverConfig UNSIGNED_RESOLVER_CONFIG{
    .timeout_ms = 500,
    .nameserver = NameserverConfig{.address = "127.0.0.1"},
    .use_root_nameservers = false,
    .use_resolve_config = false,
    .port = 1053,
    .dnssec = FeatureState::Disable,
};

#define SIGNED_DOMAIN "signed.com."
static const ResolverConfig SIGNED_RESOLVER_CONFIG{
    .timeout_ms = 500,
    .nameserver = NameserverConfig{
        .address = "127.0.0.1",
        .zone_domain = SIGNED_DOMAIN,
        .dss = {DS{
            .key_tag = 22197,
            .signing_algorithm = SigningAlgorithm::ECDSAP256SHA256,
            .digest_algorithm = DigestAlgorithm::SHA256,
            .digest = {0x11, 0xB5, 0x5D, 0x67, 0xF6, 0x98, 0x97, 0xB5, 0xAC, 0x5C, 0xF7,
                        0xF3, 0x75, 0x73, 0x00, 0x84, 0xA0, 0x3A, 0xC0, 0xAD, 0x59, 0xDA,
                        0xAD, 0xA9, 0xA9, 0x96, 0x57, 0x71, 0x82, 0x17, 0x99, 0x2D},
            .data = {},
        }},
    },
    .use_root_nameservers = false,
    .use_resolve_config = false,
    .port = 1053,
    .dnssec = FeatureState::Require,
};

#define NSEC3_SIGNED_DOMAIN "nsec3-signed.com."
static const ResolverConfig NSEC3_SIGNED_RESOLVER_CONFIG {
    .timeout_ms = 500,
    .nameserver = NameserverConfig{
        .address = "127.0.0.1",
        .zone_domain = NSEC3_SIGNED_DOMAIN,
        .dss = {DS{
            .key_tag = 32475,
            .signing_algorithm = SigningAlgorithm::ECDSAP256SHA256,
            .digest_algorithm = DigestAlgorithm::SHA256,
            .digest = {0xA5, 0x29, 0xE5, 0x47, 0x63, 0xB5, 0x68, 0x6C, 0x25, 0x95, 0x16,
                        0xB6, 0x0D, 0xEA, 0x46, 0xCB, 0x42, 0xC0, 0x14, 0x15, 0xDA, 0x5C,
                        0xC6, 0xCB, 0xD1, 0x8B, 0x9C, 0x54, 0x1A, 0x99, 0x8C, 0x5D},
            .data = {},
        }},
    },
    .use_root_nameservers = false,
    .use_resolve_config = false,
    .port = 1053,
    .dnssec = FeatureState::Require,
};

#define MOCK_DOMAIN "test.com."
#define MOCK_NAMESERVER_ADDRESS "127.0.0.2"
static const ResolverConfig MOCK_RESOLVER_CONFIG{
    .timeout_ms = 500,
    .nameserver = NameserverConfig{.address = MOCK_NAMESERVER_ADDRESS},
    .use_root_nameservers = false,
    .use_resolve_config = false,
    .port = 1053,
    .dnssec = FeatureState::Disable,
};
