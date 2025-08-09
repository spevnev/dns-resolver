#include "dns.hh"
#include <netinet/in.h>
#include <openssl/rand.h>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>
#include "dnssec.hh"
#include "write.hh"

namespace {
template <std::integral T>
T random_int() {
    T result;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&result), sizeof(result)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return result;
}
}  // namespace

uint16_t write_request(std::vector<uint8_t> &buffer, uint16_t payload_size, const std::string &domain, RRType rr_type,
                       bool enable_rd, bool enable_edns, bool enable_dnssec, bool enable_cookies, DNSCookies &cookies) {
    auto id = random_int<uint16_t>();

    // Write DNS header.
    write_u16(buffer, id);
    write_u16(buffer, static_cast<uint16_t>(enable_rd) << 8);  // flags
    write_u16(buffer, 1);                                      // question count
    write_u16(buffer, 0);                                      // answer count
    write_u16(buffer, 0);                                      // authority count
    write_u16(buffer, enable_edns ? 1 : 0);                    // additional count

    // Write question.
    write_domain(buffer, domain);
    write_u16(buffer, rr_type);
    write_u16(buffer, DNSClass::Internet);

    // Write the OPT pseudo-RR (RFC6891):
    if (enable_edns) {
        write_u8(buffer, 0);  // domain (must be root)
        write_u16(buffer, RRType::OPT);
        write_u16(buffer, payload_size);
        write_u8(buffer, 0);  // extended rcode (empty in request)
        write_u8(buffer, EDNS_VERSION);
        write_u16(buffer, static_cast<uint16_t>(enable_dnssec) << 15);  // flags

        if (enable_cookies) {
            if (!cookies.client.has_value()) cookies.client = random_int<uint64_t>();
            auto client_cookie = cookies.client.value();

            uint16_t option_length = sizeof(client_cookie) + cookies.server.size();
            write_u16(buffer, 4 + option_length);
            write_u16(buffer, OptionCode::Cookies);
            write_u16(buffer, option_length);
            write_bytes(buffer, reinterpret_cast<uint8_t *>(&client_cookie), sizeof(client_cookie));
            write_bytes(buffer, cookies.server.cbegin(), cookies.server.size());
        } else {
            // No options.
            write_u16(buffer, 0);
        }
    }

    return id;
}

class ResponseReader {
public:
    ResponseReader(const std::vector<uint8_t> &buffer, size_t offset = 0) : buffer(buffer), offset(offset) {}

    Response read_response(uint16_t request_id, const std::string &request_domain, RRType request_rr_type) {
        Response response;

        // Read response header.
        auto id = read_u16();
        auto flags = read_u16();
        bool is_response = (flags >> 15) & 1;
        auto opcode = static_cast<OpCode>((flags >> 11) & 0b1111);
        response.is_authoritative = (flags >> 10) & 1;
        bool is_truncated = (flags >> 9) & 1;
        response.rcode = static_cast<RCode>(flags & 0b1111);
        auto question_count = read_u16();
        auto answer_count = read_u16();
        auto authority_count = read_u16();
        auto additional_count = read_u16();

        // Validate response header.
        if (id != request_id) throw std::runtime_error("Wrong response ID");
        if (!is_response) throw std::runtime_error("Response is a query");
        if (opcode != OpCode::Query) throw std::runtime_error("Response has wrong opcode");
        if (is_truncated) throw std::runtime_error("Response is truncated");
        if (question_count != 1) throw std::runtime_error("Wrong question count");

        // Validate question.
        if (read_domain() != request_domain) throw std::runtime_error("Wrong question domain");
        if (read_u16<RRType>() != request_rr_type) throw std::runtime_error("Wrong question type");
        if (read_u16<DNSClass>() != DNSClass::Internet) throw std::runtime_error("Unknown DNS class");

        // Read the answer.
        response.answers.reserve(answer_count);
        for (uint16_t i = 0; i < answer_count; i++) response.answers.push_back(read_rr());
        response.authority.reserve(authority_count);
        for (uint16_t i = 0; i < authority_count; i++) response.authority.push_back(read_rr());
        response.additional.reserve(additional_count);
        for (uint16_t i = 0; i < additional_count; i++) response.additional.push_back(read_rr());

        if (offset != buffer.size()) throw std::runtime_error("Failed to parse the response");
        return response;
    }

private:
    const std::vector<uint8_t> &buffer;
    size_t offset;

    std::unique_ptr<ResponseReader> reader_at_offset(size_t offset) {
        return std::make_unique<ResponseReader>(buffer, offset);
    }

    void read(size_t size, auto &container) {
        if (offset + size > buffer.size()) throw std::runtime_error("Response is too short");
        container.assign(buffer.cbegin() + offset, buffer.cbegin() + offset + size);
        offset += size;
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    T read() {
        T value;
        if (offset + sizeof(value) > buffer.size()) throw std::runtime_error("Response is too short");
        std::memcpy(&value, buffer.data() + offset, sizeof(value));
        offset += sizeof(value);
        return value;
    }

    uint8_t read_u8() { return read<uint8_t>(); }
    uint16_t read_u16() { return ntohs(read<uint16_t>()); }
    uint32_t read_u32() { return ntohl(read<uint32_t>()); }

    template <CastableEnum<uint8_t> T>
    T read_u8() {
        return static_cast<T>(read_u8());
    }

    template <CastableEnum<uint16_t> T>
    T read_u16() {
        return static_cast<T>(read_u16());
    }

    void read_domain_rec(bool allow_compression, std::string &domain) {
        const uint8_t LABEL_DATA_MASK = 0b00111111;
        const uint8_t LABEL_TYPE_MASK = 0b11000000;
        const uint8_t LABEL_TYPE_POINTER = 0b11000000;
        const uint8_t LABEL_TYPE_NORMAL = 0b00000000;

        for (;;) {
            auto byte = read_u8();
            auto type = byte & LABEL_TYPE_MASK;
            auto data = byte & LABEL_DATA_MASK;

            if (type == LABEL_TYPE_NORMAL) {
                auto label_length = data;
                if (label_length == 0) return;

                if (offset + label_length > buffer.size()) throw std::runtime_error("Response is too short");
                std::transform(buffer.cbegin() + offset, buffer.cbegin() + offset + label_length,
                               std::back_inserter(domain), [](auto ch) { return std::tolower(ch); });
                offset += label_length;
                domain.push_back('.');
            } else if (allow_compression && type == LABEL_TYPE_POINTER) {
                size_t label_offset = (static_cast<uint16_t>(data) << 8) | read_u8();
                if (label_offset >= buffer.size()) throw std::runtime_error("Invalid offset in pointer label");

                ResponseReader rec_reader{buffer, label_offset};
                rec_reader.read_domain_rec(allow_compression, domain);

                // Pointer is always the last label.
                return;
            } else {
                throw std::runtime_error("Invalid label type");
            }
        }
    }

    std::string read_domain(bool allow_compression = true) {
        std::string domain;
        read_domain_rec(allow_compression, domain);
        // Handle root domain.
        if (domain.empty()) return ".";
        if (domain.length() > MAX_DOMAIN_LENGTH) throw std::runtime_error("Domain is too long");
        return domain;
    }

    std::string read_char_string() {
        auto length = read_u8();
        std::string string;
        string.reserve(length);
        read(length, string);
        return string;
    }

    SOA read_soa_data() {
        return SOA{
            .master_name = read_domain(),
            .rname = read_domain(),
            .serial = read_u32(),
            .refresh = read_u32(),
            .retry = read_u32(),
            .expire = read_u32(),
            .negative_ttl = read_u32(),
        };
    }

    HINFO read_hinfo_data() {
        return HINFO{
            .cpu = read_char_string(),
            .os = read_char_string(),
        };
    }

    TXT read_txt_data(uint16_t data_length) {
        TXT txt;
        size_t end = offset + data_length;
        while (offset < end) txt.strings.push_back(read_char_string());
        return txt;
    }

    OPT read_opt_data(uint16_t data_length, RR &rr, DNSClass rr_class) {
        if (rr.domain != ".") throw std::runtime_error("OPT must have root domain");

        OPT opt;

        // Class contains nameserver's UDP payload size.
        opt.udp_payload_size = std::max(std::to_underlying(rr_class), STANDARD_UDP_PAYLOAD_SIZE);

        // TTL contains different flags.
        opt.upper_extended_rcode = rr.ttl >> 24;
        uint8_t edns_version = rr.ttl >> 16;
        opt.dnssec_ok = (rr.ttl >> 15) & 1;
        rr.ttl = 0;

        if (edns_version > EDNS_VERSION) throw std::runtime_error("Unsupported EDNS version");

        while (data_length > 0) {
            auto option_code = read_u16<OptionCode>();
            auto option_length = read_u16();
            data_length -= 4;

            if (option_length > data_length) throw std::runtime_error("Response is too short");
            data_length -= option_length;

            switch (option_code) {
                case OptionCode::Cookies:
                    if (!(16 <= option_length && option_length <= 40)) {
                        throw std::runtime_error("Invalid cookies length");
                    }

                    opt.cookies = DNSCookies{};
                    opt.cookies->client = read<uint64_t>();
                    read(option_length - sizeof(uint64_t), opt.cookies->server);
                    break;
                default: offset += option_length; break;
            }
        }

        return opt;
    }

    DS read_ds_data(uint16_t data_length) {
        auto data_offset = offset;

        DS ds;
        ds.key_tag = read_u16();
        ds.signing_algorithm = read_u8<SigningAlgorithm>();
        ds.digest_algorithm = read_u8<DigestAlgorithm>();
        read(dnssec::get_ds_digest_size(ds.digest_algorithm), ds.digest);

        // Save data to authenticate the RRSIG later.
        ResponseReader data_reader{buffer, data_offset};
        data_reader.read(data_length, ds.data);

        return ds;
    }

    RRSIG read_rrsig_data(uint16_t data_length) {
        auto data_offset = offset;

        RRSIG rrsig;
        rrsig.type_covered = read_u16<RRType>();
        rrsig.algorithm = read_u8<SigningAlgorithm>();
        rrsig.labels = read_u8();
        rrsig.original_ttl = read_u32();
        rrsig.expiration_time = read_u32();
        rrsig.inception_time = read_u32();
        rrsig.key_tag = read_u16();
        rrsig.signer_name = read_domain(false);

        // The rest of the data is the signature.
        auto signature_length = data_length - (offset - data_offset);
        read(signature_length, rrsig.signature);

        // Save data without signature to authenticate it later.
        ResponseReader data_reader{buffer, data_offset};
        data_reader.read(data_length - signature_length, rrsig.data);

        return rrsig;
    }

    std::unordered_set<RRType> read_rr_type_bitmap(uint16_t data_length) {
        std::unordered_set<RRType> rr_types;
        std::vector<uint8_t> bitmap;
        while (data_length > 0) {
            auto window_block = read_u8();
            auto bitmap_length = read_u8();
            data_length -= 2;

            if (!(1 <= bitmap_length && bitmap_length <= 32)) throw std::runtime_error("Invalid RR type bitmap length");
            read(bitmap_length, bitmap);
            data_length -= bitmap_length;

            uint16_t upper_half = static_cast<uint16_t>(window_block) << 8;
            for (int i = 0; i < bitmap_length; i++) {
                for (int j = 7; j >= 0; j--) {
                    if (bitmap[i] & 1) rr_types.insert(static_cast<RRType>(upper_half | (i * 8 + j)));
                    bitmap[i] >>= 1;
                }
            }
        }
        return rr_types;
    }

    NSEC read_nsec_data(uint16_t data_length) {
        auto data_offset = offset;

        NSEC nsec;
        nsec.next_domain = read_domain(false);

        auto domain_size = offset - data_offset;
        nsec.types = read_rr_type_bitmap(data_length - domain_size);

        // Save data to authenticate the RRSIG later.
        ResponseReader data_reader{buffer, data_offset};
        data_reader.read(data_length, nsec.data);

        return nsec;
    }

    DNSKEY read_dnskey_data(uint16_t data_length) {
        auto data_offset = offset;

        DNSKEY dnskey;
        dnskey.flags = read_u16();
        dnskey.is_zone_key = (dnskey.flags >> 8) & 1;
        dnskey.is_secure_entry = dnskey.flags & 1;
        dnskey.protocol = read_u8();
        dnskey.algorithm = read_u8<SigningAlgorithm>();

        if (!dnskey.is_zone_key) throw std::runtime_error("DNSKEY does not have Zone Key flag set");
        if (dnskey.protocol != DNSKEY_PROTOCOL) throw std::runtime_error("Invalid DNSKEY protocol");

        // The rest of the data is the key.
        auto key_size = data_length - 4;
        read(key_size, dnskey.key);

        // Save data to authenticate the RRSIG later.
        ResponseReader data_reader{buffer, data_offset};
        data_reader.read(data_length, dnskey.data);
        dnskey.key_tag = dnssec::compute_key_tag(dnskey.data);

        return dnskey;
    }

    NSEC3 read_nsec3_data(uint16_t data_length) {
        auto data_offset = offset;

        NSEC3 nsec3;
        nsec3.algorithm = read_u8<HashAlgorithm>();
        nsec3.flags = read_u8();
        nsec3.opt_out = nsec3.flags & 1;
        nsec3.iterations = read_u16();
        auto salt_length = read_u8();
        if (salt_length > 0) read(salt_length, nsec3.salt);
        auto hash_length = read_u8();
        if (hash_length == 0) throw std::runtime_error("NSEC3 next hashed owner name cannot be empty");
        read(hash_length, nsec3.next_domain_hash);

        auto nsec3_data_length = offset - data_offset;
        nsec3.types = read_rr_type_bitmap(data_length - nsec3_data_length);

        // Save data to authenticate the RRSIG later.
        ResponseReader data_reader{buffer, data_offset};
        data_reader.read(data_length, nsec3.data);

        return nsec3;
    }

    RR read_rr() {
        RR rr;
        rr.domain = read_domain();
        rr.type = read_u16<RRType>();
        auto rr_class = read_u16<DNSClass>();
        rr.ttl = read_u32();
        auto data_length = read_u16();

        if (rr.type != RRType::OPT) {
            // Class must be Internet, or it is OPT RR whose CLASS contains UDP payload size (RFC6891).
            if (rr_class != DNSClass::Internet) throw std::runtime_error("Unknown DNS class");

            // TTL is an unsigned number between 0 and 2147483647 (RFC2181).
            // Treat TTL values with the MSB set as if the value were zero.
            if (rr.ttl > MAX_TTL) rr.ttl = 0;
        }

        if (offset + data_length > buffer.size()) throw std::runtime_error("Respose is too short");
        switch (rr.type) {
            case RRType::A:      rr.data = A{.address = read<in_addr_t>()}; break;
            case RRType::NS:     rr.data = NS{.domain = read_domain()}; break;
            case RRType::CNAME:  rr.data = CNAME{.domain = read_domain()}; break;
            case RRType::SOA:    rr.data = read_soa_data(); break;
            case RRType::HINFO:  rr.data = read_hinfo_data(); break;
            case RRType::TXT:    rr.data = read_txt_data(data_length); break;
            case RRType::AAAA:   rr.data = AAAA{.address = read<struct in6_addr>()}; break;
            case RRType::OPT:    rr.data = read_opt_data(data_length, rr, rr_class); break;
            case RRType::DS:     rr.data = read_ds_data(data_length); break;
            case RRType::RRSIG:  rr.data = read_rrsig_data(data_length); break;
            case RRType::NSEC:   rr.data = read_nsec_data(data_length); break;
            case RRType::DNSKEY: rr.data = read_dnskey_data(data_length); break;
            case RRType::NSEC3:  rr.data = read_nsec3_data(data_length); break;
            case RRType::ANY:    throw std::runtime_error("Invalid response RR of type ANY");
            default:             offset += data_length; break;
        }
        return rr;
    }
};

Response read_response(const std::vector<uint8_t> &buffer, uint16_t request_id, const std::string &request_domain,
                       RRType request_rr_type) {
    return ResponseReader{buffer}.read_response(request_id, request_domain, request_rr_type);
}
