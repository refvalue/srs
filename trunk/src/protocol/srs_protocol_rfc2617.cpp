#include "srs_protocol_rfc2617.hpp"

#include <map>
#include <regex>
#include <random>
#include <unordered_set>

#include <srs_kernel_file.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_kernel_consts.hpp>
#include <srs_kernel_log.hpp>
#include <srs_core_autofree.hpp>

#define SRS_HTTP_AUTH_SCHEME_DIGEST "Digest"
#define SRS_HTTP_AUTH_PREFIX_DIGEST SRS_HTTP_AUTH_SCHEME_DIGEST " "
#define SRS_HTTP_AUTH_ALGORTIHM_MD5 "MD5"
#define SRS_HTTP_AUTH_ALGORTIHM_MD5_SESS "MD5-sess"

namespace
{
    srs_error_t srs_rfc2617_make_nonce(std::string etag, std::string& result)
    {
        static constexpr auto private_key = "7214CBD6-E511-4F69-BB89-9BE7D44674CF";

        std::string hash;
        auto timestamp = srs_get_system_time();
        auto err = make_digest(SrsDigestModeSha3_512, srs_fmt("%lld:%s:%s", timestamp, etag.c_str(), private_key), hash);

        if (err != srs_success) {
            return err;
        }

        result.clear();
        result.append(std::to_string(timestamp)).append(hash);

        return err;
    }

    srs_error_t srs_rfc2617_make_opaque(std::string& result)
    {
        static constexpr std::size_t sequence_size = 1024;
        thread_local std::uniform_int_distribution<std::uint64_t> distribution;
        thread_local std::mt19937_64 engine{ std::random_device{}() };

        std::string sequence(sequence_size * sizeof(decltype(distribution)::result_type), '\0');
        auto ptr = sequence.begin();

        for (std::size_t i = 0; i < sequence_size; i++) {
            auto number = distribution(engine);

            ptr = std::copy(reinterpret_cast<const char*>(&number), reinterpret_cast<const char*>(&number) + sizeof(number), ptr);
        }

        return srs_rfc2617_make_nonce(sequence, result);
    }

    std::string srs_rfc2617_make_authorization_line(const std::map<std::string, std::string>& data) {
        std::string result{ SRS_HTTP_AUTH_PREFIX_DIGEST };

        for (auto&& item : data) {
            result
                .append(item.first)
                .append("=")
                .append("\"")
                .append(item.second)
                .append("\"")
                .append(",");
        }

        if (result.back() == ',') {
            result.pop_back();
        }

        return result;
    }

    std::map<std::string, std::string> srs_rfc2617_parse_authorization_line(std::string data) {
        static constexpr auto blank_chars = "\"\t ";
        thread_local const std::regex pattern{R"((.+?)\s*?\=\s*?(.+?)(?:,|$))", std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize};

        std::map<std::string, std::string> result;

        for (std::sregex_iterator iter{data.begin(), data.end(), pattern}, iter_end; iter != iter_end; ++iter) {
            auto key = srs_string_trim_end(srs_string_trim_start((*iter)[1], blank_chars), blank_chars);
            auto value = srs_string_trim_end(srs_string_trim_start((*iter)[2], blank_chars), blank_chars);

            result[key] = value;
        }

        return result;
    }

    srs_error_t srs_rfc2617_make_htdigest_md5(std::string username, std::string realm, std::string password, std::string& result) {
        return make_digest(SrsDigestModeMd5, srs_fmt("%s:%s:%s", username.c_str(), realm.c_str(), password.c_str()), result);
    }

    srs_error_t srs_rfc2617_make_kd(std::string secret, std::string data, std::string& result) {
        printf("==== KD SECRET: %s\nKD DATA: %s\n", secret.c_str(), data.c_str());
        return make_digest(SrsDigestModeMd5, srs_fmt("%s:%s", secret.c_str(), data.c_str()), result);
    }

    srs_error_t srs_rfc2617_make_ha1(bool md5_sess, std::string htdigest_md5_data, std::string nonce, std::string cnonce, std::string& result)
    {
        if (md5_sess) {
            return make_digest(SrsDigestModeMd5, srs_fmt("%s:%s:%s", htdigest_md5_data.c_str(), nonce.c_str(), cnonce.c_str()), result);
        }

        result = std::move(htdigest_md5_data);

        return srs_success;
    }

    srs_error_t srs_rfc2617_make_ha2(bool auth_int, std::string digest_uri, ISrsHttpMessage* r, std::string& result) {
        if (auth_int) {
            std::string body;
            auto err = r->body_read_all(body);

            if (err != srs_success) {
                return err;
            }

            return make_digest(SrsDigestModeMd5, srs_fmt("%s:%s:%s", r->method_str().c_str(), digest_uri.c_str(), body.c_str()), result);
        }

        return make_digest(SrsDigestModeMd5, srs_fmt("%s:%s", r->method_str().c_str(), digest_uri.c_str()), result);
    }

    std::unordered_set<std::string> srs_rfc2617_make_request_digest_set(const std::vector<std::string>& htdigest_md5_data, bool md5_sess, std::string nonce, std::string nc, std::string cnonce, std::string qop, std::string ha2) {
        std::string kd;
        std::string ha1;
        std::unordered_set<std::string> result;

        for (auto&& item : htdigest_md5_data) {
            if (srs_rfc2617_make_ha1(md5_sess, item, nonce, cnonce, ha1) == srs_success && srs_rfc2617_make_kd(ha1, srs_fmt("%s:%s:%s:%s:%s", nonce.c_str(), nc.c_str(), cnonce.c_str(), qop.c_str(), ha2.c_str()), kd) == srs_success) {
                result.emplace(kd);
            }
        }

        return result;
    }
}

SrsRfc2617Auth::SrsRfc2617Auth()
{
}

SrsRfc2617Auth::~SrsRfc2617Auth()
{
}

srs_error_t SrsRfc2617Auth::initialize(bool enabled, std::string realm, std::string htdigest_file)
{
    enabled_ = enabled;
    realm_ = std::move(realm);

    srs_trace("rfc2617 init: enabled=%d, realm=%s, htdigest_file=%s\n", static_cast<int>(enabled), realm_.c_str(), htdigest_file.c_str());

    if (enabled_) {
        if (realm_.empty()) {
            return srs_error_new(-1, "realm must be non-empty.");
        }

        auto factory = new ISrsFileReaderFactory;
        auto reader = factory->create_file_reader();

        SrsAutoFree(ISrsFileReaderFactory, factory);
        SrsAutoFree(SrsFileReader, reader);

        auto err = reader->open(htdigest_file);

        if (err != srs_success) {
            auto wrapped = srs_error_wrap(err, "failed to open htdigest file %s, realm %s", htdigest_file.c_str(), realm_.c_str());

            srs_error("%s", srs_error_desc(wrapped).c_str());

            return wrapped;
        }

        thread_local const std::regex pattern(R"(^(.+?)\:(.+?)\:(.+?)$)", std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
        std::vector<std::string> lines;

        if ((err = srs_get_lines(reader, lines)) != srs_success) {
            auto wrapped = srs_error_wrap(err, "failed to read htdigest file %s, realm %s", htdigest_file.c_str(), realm_.c_str());

            srs_error("%s", srs_error_desc(wrapped).c_str());

            return wrapped;
        }

        std::smatch match;
        std::string htdigest_md5;

        // Stores H(A1) in memory, where A1 = username ":" realm ":" password.
        for (auto&& item : lines) {
            if (std::regex_match(item, match, pattern)) {
                auto username = match[1].str();
                auto realm = match[2].str();
                auto password = match[3].str();

                // Only accepts matched realms.
                if (srs_string_icase_compare(realm, realm_) && srs_rfc2617_make_htdigest_md5(username, realm, password, htdigest_md5) == srs_success) {
                    htdigest_md5_data_.emplace_back(htdigest_md5);
                    srs_trace("rfc2617 added htdigest username:realm:password=%s:%s:%s", username.c_str(), realm.c_str(), password.c_str());
                }
            }
        }
    }

    return srs_success;
}


srs_error_t SrsRfc2617Auth::do_auth(ISrsHttpMessage* msg, std::string& www_authenticate)
{
    static constexpr auto qop_value = "auth,auth-int";
    static constexpr auto algorithm_value = "MD5";

    srs_error_t err = srs_success;

    if (!enabled_) {
        return err;
    }

    www_authenticate.clear();

    auto auth = msg->header()->get("Authorization");

    if (auth.empty()) {
        if ((err = srs_rfc2617_make_nonce(msg->header()->get("ETag"), nonce_)) != srs_success) {
            return err;
        }

        if ((err = srs_rfc2617_make_opaque(opaque_)) != srs_success) {
            return err;
        }

        std::map<std::string, std::string> fields{
            { "realm", realm_ },
            { "nonce", nonce_ },
            { "opaque", opaque_ },
            { "algorithm", algorithm_value },
            { "qop", qop_value }
        };

        www_authenticate = srs_rfc2617_make_authorization_line(fields);
        return srs_error_new(SRS_CONSTS_HTTP_Unauthorized, "empty Authorization");
    }

    if (!srs_string_contains(auth, SRS_HTTP_AUTH_PREFIX_DIGEST)) {
        return srs_error_new(SRS_CONSTS_HTTP_Unauthorized, "invalid auth %s, should start with %s", auth.c_str(), SRS_HTTP_AUTH_PREFIX_DIGEST);
    }

    auto token = srs_erase_first_substr(auth, SRS_HTTP_AUTH_PREFIX_DIGEST);

    if (token.empty()) {
        return srs_error_new(SRS_CONSTS_HTTP_Unauthorized, "empty token from auth %s", auth.c_str());
    }

    auto fields = srs_rfc2617_parse_authorization_line(token);

    auto field_checker = [&](std::string name, std::string& result, std::initializer_list<std::string> expected_values = {})->srs_error_t {
        auto iter = fields.find(name);

        if (iter == fields.end()) {
            return srs_error_new(SRS_CONSTS_HTTP_Unauthorized, "invalid token %s, %s must be given but not found.", token.c_str(), name.c_str());
        }

        if (iter->second.empty()) {
            return srs_error_new(SRS_CONSTS_HTTP_Unauthorized, "invalid token %s, %s must be non-empty.", token.c_str(), name.c_str());
        }

        if (expected_values.size() != 0 && !std::any_of(expected_values.begin(), expected_values.end(), [&](const std::string& inner) { return srs_string_icase_compare(iter->second, inner); })) {
            return srs_error_new(SRS_CONSTS_HTTP_Unauthorized, "invalid token %s, invalid %s %s", token.c_str(), name.c_str(), iter->second.c_str());
        }

        result = iter->second;

        return srs_success;
    };

    std::string realm;
    std::string username;
    std::string nonce;
    std::string digest_uri;
    std::string response;
    std::string algorithm;
    std::string qop;
    std::string cnonce;
    std::string nc;

    if ((err = field_checker("realm", realm, { realm_ })) != srs_success) {
        return err;
    }

    if ((err = field_checker("username", username)) != srs_success) {
        return err;
    }

    if ((err = field_checker("nonce", nonce, { nonce_ })) != srs_success) {
        return err;
    }

    if ((err = field_checker("uri", digest_uri)) != srs_success) {
        return err;
    }

    if ((err = field_checker("response", response)) != srs_success) {
        return err;
    }

    if ((err = field_checker("algorithm", algorithm, { "MD5", "MD5-sess" })) != srs_success) {
        return err;
    }

    // The qop must exist cause this implementation always responds with "qop=auth,auth-int".
    if ((err = field_checker("qop", qop, { "auth", "auth-int" })) != srs_success) {
        return err;
    }

    if ((err = field_checker("cnonce", cnonce)) != srs_success) {
        return err;
    }

    if ((err = field_checker("nc", nc)) != srs_success) {
        return err;
    }

    std::string ha2;
    auto auth_int = srs_string_icase_compare(auth, "auth-int");

    if ((err = srs_rfc2617_make_ha2(auth_int, digest_uri, msg, ha2)) != srs_success) {
        return srs_error_wrap(err, "invalid token %s", token.c_str());
    }

    // Makes a digest list from available htdigest entries.
    auto md5_sess = srs_string_icase_compare(algorithm, "MD5-sess");
    auto request_digests = srs_rfc2617_make_request_digest_set(htdigest_md5_data_, md5_sess, nonce, nc, cnonce, qop, ha2);

    if (request_digests.find(response) == request_digests.end()) {
        return srs_error_new(SRS_CONSTS_HTTP_Unauthorized, "invalid token %s", token.c_str());
    }

    return err;
}
