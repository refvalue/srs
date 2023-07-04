#pragma once

#include <string>
#include <vector>

#include <srs_kernel_error.hpp>
#include <srs_protocol_http_stack.hpp>

class SrsRfc2617Auth
{
public:
    SrsRfc2617Auth();
    virtual ~SrsRfc2617Auth();
    virtual srs_error_t initialize(bool enabled, std::string realm, std::string htdigest_file);
    srs_error_t do_auth(ISrsHttpMessage* msg, std::string& www_authenticate);
protected:
    bool enabled_;
    std::string realm_;
    std::string nonce_;
    std::string opaque_;
    std::vector<std::string> htdigest_md5_data_;
};
