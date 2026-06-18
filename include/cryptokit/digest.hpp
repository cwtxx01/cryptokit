#ifndef CRYPTO_KIT_DIGIST_HPP_
#define CRYPTO_KIT_DIGIST_HPP_

#include <openssl/evp.h>
#include <openssl/types.h>

#include <memory>
#include <stdexcept>

#include "cryptokit/byte_view.hpp"

namespace ckit {
namespace digest {
enum class Mode { md5, sha1, sha224, sha256, sha384, sha512 };

namespace detail {
struct MdDeleter {
    void operator()(EVP_MD* md) const {
        if (md) {
            EVP_MD_free(md);
        }
    }
};

struct MdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};

inline constexpr std::string_view ToStrView(Mode m) {
    switch (m) {
        case Mode::md5:
            return "MD5";
        case Mode::sha1:
            return "SHA1";
        case Mode::sha224:
            return "SHA224";
        case Mode::sha256:
            return "SHA256";
        case Mode::sha384:
            return "SHA384";
        case Mode::sha512:
            return "SHA512";
    }
    return {};
}

using SmartMd = std::unique_ptr<EVP_MD, MdDeleter>;

template <Mode M>
inline SmartMd MakeMd(const char* provider) {
    return SmartMd(EVP_MD_fetch(nullptr, ToStrView(M).data(), provider));
}

using SmartMdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

inline SmartMdCtx MakeMdCtx() { return SmartMdCtx(EVP_MD_CTX_new()); }
}  // namespace detail

template <Mode M>
class Digest {
public:
    enum class Status { good, error, over };

    explicit Digest(std::string_view provider = {})
        : md_(detail::MakeMd<M>(
              provider.empty()
                  ? nullptr
                  : (std::string("provider=") + provider.data()).c_str())),
          ctx_(detail::MakeMdCtx()) {
        if (!EVP_DigestInit_ex(ctx_.get(), md_.get(), nullptr)) {
            status_ = Status::error;
            throw std::runtime_error("Digest Init failed");
        }
    }

    static std::string Once(BytesView text, std::string_view provider = {}) {
        std::string str;
        Digest<M>{provider} << text >> str;
        return str;
    }

    void Init(std::string_view provider = {}) {
        md_.reset();
        md_ = detail::MakeMd<M>(
            provider.empty()
                ? nullptr
                : (std::string("provider=") + provider.data()).c_str());
        ctx_.reset();
        ctx_ = detail::MakeMdCtx();
        if (!EVP_DigestInit_ex(ctx_.get(), md_.get(), nullptr)) {
            status_ = Status::error;
            throw std::runtime_error("Digest Init failed");
        }
        status_ = Status::good;
    }

    Digest& operator<<(BytesView text) {
        if (status_ == Status::good) {
            if (!EVP_DigestUpdate(ctx_.get(), text.data(), text.size())) {
                status_ = Status::error;
            }
        }
        return *this;
    }

    Digest& operator>>(std::string& out) {
        out = Out();
        return *this;
    }

    std::string Out() {
        auto buf_size = EVP_MD_CTX_size(ctx_.get());
        if (buf_size <= 0) {
            status_ = Status::error;
            return {};
        }
        std::string hash_buf(buf_size, 0);
        unsigned int len = 0;
        if (!EVP_DigestFinal_ex(
                ctx_.get(), reinterpret_cast<Byte*>(hash_buf.data()), &len)) {
            status_ = Status::error;
            return {};
        }
        hash_buf.resize(len);
        status_ = Status::over;
        return hash_buf;
    }

    Status GetStatus() const { return status_; }

private:
    detail::SmartMdCtx ctx_;
    detail::SmartMd md_;
    Status status_{Digest::Status::good};
};

}  // namespace digest
using DigestMode = digest::Mode;

using Md5 = digest::Digest<DigestMode::md5>;
using Sha1 = digest::Digest<DigestMode::sha1>;
using Sha224 = digest::Digest<DigestMode::sha224>;
using Sha256 = digest::Digest<DigestMode::sha256>;
using Sha384 = digest::Digest<DigestMode::sha384>;
using Sha512 = digest::Digest<DigestMode::sha512>;
}  // namespace ckit
#endif