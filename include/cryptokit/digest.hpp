#ifndef CRYPTO_KIT_DIGIST_HPP_
#define CRYPTO_KIT_DIGIST_HPP_

#include <openssl/evp.h>
#include <openssl/types.h>

#include <memory>
#include <stdexcept>

#include "cryptokit/byte_view.hpp"

namespace ckit {
namespace digest {
/// 支持的消息摘要算法。
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

inline const EVP_MD* Md(Mode m) {
    switch (m) {
        case Mode::md5:
            return EVP_md5();
        case Mode::sha1:
            return EVP_sha1();
        case Mode::sha224:
            return EVP_sha224();
        case Mode::sha256:
            return EVP_sha256();
        case Mode::sha384:
            return EVP_sha384();
        case Mode::sha512:
            return EVP_sha512();
    }
    return nullptr;
}

using SmartMdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

inline SmartMdCtx MakeMdCtx() { return SmartMdCtx(EVP_MD_CTX_new()); }
}  // namespace detail

/**
 * @brief 基于 OpenSSL EVP 的一次性及增量消息摘要器。
 *
 * 数据可分多次通过 operator<<() 输入，调用 Out() 或 operator>>() 后完成摘要。
 * 完成或出错后需调用 Init() 才能复用对象。返回的摘要是原始二进制字节，
 * 如需可读文本可再使用 Hex 或 Base64 编码。
 *
 * @tparam M 编译期选定的摘要算法。
 */
template <Mode M>
class Digest {
public:
    /// 摘要器状态：可继续、出错或已经完成。
    enum class Status { good, error, over };

    /**
     * @param prop OpenSSL provider 属性查询字符串；为空时使用默认实现。
     * @throws std::runtime_error 摘要上下文初始化失败。
     */
    explicit Digest(std::string_view prop = {})
        : md_(detail::MakeMd<M>(prop.empty() ? nullptr : prop.data())),
          ctx_(detail::MakeMdCtx()) {
        if (!EVP_DigestInit_ex(ctx_.get(), md_.get(), nullptr)) {
            status_ = Status::error;
            throw std::runtime_error("Digest Init failed");
        }
    }

    /// 一次性计算 @p text 的二进制摘要。
    static std::string Once(BytesView text, std::string_view provider = {}) {
        std::string str;
        Digest<M>{provider} << text >> str;
        return str;
    }

    /// 丢弃当前状态并使用指定 provider 属性重新初始化。
    void Init(std::string_view prop = {}) {
        md_.reset();
        md_ = detail::MakeMd<M>(prop.empty() ? nullptr : prop.data());
        ctx_.reset();
        ctx_ = detail::MakeMdCtx();
        if (!EVP_DigestInit_ex(ctx_.get(), md_.get(), nullptr)) {
            status_ = Status::error;
            throw std::runtime_error("Digest Init failed");
        }
        status_ = Status::good;
    }

    /// 追加一段输入；仅在状态为 Status::good 时处理。
    Digest& operator<<(BytesView text) {
        if (status_ == Status::good) {
            if (!EVP_DigestUpdate(ctx_.get(), text.Data(), text.Length())) {
                status_ = Status::error;
            }
        }
        return *this;
    }

    /// 完成摘要并将二进制结果写入 @p out。
    Digest& operator>>(std::string& out) {
        out = Out();
        return *this;
    }

    /// 完成并返回二进制摘要；失败时返回空字符串并进入错误状态。
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

    /// 返回当前处理状态。
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
