#ifndef CRYPTO_KIT_COMMON_HPP__
#define CRYPTO_KIT_COMMON_HPP__

#include <openssl/bio.h>

#include <memory>

namespace ckit {

/// 指定流式编解码操作的方向。
enum class Crypto : bool { enc, dec };

/// 指定文本编码输出使用大写或小写字符。
enum class Character : bool { upper, lower };

namespace bio {
struct BioDeleter {
    void operator()(BIO* bio) const {
        if (bio) {
            BIO_free(bio);
        }
    };
};
using SmartBio = std::unique_ptr<BIO, BioDeleter>;
}  // namespace bio

}  // namespace ckit

#endif  // CRYPTO_KIT_COMMON_HPP__
