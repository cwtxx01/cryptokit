#ifndef CRYPTO_KIT_COMMON_HPP__
#define CRYPTO_KIT_COMMON_HPP__

#include <openssl/bio.h>

#include <memory>

namespace ckit {

enum class Crypto : bool { enc, dec };

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