#ifndef CRYPTO_KIT_COMMON_HPP__
#define CRYPTO_KIT_COMMON_HPP__

#define RETURN_NULLOPT_IF_ZERO(VAL) \
    do {                            \
        if (VAL == 0) {             \
            return std::nullopt;    \
        }                           \
    } while (false)

namespace ckit {

enum class Crypto : bool { enc, dec };

enum class Character : bool { upper, lower };

}  // namespace ckit

#endif  // CRYPTO_KIT_COMMON_HPP__