#ifndef CRYPTO_KIT_CIPHER_HPP_
#define CRYPTO_KIT_CIPHER_HPP_

#include <memory>

namespace cryptokit {
class Cipher {
public:
    Cipher();

    ~Cipher();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace cryptokit

#endif