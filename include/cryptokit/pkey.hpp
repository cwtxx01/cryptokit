#ifndef CRYPTO_KIT_PKEY_HPP_
#define CRYPTO_KIT_PKEY_HPP_

#include <memory>

namespace cryptokit {
class Pkey {
public:
    Pkey();

    ~Pkey();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace cryptokit

#endif