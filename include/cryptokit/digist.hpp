#ifndef CRYPTO_KIT_DIGIST_HPP_
#define CRYPTO_KIT_DIGIST_HPP_

#include <memory>

namespace cryptokit {
class Digist {
public:
    Digist();

    ~Digist();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace cryptokit

#endif