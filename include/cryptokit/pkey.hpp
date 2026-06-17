#ifndef CRYPTO_KIT_PKEY_HPP_
#define CRYPTO_KIT_PKEY_HPP_

#include <memory>

namespace ckit {
namespace pkey {
class Pkey {
public:
    Pkey();

    ~Pkey();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace pkey
}  // namespace ckit
#endif