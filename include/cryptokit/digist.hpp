#ifndef CRYPTO_KIT_DIGIST_HPP_
#define CRYPTO_KIT_DIGIST_HPP_

#include <memory>

namespace ckit {
namespace digist {
class Digist {
public:
    Digist();

    ~Digist();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace digist
}  // namespace ckit
#endif