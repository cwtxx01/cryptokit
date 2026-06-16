#ifndef CRYPTO_KIT_CODEC_HPP_
#define CRYPTO_KIT_CODEC_HPP_

#include <memory>

namespace cryptokit {
class Codec {
public:
    Codec();

    ~Codec();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace cryptokit

#endif