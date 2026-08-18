#ifndef CRYPTO_KIT_PKEY_HPP_
#define CRYPTO_KIT_PKEY_HPP_

#include <openssl/rsa.h>

#include <filesystem>
#include <memory>
#include <optional>

#include "cryptokit/byte_view.hpp"
#include "cryptokit/digest.hpp"

namespace ckit {
namespace pkey {
enum class Bits { b1024 = 1024, b2048 = 2048, b3072 = 3072, b4096 = 4096 };

enum class Padding {
    pkcs1 = RSA_PKCS1_PADDING,
    oaep = RSA_PKCS1_OAEP_PADDING,
    pss = RSA_PKCS1_PSS_PADDING,
    x931 = RSA_X931_PADDING,
};

class RsaPrivKey;

class RsaPubKey {
    struct Impl;
    std::unique_ptr<Impl> impl_;

public:
    std::optional<std::string> Pem() const;

    std::optional<ByteVec> Encrypt(
        BytesView data, Padding padding = Padding::oaep,
        digest::Mode oaep = digest::Mode::sha256,
        digest::Mode mgf1 = digest::Mode::sha256) const;

    bool Verify(BytesView data, BytesView signature,
                Padding padding = Padding::pss,
                digest::Mode digest = digest::Mode::sha256,
                digest::Mode mgf1 = digest::Mode::sha256,
                int saltlen = RSA_PSS_SALTLEN_DIGEST) const;

    bool IsOk() const noexcept;

    explicit RsaPubKey(BytesView pem);

    explicit RsaPubKey(const RsaPrivKey& rsa);

    explicit RsaPubKey(const std::filesystem::path& path);

    ~RsaPubKey();
};

class RsaPrivKey {
    friend class RsaPubKey;

    struct Impl;
    std::unique_ptr<Impl> impl_;

public:
    std::optional<std::string> Pem() const;

    std::optional<ByteVec> Decrypt(
        BytesView data, Padding padding = Padding::oaep,
        digest::Mode oaep = digest::Mode::sha256,
        digest::Mode mgf1 = digest::Mode::sha256) const;

    std::optional<ByteVec> Sign(BytesView data,
                                digest::Mode digest = digest::Mode::sha256,
                                Padding padding = Padding::pss,
                                digest::Mode mgf1 = digest::Mode::sha256,
                                int saltlen = RSA_PSS_SALTLEN_DIGEST) const;

    bool IsOk() const noexcept;

    explicit RsaPrivKey(BytesView pem);

    explicit RsaPrivKey(Bits bits);

    explicit RsaPrivKey(const std::filesystem::path& path);

    ~RsaPrivKey();
};
}  // namespace pkey

using pkey::RsaPrivKey;
using pkey::RsaPubKey;
}  // namespace ckit
#endif