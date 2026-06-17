#ifndef CRYPTO_KIT_CIPHER_HPP_
#define CRYPTO_KIT_CIPHER_HPP_

#include <openssl/evp.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include "common.hpp"
#include "cryptokit/byte_view.hpp"

namespace ckit {
namespace cipher {
enum class Mode : char { gcm, ecb, cbc };

enum class Bits : int { k128 = 128 / 8, k192 = 192 / 8, k256 = 256 / 8 };

namespace detail {

using SmartCtx =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

inline SmartCtx MakeSmartCtx(EVP_CIPHER_CTX* ctx) {
    return SmartCtx(ctx, EVP_CIPHER_CTX_free);
}

struct AesBase {
    AesBase() = default;

    AesBase(BytesView key, BytesView iv)
        : key_(key.data(), key.data() + key.size()),
          iv_(iv.data(), iv.data() + iv.size()) {}

    AesBase(BytesView key) : key_(key.data(), key.data() + key.size()), iv_() {}

    AesBase(const AesBase&) = default;

    AesBase(AesBase&&) noexcept = default;

    ~AesBase() = default;

    AesBase& operator=(const AesBase&) = default;

    AesBase& operator=(AesBase&&) noexcept = default;

    std::vector<Byte> key_;
    std::vector<Byte> iv_;
};
}  // namespace detail

/**
 * @brief 基于OpenSSL库中EVP高级抽象层的Aes对称加密算法对象封装,
 * 具体算法严格使用OpenSSL的内部推荐值，如,
 * 限制KEY的长度严格匹配,
 * IV的长度CBC模式下是16，GCM模式下是12,
 * GCM模式的TAG长度必须为16
 *
 * @tparam M 模式枚举值
 * @tparam B 密钥长度枚举值
 **/
template <Mode M, Bits B>
class Aes : private detail::AesBase {
    template <Mode, Bits>
    friend class Aes;

public:
    using Base = AesBase;
    Aes() = delete;

    template <Mode M1 = M, typename = std::enable_if_t<M1 != Mode::ecb>>
    explicit Aes(BytesView secret_key, BytesView iv)
        : Base(SecretKey(secret_key), InitializationVector(iv)) {}

    template <Mode M1 = M, typename = std::enable_if_t<M1 == Mode::ecb>>
    explicit Aes(BytesView secret_key) : Base(SecretKey(secret_key)) {}

    template <Mode M1, Bits B1>
    Aes(const Aes<M1, B1>& other) : Base(other) {}

    template <Mode M1, Bits B1>
    Aes(Aes<M1, B1>&& other) noexcept : Base(std::move(other)) {}

    ~Aes() = default;

    template <Mode M1, Bits B1>
    Aes& operator=(const Aes<M1, B1>& rhs) {
        if (std::addressof(rhs) != this) {
            static_cast<Base&>(*this) = rhs;
        }
        return *this;
    }

    template <Mode M1, Bits B1>
    Aes& operator=(Aes<M1, B1>&& rhs) noexcept {
        if (std::addressof(rhs) != this) {
            static_cast<Base&>(*this) = std::move(rhs);
        }
        return *this;
    }

    std::optional<std::vector<Byte>> Encrypt(BytesView data) {
        return PerformCipher<Crypto::Encryption>(data, key_, iv_);
    }

    std::optional<std::vector<Byte>> Decrypt(BytesView data) {
        return PerformCipher<Crypto::Decryption>(data, key_, iv_);
    }

private:
    BytesView SecretKey(BytesView key) {
        if (key.size() != static_cast<size_t>(B)) {
            throw std::runtime_error(
                "secret key length " + std::to_string(key.size()) +
                " vs required " + std::to_string(static_cast<size_t>(B)));
        }
        return key;
    }

    BytesView InitializationVector(BytesView iv) {
        if (iv.size() != EVP_CIPHER_iv_length(GetCipher(M, B))) {
            throw std::runtime_error(
                "iv length must be " +
                std::to_string(EVP_CIPHER_iv_length(GetCipher(M, B))));
        }
        return iv;
    }

    template <Crypto Op>
    std::optional<std::vector<Byte>> PerformCipher(BytesView data,
                                                   BytesView secret_key,
                                                   BytesView iv) {
        auto ctx = detail::MakeSmartCtx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return std::nullopt;
        }

        auto cipher = GetCipher(M, B);
        if (!cipher) {
            return std::nullopt;
        }

        constexpr unsigned char k_tag_len = 16;

        std::vector<Byte> bytes(data.size() + EVP_MAX_BLOCK_LENGTH + k_tag_len);

        if constexpr (Op == Crypto::Encryption) {  // 加密
            RETURN_NULLOPT_IF_ZERO(EVP_EncryptInit_ex(
                ctx.get(), cipher, nullptr, secret_key.data(), iv.data()));

            int update_out_len = 0;
            RETURN_NULLOPT_IF_ZERO(EVP_EncryptUpdate(ctx.get(), bytes.data(),
                                                     &update_out_len,
                                                     data.data(), data.size()));

            int final_out_len = 0;
            RETURN_NULLOPT_IF_ZERO(EVP_EncryptFinal_ex(
                ctx.get(), bytes.data() + update_out_len, &final_out_len));

            if constexpr (M == Mode::gcm) {
                RETURN_NULLOPT_IF_ZERO(EVP_CIPHER_CTX_ctrl(
                    ctx.get(), EVP_CTRL_GCM_GET_TAG, k_tag_len,
                    bytes.data() + update_out_len + final_out_len));
                bytes.resize(update_out_len + final_out_len + k_tag_len);
            } else {
                bytes.resize(update_out_len + final_out_len);
            }
        } else {  // 解密
            if (data.size() < k_tag_len) {
                return std::nullopt;
            }

            RETURN_NULLOPT_IF_ZERO(EVP_DecryptInit_ex(
                ctx.get(), cipher, nullptr, secret_key.data(), iv.data()));

            int update_out_len = 0;
            if constexpr (M == Mode::gcm) {
                RETURN_NULLOPT_IF_ZERO(
                    EVP_DecryptUpdate(ctx.get(), bytes.data(), &update_out_len,
                                      data.data(), data.size() - k_tag_len));

                auto tag_idx = data.data() + data.size() - k_tag_len;
                RETURN_NULLOPT_IF_ZERO(
                    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                        k_tag_len, const_cast<Byte*>(tag_idx)));
            } else {
                RETURN_NULLOPT_IF_ZERO(
                    EVP_DecryptUpdate(ctx.get(), bytes.data(), &update_out_len,
                                      data.data(), data.size()));
            }

            int final_out_len = 0;
            RETURN_NULLOPT_IF_ZERO(EVP_DecryptFinal_ex(
                ctx.get(), bytes.data() + update_out_len, &final_out_len));

            bytes.resize(update_out_len + final_out_len);
        }
        return bytes;
    }

    const EVP_CIPHER* GetCipher(Mode m, Bits b) {
        switch (m) {
            case Mode::cbc:
                switch (b) {
                    case Bits::k128:
                        return EVP_aes_128_cbc();
                    case Bits::k192:
                        return EVP_aes_192_cbc();
                    case Bits::k256:
                        return EVP_aes_256_cbc();
                }
                break;
            case Mode::ecb:
                switch (b) {
                    case Bits::k128:
                        return EVP_aes_128_ecb();
                    case Bits::k192:
                        return EVP_aes_192_ecb();
                    case Bits::k256:
                        return EVP_aes_256_ecb();
                }
                break;
            case Mode::gcm:
                switch (b) {
                    case Bits::k128:
                        return EVP_aes_128_gcm();
                    case Bits::k192:
                        return EVP_aes_192_gcm();
                    case Bits::k256:
                        return EVP_aes_256_gcm();
                }
                break;
        }
        return nullptr;
    }
};
}  // namespace cipher

using Aes128cbc = cipher::Aes<cipher::Mode::cbc, cipher::Bits::k128>;
using Aes192cbc = cipher::Aes<cipher::Mode::cbc, cipher::Bits::k192>;
using Aes256cbc = cipher::Aes<cipher::Mode::cbc, cipher::Bits::k256>;
using Aes128ecb = cipher::Aes<cipher::Mode::ecb, cipher::Bits::k128>;
using Aes192ecb = cipher::Aes<cipher::Mode::ecb, cipher::Bits::k192>;
using Aes256ecb = cipher::Aes<cipher::Mode::ecb, cipher::Bits::k256>;
using Aes128gcm = cipher::Aes<cipher::Mode::gcm, cipher::Bits::k128>;
using Aes192gcm = cipher::Aes<cipher::Mode::gcm, cipher::Bits::k192>;
using Aes256gcm = cipher::Aes<cipher::Mode::gcm, cipher::Bits::k256>;
}  // namespace ckit

#endif