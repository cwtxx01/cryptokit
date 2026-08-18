#ifndef CRYPTO_KIT_CIPHER_HPP_
#define CRYPTO_KIT_CIPHER_HPP_

#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>

#include "common.hpp"
#include "cryptokit/byte_view.hpp"

namespace ckit {
namespace cipher {
/// 支持的 AES 工作模式。
enum class Mode : char { gcm, ecb, cbc };

/// AES 密钥长度；枚举值以字节数表示。
enum class Bits : int { k128 = 128 / 8, k192 = 192 / 8, k256 = 256 / 8 };

namespace detail {

using SmartCtx =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

inline SmartCtx MakeSmartCtx(EVP_CIPHER_CTX* ctx) {
    return SmartCtx(ctx, EVP_CIPHER_CTX_free);
}

struct AesBase {
    ByteVec key_;
    ByteVec iv_;

    AesBase() = default;

    AesBase(BytesView key, BytesView iv)
        : key_(key.Data(), key.Data() + key.Length()),
          iv_(iv.Data(), iv.Data() + iv.Length()) {}

    AesBase(BytesView key)
        : key_(key.Data(), key.Data() + key.Length()), iv_() {}

    AesBase(const AesBase&) = default;

    AesBase(AesBase&&) noexcept = default;

    ~AesBase() { ClearKey(); }

    AesBase& operator=(const AesBase& rhs) {
        if (this != &rhs) {
            ClearKey();
            key_ = rhs.key_;
            iv_ = rhs.iv_;
        }
        return *this;
    }

    AesBase& operator=(AesBase&& rhs) noexcept {
        if (this != &rhs) {
            ClearKey();
            key_ = std::move(rhs.key_);
            iv_ = std::move(rhs.iv_);
        }
        return *this;
    }

private:
    void ClearKey() noexcept {
        if (!key_.empty()) {
            OPENSSL_cleanse(key_.data(), key_.size());
        }
    }
};
}  // namespace detail

/**
 * @brief 基于 OpenSSL EVP 的 AES 加解密器。
 *
 * 密钥长度必须与 @p B 严格匹配。CBC 使用 16 字节 IV，GCM 使用 OpenSSL
 * 为所选算法报告的 IV 长度（当前为 12 字节）；ECB 不使用 IV。GCM 密文的
 * 最后 16 字节是认证标签，Decrypt() 会验证该标签。CBC 和 ECB 使用 OpenSSL
 * 默认的 PKCS#7 填充，不提供完整性认证。
 *
 * 对象保存密钥与 IV 的副本，析构和覆盖赋值时会清理原密钥内存。同一密钥下
 * 每次 GCM 加密必须使用唯一 IV，通常应为每条消息创建新对象。
 *
 * @tparam M AES 工作模式。
 * @tparam B AES 密钥长度。
 */
template <Mode M, Bits B>
class Aes : private detail::AesBase {
public:
    using Base = AesBase;
    Aes() = delete;

    template <Mode M1 = M, typename = std::enable_if_t<M1 != Mode::ecb>>
    /**
     * @brief 构造 CBC 或 GCM 加解密器。
     * @throws std::runtime_error 密钥或 IV 长度不符合所选算法要求。
     */
    explicit Aes(BytesView secret_key, BytesView iv)
        : Base(SecretKey(secret_key), InitializationVector(iv)) {}

    template <Mode M1 = M, typename = std::enable_if_t<M1 == Mode::ecb>>
    /**
     * @brief 构造 ECB 加解密器。
     * @throws std::runtime_error 密钥长度不符合所选算法要求。
     */
    explicit Aes(BytesView secret_key) : Base(SecretKey(secret_key)) {}

    Aes(const Aes&) = default;

    Aes(Aes&&) noexcept = default;

    ~Aes() = default;

    Aes& operator=(const Aes&) = default;

    Aes& operator=(Aes&&) noexcept = default;

    /**
     * @brief 加密输入数据。
     * @return 成功时返回密文；GCM 结果末尾附加 16 字节认证标签，失败时返回
     * std::nullopt。
     */
    std::optional<ByteVec> Encrypt(BytesView data) {
        return PerformCipher<Crypto::enc>(data, key_, iv_);
    }

    /**
     * @brief 解密输入数据。
     * @return 成功时返回明文；输入无效、填充错误或 GCM 认证失败时返回
     * std::nullopt。
     */
    std::optional<ByteVec> Decrypt(BytesView data) {
        return PerformCipher<Crypto::dec>(data, key_, iv_);
    }

private:
    BytesView SecretKey(BytesView key) {
        if (key.Length() != static_cast<size_t>(B)) {
            throw std::runtime_error(
                "secret key length " + std::to_string(key.Length()) +
                " vs required " + std::to_string(static_cast<size_t>(B)));
        }
        return key;
    }

    BytesView InitializationVector(BytesView iv) {
        if (iv.Length() != EVP_CIPHER_iv_length(GetCipher(M, B))) {
            throw std::runtime_error(
                "iv length must be " +
                std::to_string(EVP_CIPHER_iv_length(GetCipher(M, B))));
        }
        return iv;
    }

    template <Crypto Op>
    std::optional<ByteVec> PerformCipher(BytesView data, BytesView secret_key,
                                         BytesView iv) {
        if (data.Length() >
            static_cast<size_t>(std::numeric_limits<int>::max())) {
            return std::nullopt;
        }

        auto ctx = detail::MakeSmartCtx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return std::nullopt;
        }

        auto cipher = GetCipher(M, B);
        if (!cipher) {
            return std::nullopt;
        }

        constexpr unsigned char k_tag_len = 16;

        ByteVec bytes(data.Length() + EVP_MAX_BLOCK_LENGTH + k_tag_len);

        if constexpr (Op == Crypto::enc) {  // 加密
            if (!EVP_EncryptInit_ex(ctx.get(), cipher, nullptr,
                                    secret_key.Data(), iv.Data())) {
                return std::nullopt;
            }

            int update_out_len = 0;
            if (!EVP_EncryptUpdate(ctx.get(), bytes.data(), &update_out_len,
                                   data.Data(),
                                   static_cast<int>(data.Length()))) {
                return std::nullopt;
            }

            int final_out_len = 0;
            if (!EVP_EncryptFinal_ex(ctx.get(), bytes.data() + update_out_len,
                                     &final_out_len)) {
                return std::nullopt;
            }

            if constexpr (M == Mode::gcm) {
                if (!EVP_CIPHER_CTX_ctrl(
                        ctx.get(), EVP_CTRL_GCM_GET_TAG, k_tag_len,
                        bytes.data() + update_out_len + final_out_len)) {
                    return std::nullopt;
                }
                bytes.resize(update_out_len + final_out_len + k_tag_len);
            } else {
                bytes.resize(update_out_len + final_out_len);
            }
        } else {  // 解密
            if (data.Length() < k_tag_len) {
                return std::nullopt;
            }

            if (!EVP_DecryptInit_ex(ctx.get(), cipher, nullptr,
                                    secret_key.Data(), iv.Data())) {
                return std::nullopt;
            }

            int update_out_len = 0;
            if constexpr (M == Mode::gcm) {
                if (!EVP_DecryptUpdate(ctx.get(), bytes.data(), &update_out_len,
                                       data.Data(),
                                       static_cast<int>(data.Length() -
                                                        k_tag_len))) {
                    return std::nullopt;
                }

                auto tag_idx = data.Data() + data.Length() - k_tag_len;
                if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                         k_tag_len,
                                         const_cast<Byte*>(tag_idx))) {
                    return std::nullopt;
                }
            } else {
                if (!EVP_DecryptUpdate(ctx.get(), bytes.data(), &update_out_len,
                                       data.Data(),
                                       static_cast<int>(data.Length()))) {
                    return std::nullopt;
                }
            }

            int final_out_len = 0;
            if (!EVP_DecryptFinal_ex(ctx.get(), bytes.data() + update_out_len,
                                     &final_out_len)) {
                return std::nullopt;
            }

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

using AesMode = cipher::Mode;
using AesBits = cipher::Bits;

using Aes128cbc = cipher::Aes<AesMode::cbc, AesBits::k128>;
using Aes192cbc = cipher::Aes<AesMode::cbc, AesBits::k192>;
using Aes256cbc = cipher::Aes<AesMode::cbc, AesBits::k256>;
using Aes128ecb = cipher::Aes<AesMode::ecb, AesBits::k128>;
using Aes192ecb = cipher::Aes<AesMode::ecb, AesBits::k192>;
using Aes256ecb = cipher::Aes<AesMode::ecb, AesBits::k256>;
using Aes128gcm = cipher::Aes<AesMode::gcm, AesBits::k128>;
using Aes192gcm = cipher::Aes<AesMode::gcm, AesBits::k192>;
using Aes256gcm = cipher::Aes<AesMode::gcm, AesBits::k256>;
}  // namespace ckit

#endif
