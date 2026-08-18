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
/// 支持生成的 RSA 模数位数。
enum class Bits { b1024 = 1024, b2048 = 2048, b3072 = 3072, b4096 = 4096 };

/// RSA 加密或签名操作使用的填充模式。
enum class Padding {
    pkcs1 = RSA_PKCS1_PADDING,
    oaep = RSA_PKCS1_OAEP_PADDING,
    pss = RSA_PKCS1_PSS_PADDING,
    x931 = RSA_X931_PADDING,
};

class RsaPrivKey;

/**
 * @brief RSA 公钥及其加密、验签操作。
 *
 * 构造函数不会抛出解析或文件读取错误；应通过 IsOk() 检查对象是否可用。
 * 对象不可复制或移动。新代码进行加密时应优先使用 OAEP，验签时应优先
 * 使用 PSS。
 */
class RsaPubKey {
    struct Impl;
    std::unique_ptr<Impl> impl_;

public:
    /// 导出 SubjectPublicKeyInfo PEM 文本；对象无效或导出失败时返回 std::nullopt。
    std::optional<std::string> Pem() const;

    /**
     * @brief 使用公钥加密数据。
     * @param data 明文；最大长度由密钥位数、填充和摘要算法共同决定。
     * @param padding 加密填充模式，通常应为 Padding::oaep。
     * @param oaep OAEP 摘要；仅在 OAEP 模式下使用。
     * @param mgf1 OAEP 的 MGF1 摘要；仅在 OAEP 模式下使用。
     * @return 密文，参数不兼容、输入过长或 OpenSSL 操作失败时返回
     * std::nullopt。
     */
    std::optional<ByteVec> Encrypt(
        BytesView data, Padding padding = Padding::oaep,
        digest::Mode oaep = digest::Mode::sha256,
        digest::Mode mgf1 = digest::Mode::sha256) const;

    /**
     * @brief 验证数据的 RSA 签名。
     * @param data 被签名的原始数据，方法内部会计算摘要。
     * @param signature 待验证的签名字节。
     * @param padding 签名填充模式。
     * @param digest 消息摘要算法。
     * @param mgf1 PSS 的 MGF1 摘要；仅在 PSS 模式下使用。
     * @param saltlen PSS 盐长度；可使用 OpenSSL 的 RSA_PSS_SALTLEN_* 常量。
     * @return 签名有效时为 true；签名不匹配、对象无效或操作失败时为 false。
     */
    bool Verify(BytesView data, BytesView signature,
                Padding padding = Padding::pss,
                digest::Mode digest = digest::Mode::sha256,
                digest::Mode mgf1 = digest::Mode::sha256,
                int saltlen = RSA_PSS_SALTLEN_DIGEST) const;

    /// 判断公钥是否已成功加载或派生。
    bool IsOk() const noexcept;

    /// 从未加密的 SubjectPublicKeyInfo PEM 文本加载公钥。
    explicit RsaPubKey(BytesView pem);

    /// 从有效私钥派生对应公钥；私钥无效时构造无效对象。
    explicit RsaPubKey(const RsaPrivKey& rsa);

    /// 从文件加载未加密的 SubjectPublicKeyInfo PEM 公钥。
    explicit RsaPubKey(const std::filesystem::path& path);

    ~RsaPubKey();
};

/**
 * @brief RSA 私钥及其解密、签名操作。
 *
 * 可生成新密钥或从未加密 PEM 加载私钥。构造失败不会抛出解析或文件读取
 * 错误；应通过 IsOk() 检查对象是否可用。对象不可复制或移动。
 */
class RsaPrivKey {
    friend class RsaPubKey;

    struct Impl;
    std::unique_ptr<Impl> impl_;

public:
    /// 导出未加密的 PKCS#8 PEM 私钥；对象无效或导出失败时返回 std::nullopt。
    std::optional<std::string> Pem() const;

    /**
     * @brief 使用私钥解密数据。
     * @param data 由匹配公钥和相同参数生成的密文。
     * @param padding 加密填充模式。
     * @param oaep OAEP 摘要；仅在 OAEP 模式下使用。
     * @param mgf1 OAEP 的 MGF1 摘要；仅在 OAEP 模式下使用。
     * @return 明文；参数不匹配、密文无效或操作失败时返回 std::nullopt。
     */
    std::optional<ByteVec> Decrypt(
        BytesView data, Padding padding = Padding::oaep,
        digest::Mode oaep = digest::Mode::sha256,
        digest::Mode mgf1 = digest::Mode::sha256) const;

    /**
     * @brief 计算数据摘要并生成 RSA 签名。
     * @param data 待签名的原始数据。
     * @param digest 消息摘要算法。
     * @param padding 签名填充模式。
     * @param mgf1 PSS 的 MGF1 摘要；仅在 PSS 模式下使用。
     * @param saltlen PSS 盐长度；可使用 OpenSSL 的 RSA_PSS_SALTLEN_* 常量。
     * @return 签名字节，参数不兼容或操作失败时返回 std::nullopt。
     */
    std::optional<ByteVec> Sign(BytesView data,
                                digest::Mode digest = digest::Mode::sha256,
                                Padding padding = Padding::pss,
                                digest::Mode mgf1 = digest::Mode::sha256,
                                int saltlen = RSA_PSS_SALTLEN_DIGEST) const;

    /// 判断私钥是否已成功生成或加载。
    bool IsOk() const noexcept;

    /// 从未加密的 PKCS#8 或 OpenSSL 支持的 PEM 私钥文本加载密钥。
    explicit RsaPrivKey(BytesView pem);

    /// 生成指定模数位数的新 RSA 私钥；生成结果通过 IsOk() 检查。
    explicit RsaPrivKey(Bits bits);

    /// 从文件加载未加密的 PEM 私钥。
    explicit RsaPrivKey(const std::filesystem::path& path);

    ~RsaPrivKey();
};
}  // namespace pkey

using pkey::RsaPrivKey;
using pkey::RsaPubKey;
}  // namespace ckit
#endif
