#ifndef CRYPTO_KIT_CODEC_HPP_
#define CRYPTO_KIT_CODEC_HPP_

#include <cctype>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "cryptokit/byte_view.hpp"
#include "cryptokit/common.hpp"

namespace ckit {
namespace codec {
namespace detail {
struct Base64Impl;
}

/// 流式 Base64 操作的当前状态。
enum class Status { good, error, over };

/**
 * @brief Base64 一次性及流式编解码器。
 *
 * 流式实例由构造函数或 Init() 选择编码/解码方向。数据可分多次通过
 * operator<<() 输入，最后调用 Out() 或 operator>>() 完成处理。完成或出错后，
 * 需要调用 Init() 才能开始新的操作。
 */
class Base64 {
    std::unique_ptr<detail::Base64Impl> impl_;
    Status status_{Status::good};

public:
    /**
     * @param codec 编码或解码方向。
     * @param mime 编码时是否保留 MIME 换行；解码时交由 OpenSSL 处理换行。
     * @param blk_size 内部输出缓冲区的最小扩展大小。
     * @throws std::runtime_error 无法创建 OpenSSL 编解码上下文。
     */
    explicit Base64(Crypto codec, bool mime = false, size_t blk_size = 1024);

    Base64(const Base64&) = delete;

    Base64(Base64&&) noexcept = default;

    ~Base64();

    Base64& operator=(const Base64&) = delete;

    Base64& operator=(Base64&&) noexcept;

    /// 一次性编码；输入过大时返回 std::nullopt。
    static std::optional<std::string> Encode(BytesView plain);

    /// 一次性解码严格的、带正确填充的 Base64；格式无效时返回 std::nullopt。
    static std::optional<std::string> Decode(BytesView b64);

    /// 丢弃当前操作及输出，并按给定参数重新初始化编解码器。
    Base64& Init(Crypto codec, bool mime = false, size_t blk_size = 1024);

    /// 追加一段输入；仅在状态为 Status::good 时处理。
    Base64& operator<<(BytesView stream);

    /// 完成操作并将结果写入 @p out，语义等同于 `out = Out()`。
    Base64& operator>>(std::string& out);

    /// 完成并取出累计结果；失败或重复调用时返回空字符串。
    std::string Out();

    /// 返回当前状态：可继续、出错或已经完成。
    Status GetStatus() const noexcept;

private:
};

/**
 * @brief 十六进制编解码器。
 *
 * @tparam DELIM 每个编码字节之间的分隔符；为 0 时不使用分隔符。
 * 可配置输出字母大小写及输入/输出前缀。Decode() 要求输入前缀、分隔符和
 * 十六进制字符均严格匹配，失败时返回空字符串。由于空输入也会得到空结果，
 * 未配置前缀时调用方不能仅凭返回值区分空输入和格式错误。
 */
template <char DELIM = 0>
class Hex {
    static_assert(!((DELIM >= '0' && DELIM <= '9') ||
                    (DELIM >= 'a' && DELIM <= 'f') ||
                    (DELIM >= 'A' && DELIM <= 'F')),
                  "delimiter cannot be in hex character range");

    std::string prefix_{};
    Character ctrl_{Character::upper};

    Byte ToHexCharacter(Byte n) const noexcept {
        return n < 10 ? '0' + n
                      : (ctrl_ == Character::upper ? 'A' : 'a') + n - 10;
    }

    Byte FromHexCharacter(Byte n) const noexcept {
        return n > '9' ? n + 10 - 'A' : n - '0';
    }

    bool IsHexCharacter(Byte n) const noexcept {
        return (n >= '0' && n <= '9') || (n >= 'a' && n <= 'f') ||
               (n >= 'A' && n <= 'F');
    }

public:
    /// 构造使用大写字母、无前缀的编解码器。
    Hex() = default;

    /// 构造指定字母大小写、无前缀的编解码器。
    explicit Hex(Character ctrl) : ctrl_(ctrl) {}

    /// 构造使用大写字母及指定前缀的编解码器。
    explicit Hex(std::string_view prefix) : prefix_(prefix) {}

    /// 构造使用指定字母大小写及前缀的编解码器。
    explicit Hex(Character ctrl, std::string_view prefix)
        : prefix_(prefix), ctrl_(ctrl) {}

    /// 编码输入字节，并在结果开头添加配置的前缀。
    std::string Encode(BytesView bytes) {
        std::string result(prefix_);
        if (bytes.Empty()) {
            return result;
        }
        if constexpr (DELIM) {
            result.resize(prefix_.size() + (bytes.Length() * 3 - 1));
        } else {
            result.resize(prefix_.size() + (bytes.Length() << 1));
        }

        auto cur_pos = prefix_.size();
        for (auto byte : bytes) {
            result[cur_pos++] = ToHexCharacter(byte >> 4);
            result[cur_pos++] = ToHexCharacter(byte & 0xF);
            if constexpr (DELIM) {
                if (cur_pos < result.size()) {
                    result[cur_pos++] = DELIM;
                }
            }
        }

        return result;
    }

    /// 解码十六进制文本；格式或前缀无效时返回空字符串。
    std::string Decode(BytesView bytes) {
        size_t index = 0;
        for (; index < prefix_.size(); ++index) {
            if (index >= bytes.Length() || bytes[index] != prefix_[index]) {
                return {};
            }
        }

        std::string result((bytes.Length() - index + 1) / 2, 0);
        size_t count = 0;
        uint32_t parse_status = 0;
        Byte parse_ch{};
        for (; index < bytes.Length();) {
            Byte byte = std::toupper(bytes[index]);
            switch (parse_status % 3) {
                case 0:
                    if (!IsHexCharacter(byte)) {
                        return {};
                    }
                    parse_ch = FromHexCharacter(byte) << 4;
                    break;
                case 1:
                    if (!IsHexCharacter(byte)) {
                        return {};
                    }

                    parse_ch += FromHexCharacter(byte);
                    result[count++] = parse_ch;
                    break;
                case 2:
                    if constexpr (DELIM) {
                        if (byte != static_cast<Byte>(DELIM)) {
                            return {};
                        }
                    } else {
                        ++parse_status;
                        continue;
                    }
                    break;
                default:
                    break;
            }
            ++parse_status;
            ++index;
        }

        if constexpr (DELIM) {
            if (count > 0 && parse_status % 3 != 2) {
                return {};
            }
        } else if (parse_status % 3 == 1) {
            return {};
        }

        result.resize(count);
        return result;
    }
};
}  // namespace codec

using codec::Base64;

using codec::Hex;
}  // namespace ckit

#endif
