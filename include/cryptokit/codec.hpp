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

struct Base64 {
    enum class Status { good, error, over };

    explicit Base64(Crypto codec, bool mime = false, size_t blk_size = 1024);

    Base64(const Base64&) = delete;

    Base64(Base64&&) noexcept = default;

    ~Base64();

    Base64& operator=(const Base64&) = delete;

    Base64& operator=(Base64&&) noexcept;

    static std::optional<std::string> Encode(BytesView plain);

    static std::optional<std::string> Decode(BytesView b64);

    Base64& Init(Crypto codec, bool mime = false, size_t blk_size = 1024);

    Base64& operator<<(BytesView stream);

    Base64& operator>>(std::string& out);

    std::string Out();

    Status GetStatus() const noexcept;

private:
    std::unique_ptr<detail::Base64Impl> impl_;
    Status status_{Status::good};
};

template <char DELIM = 0>
class Hex {
    static_assert(!((DELIM >= '0' && DELIM <= '9') ||
                    (DELIM >= 'a' && DELIM <= 'f') ||
                    (DELIM >= 'A' && DELIM <= 'F')),
                  "delimiter cannot be in hex character range");

public:
    Hex() = default;

    explicit Hex(Character ctrl) : ctrl_(ctrl) {}

    explicit Hex(std::string_view prefix) : prefix_(prefix) {}

    explicit Hex(Character ctrl, std::string_view prefix)
        : prefix_(prefix), ctrl_(ctrl) {}

    std::string Encode(BytesView bytes) {
        std::string result(prefix_);
        if constexpr (DELIM) {
            result.resize(prefix_.size() + (bytes.size() * 3 - 1));
        } else {
            result.resize(prefix_.size() + (bytes.size() << 1));
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

    std::string Decode(BytesView bytes) {
        size_t index = 0;
        for (; index < prefix_.size(); ++index) {
            if (index >= bytes.size() || bytes[index] != prefix_[index]) {
                return {};
            }
        }

        std::string result(bytes.size() * 3, 0);
        size_t count = 0;
        uint32_t parse_status = 0;
        Byte parse_ch{};
        for (; index < bytes.size();) {
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
                    if (IsHexCharacter(byte)) {
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

        result.resize(count);
        return result;
    }

private:
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

    std::string prefix_{};
    Character ctrl_{Character::upper};
};
}  // namespace codec

using codec::Base64;

using codec::Hex;
}  // namespace ckit

#endif