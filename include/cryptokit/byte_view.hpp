#ifndef CRYPTO_KIT_BYTE_VIEW_HPP__
#define CRYPTO_KIT_BYTE_VIEW_HPP__

#include <array>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace ckit {
using Byte = unsigned char;

/// 拥有连续字节数据的动态数组。
using ByteVec = std::vector<Byte>;

/// 拥有连续字节数据的字符串容器。
using ByteStr = std::basic_string<Byte>;

/// 不拥有底层数据的字节字符串视图。
using ByteStrView = std::basic_string_view<Byte>;

template <size_t N>
using ByteArr = std::array<Byte, N>;

inline constexpr Byte ToByte(char ch) { return static_cast<Byte>(ch); }

inline constexpr char ToChar(Byte byte) { return static_cast<char>(byte); }

/**
 * @brief 只读、非拥有的连续字节视图。
 *
 * 构造视图不会复制数据。调用方必须保证底层字符串、容器、数组或缓冲区
 * 在视图的整个使用期间保持有效，且不会发生导致地址失效的重分配。
 */
class BytesView {
public:
    /// 构造空视图。
    BytesView() = default;

    /// 查看字符串的全部字节，不包含字符串结尾的空字符。
    BytesView(const std::string& str);

    /// 查看字节字符串的全部内容。
    BytesView(const ByteStr& str);

    /// 查看字符数组的全部内容。
    BytesView(const std::vector<char>& vec);

    /// 查看字节数组的全部内容。
    BytesView(const ByteVec& vec);

    /// 查看从 @p buff 开始的 @p n 个字节；缓冲区必须保持有效。
    BytesView(const char* buff, size_t n);

    /// 查看从 @p buff 开始的 @p n 个字节；缓冲区必须保持有效。
    BytesView(const Byte* buff, size_t n);

    template <size_t N>
    BytesView(const std::array<char, N>& arr)
        : data_(reinterpret_cast<const Byte*>(arr.data())), len_(arr.size()) {}

    template <size_t N>
    BytesView(const ByteArr<N>& arr) : data_(arr.data()), len_(arr.size()) {}

    template <typename T, size_t N>
    using RawArrCRef = const T (&)[N];

    template <size_t N>
    BytesView(RawArrCRef<Byte, N> buff) : data_(buff), len_(N) {}

    BytesView(const BytesView& other) = default;

    BytesView(BytesView&& other) noexcept = default;

    ~BytesView() = default;

    BytesView& operator=(const BytesView& rhs) = default;

    BytesView& operator=(BytesView&& rhs) noexcept = default;

    /// 返回指定位置的字节，不执行边界检查。
    Byte operator[](size_t n) const { return data_[n]; }

    /// 返回底层缓冲区首地址；空视图可能返回 nullptr。
    constexpr const Byte* Data() const noexcept { return data_; }

    /// 以 char 字符串视图表示同一段二进制数据，不执行编码转换。
    std::string_view StrView() const noexcept {
        return std::string_view(reinterpret_cast<const char*>(data_), len_);
    }

    /// 返回视图包含的字节数。
    constexpr size_t Length() const noexcept { return len_; }

    /// 判断视图是否不包含任何字节。
    constexpr bool Empty() const noexcept { return len_ == 0; }

    /// 用于只读遍历字节视图的随机访问迭代器。
    struct Iterator {
        using iterator_category = std::random_access_iterator_tag;

        using value_type = Byte;
        using pointer = Byte*;
        using const_pointer = const Byte*;
        using reference = Byte&;
        using const_reference = const Byte&;
        using difference_type = std::ptrdiff_t;

        Iterator(const_pointer ptr = nullptr) : p_(ptr) {}

        const_reference operator*() const { return *p_; }

        const_pointer operator->() const { return p_; }

        Iterator& operator++() {
            ++p_;
            return *this;
        }

        Iterator operator++(int) {
            auto tmp = *this;
            ++(*this);
            return tmp;
        }

        Iterator& operator--() {
            --p_;
            return *this;
        }

        Iterator operator--(int) {
            auto tmp = *this;
            --(*this);
            return tmp;
        }

        Iterator& operator+=(difference_type n) {
            p_ += n;
            return *this;
        }

        Iterator& operator-=(difference_type n) {
            p_ -= n;
            return *this;
        }

        Iterator operator+(difference_type n) const { return Iterator(p_ + n); }

        Iterator operator-(difference_type n) const { return Iterator(p_ - n); }

        difference_type operator-(const Iterator& other) const {
            return p_ - other.p_;
        }

        const_reference operator[](difference_type n) const { return p_[n]; }

        bool operator==(const Iterator& other) const { return p_ == other.p_; }

        bool operator!=(const Iterator& other) const {
            return !(*this == other);
        }

        bool operator>(const Iterator& other) const { return p_ > other.p_; }

        bool operator<(const Iterator& other) const { return p_ < other.p_; }

        bool operator>=(const Iterator& other) const { return p_ >= other.p_; }

        bool operator<=(const Iterator& other) const { return p_ <= other.p_; }

    private:
        const_pointer p_;
    };

    Iterator begin() const { return data_; }

    Iterator end() const { return data_ + len_; }

private:
    const Byte* data_{nullptr};
    size_t len_{};
};
}  // namespace ckit

#endif  // CRYPTO_KIT_BYTE_VIEW_HPP__
