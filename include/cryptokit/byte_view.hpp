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
using ByteVec = std::vector<Byte>;
using ByteStr = std::basic_string<Byte>;
using ByteStrView = std::basic_string_view<Byte>;
template <size_t N>
using ByteArr = std::array<Byte, N>;

inline constexpr Byte ToByte(char ch) { return static_cast<Byte>(ch); }

inline constexpr char ToChar(Byte byte) { return static_cast<char>(byte); }

class BytesView {
public:
    BytesView() = default;

    BytesView(const std::string& str);

    BytesView(const ByteStr& str);

    BytesView(std::string_view sv);

    BytesView(ByteStrView sv);

    BytesView(const std::vector<char>& vec);

    BytesView(const ByteVec& vec);

    BytesView(const char* buff, size_t n);

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

    Byte operator[](size_t n) const { return data_[n]; }

    constexpr const Byte* Data() const noexcept { return data_; }

    std::string_view StrView() const noexcept {
        return std::string_view(reinterpret_cast<const char*>(data_), len_);
    }

    constexpr size_t Length() const noexcept { return len_; }

    constexpr bool Empty() const noexcept { return len_ == 0; }

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