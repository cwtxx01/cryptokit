#include "cryptokit/byte_view.hpp"

#include <string>

namespace ckit {
BytesView::BytesView(const std::string& str)
    : data_(reinterpret_cast<const Byte*>(str.data())), len_(str.size()) {}

BytesView::BytesView(const std::basic_string<Byte>& str)
    : data_(str.data()), len_(str.size()) {}

BytesView::BytesView(const std::vector<char>& vec)
    : data_(reinterpret_cast<const Byte*>(vec.data())), len_(vec.size()) {}

BytesView::BytesView(const std::vector<Byte>& vec)
    : data_(vec.data()), len_(vec.size()) {}

BytesView::BytesView(const char* buff, size_t n)
    : data_(reinterpret_cast<const Byte*>(buff)), len_(n) {}

BytesView::BytesView(const Byte* buff, size_t n) : data_(buff), len_(n) {}
}  // namespace ckit