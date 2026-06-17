#include "cryptokit/byte_view.hpp"

#include <gtest/gtest.h>

#include <string>

using ckit::Byte;
using ckit::BytesView;

TEST(ByteViewTest, char_string) {
    std::string str = "hello";
    ckit::BytesView view(str);
    EXPECT_EQ(view.size(), str.size());
    EXPECT_EQ(view.char_view(), str);
}

TEST(ByteViewTest, byte_string) {
    std::basic_string<Byte> str{'h', 'e', 'l', 'l', 'o'};
    BytesView view(str);
    EXPECT_EQ(view.size(), str.size());
    EXPECT_EQ(view.data(), str);
}

TEST(ByteViewTest, char_vector) {
    std::vector<char> vec{'h', 'e', 'l', 'l', 'o'};
    BytesView view(vec);
    EXPECT_EQ(view.size(), vec.size());
    for (size_t i = 0; i < view.size(); ++i) {
        EXPECT_EQ(view[i], vec.at(i));
    }
}

TEST(ByteViewTest, byte_vector) {
    std::vector<Byte> vec{'h', 'e', 'l', 'l', 'o'};
    BytesView view(vec);
    EXPECT_EQ(view.size(), vec.size());
    for (size_t i = 0; i < view.size(); ++i) {
        EXPECT_EQ(view[i], vec.at(i));
    }
}

TEST(ByteViewTest, char_std_array) {
    std::array<char, 5> arr{'h', 'e', 'l', 'l', 'o'};
    BytesView view(arr);
    EXPECT_EQ(view.size(), arr.size());
    for (size_t i = 0; i < view.size(); ++i) {
        EXPECT_EQ(view[i], arr.at(i));
    }
}

TEST(ByteViewTest, byte_std_array) {
    std::array<Byte, 5> arr{'h', 'e', 'l', 'l', 'o'};
    BytesView view(arr);
    EXPECT_EQ(view.size(), arr.size());
    for (size_t i = 0; i < view.size(); ++i) {
        EXPECT_EQ(view[i], arr.at(i));
    }
}

TEST(ByteViewTest, char_pointer) {
    char buf[] = "hello";
    BytesView view(buf, 5);
    EXPECT_EQ(view.size(), std::size(buf) - 1);
    for (size_t i = 0; i < view.size(); ++i) {
        EXPECT_EQ(view[i], buf[i]);
    }
}

TEST(ByteViewTest, byte_pointer) {
    Byte buf[] = "hello";
    BytesView view(buf, 5);
    EXPECT_EQ(view.size(), std::size(buf) - 1);
    for (size_t i = 0; i < view.size(); ++i) {
        EXPECT_EQ(view[i], buf[i]);
    }
}

TEST(ByteViewTest, byte_raw_array) {
    Byte buf[]{'h', 'e', 'l', 'l', 'o'};
    BytesView view(buf);
    EXPECT_EQ(view.size(), std::size(buf));
    for (size_t i = 0; i < view.size(); ++i) {
        EXPECT_EQ(view[i], buf[i]);
    }
}