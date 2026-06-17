#include "cryptokit/cipher.hpp"

#include <gtest/gtest.h>

#include <stdexcept>

#include "cryptokit/byte_view.hpp"
#include "gtest/gtest.h"

TEST(Aes128ecbTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes128ecb ecb(ckit::BytesView("0123456789abcdef"));
    auto encrypt_result = ecb.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = ecb.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes128ecbTest, key_mismatch) {
    EXPECT_THROW(ckit::Aes128ecb(ckit::BytesView{}), std::runtime_error);

    EXPECT_THROW(ckit::Aes128ecb(ckit::BytesView("0123456789")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes128ecb(ckit::BytesView("")), std::runtime_error);

    EXPECT_THROW(ckit::Aes128ecb(ckit::BytesView(
                     "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes192ecbTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes192ecb ecb(ckit::BytesView("0123456789abcdef01234567"));
    auto encrypt_result = ecb.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = ecb.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes192ecbTest, key_mismatch) {
    EXPECT_THROW(ckit::Aes192ecb(ckit::BytesView{}), std::runtime_error);

    EXPECT_THROW(ckit::Aes192ecb(ckit::BytesView("0123456789")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192ecb(ckit::BytesView("")), std::runtime_error);

    EXPECT_THROW(ckit::Aes192ecb(ckit::BytesView(
                     "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes256ecbTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes256ecb ecb(ckit::BytesView("0123456789abcdef0123456789abcdef"));
    auto encrypt_result = ecb.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = ecb.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes256ecbTest, key_mismatch) {
    EXPECT_THROW(ckit::Aes256ecb(ckit::BytesView{}), std::runtime_error);

    EXPECT_THROW(ckit::Aes256ecb(ckit::BytesView("0123456789")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes256ecb(ckit::BytesView("")), std::runtime_error);

    EXPECT_THROW(ckit::Aes256ecb(ckit::BytesView(
                     "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes128cbcTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes128cbc cbc(ckit::BytesView("0123456789abcdef"),
                        ckit::BytesView("0123456789abcdef"));
    auto encrypt_result = cbc.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = cbc.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes128cbcTest, key_mismatch) {
    EXPECT_THROW(
        ckit::Aes128cbc(ckit::BytesView{}, ckit::BytesView("0123456789abcdef")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes128cbc(ckit::BytesView("0123456789"),
                                 ckit::BytesView("0123456789abcdef")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes128cbc(ckit::BytesView(""),
                                 ckit::BytesView("0123456789abcdef")),
                 std::runtime_error);

    EXPECT_THROW(
        ckit::Aes128cbc(
            ckit::BytesView("0123456789abcdef0123456789abcdef0123456789abcdef"),
            ckit::BytesView("0123456789abcdef")),
        std::runtime_error);
}

TEST(Aes128cbcTest, iv_mismatch) {
    EXPECT_THROW(
        ckit::Aes128cbc(ckit::BytesView("0123456789abcdef"), ckit::BytesView{}),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes128cbc(ckit::BytesView("0123456789abcdef"),
                                 ckit::BytesView("0123456789")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes128cbc(ckit::BytesView("0123456789abcdef"),
                                 ckit::BytesView("")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes128cbc(
                     ckit::BytesView("0123456789abcdef"),
                     ckit::BytesView(
                         "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes192cbcTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes192cbc cbc(ckit::BytesView("0123456789abcdef01234567"),
                        ckit::BytesView("0123456789abcdef"));
    auto encrypt_result = cbc.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = cbc.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes192cbcTest, key_mismatch) {
    EXPECT_THROW(
        ckit::Aes192cbc(ckit::BytesView{}, ckit::BytesView("0123456789abcdef")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes192cbc(ckit::BytesView("0123456789"),
                                 ckit::BytesView("0123456789abcdef")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192cbc(ckit::BytesView(""),
                                 ckit::BytesView("0123456789abcdef")),
                 std::runtime_error);

    EXPECT_THROW(
        ckit::Aes192cbc(
            ckit::BytesView("0123456789abcdef0123456789abcdef0123456789abcdef"),
            ckit::BytesView("0123456789abcdef")),
        std::runtime_error);
}

TEST(Aes192cbcTest, iv_mismatch) {
    EXPECT_THROW(ckit::Aes192cbc(ckit::BytesView("0123456789abcdef01234567"),
                                 ckit::BytesView{}),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192cbc(ckit::BytesView("0123456789abcdef01234567"),
                                 ckit::BytesView("0123456789")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192cbc(ckit::BytesView("0123456789abcdef01234567"),
                                 ckit::BytesView("")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192cbc(
                     ckit::BytesView("0123456789abcdef01234567"),
                     ckit::BytesView(
                         "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes256cbcTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes256cbc cbc(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView("0123456789abcdef"));
    auto encrypt_result = cbc.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = cbc.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes256cbcTest, key_mismatch) {
    EXPECT_THROW(
        ckit::Aes256cbc(ckit::BytesView{}, ckit::BytesView("0123456789abcdef")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes256cbc(ckit::BytesView("0123456789"),
                                 ckit::BytesView("0123456789abcdef")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes256cbc(ckit::BytesView(""),
                                 ckit::BytesView("0123456789abcdef")),
                 std::runtime_error);

    EXPECT_THROW(
        ckit::Aes256cbc(
            ckit::BytesView("0123456789abcdef0123456789abcdef0123456789abcdef"),
            ckit::BytesView("0123456789abcdef")),
        std::runtime_error);
}

TEST(Aes256cbcTest, iv_mismatch) {
    EXPECT_THROW(
        ckit::Aes256cbc(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView{}),
        std::runtime_error);

    EXPECT_THROW(
        ckit::Aes256cbc(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView("0123456789")),
        std::runtime_error);

    EXPECT_THROW(
        ckit::Aes256cbc(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView("")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes256cbc(
                     ckit::BytesView("0123456789abcdef0123456789abcdef"),
                     ckit::BytesView(
                         "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes128gcmTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes128gcm gcm(ckit::BytesView("0123456789abcdef"),
                        ckit::BytesView("0123456789ab"));
    auto encrypt_result = gcm.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = gcm.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes128gcmTest, key_mismatch) {
    EXPECT_THROW(
        ckit::Aes128gcm(ckit::BytesView{}, ckit::BytesView("0123456789ab")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes128gcm(ckit::BytesView("0123456789"),
                                 ckit::BytesView("0123456789ab")),
                 std::runtime_error);

    EXPECT_THROW(
        ckit::Aes128gcm(ckit::BytesView(""), ckit::BytesView("0123456789ab")),
        std::runtime_error);

    EXPECT_THROW(
        ckit::Aes128gcm(
            ckit::BytesView("0123456789abcdef0123456789abcdef0123456789abcdef"),
            ckit::BytesView("0123456789ab")),
        std::runtime_error);
}

TEST(Aes128gcmTest, iv_mismatch) {
    EXPECT_THROW(
        ckit::Aes192gcm(ckit::BytesView("0123456789abcdef"), ckit::BytesView{}),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes192gcm(ckit::BytesView("0123456789abcdef"),
                                 ckit::BytesView("1234")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192gcm(ckit::BytesView("0123456789abcdef"),
                                 ckit::BytesView("")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192gcm(
                     ckit::BytesView("0123456789abcdef"),
                     ckit::BytesView(
                         "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes192gcmTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes192gcm gcm(ckit::BytesView("0123456789abcdef01234567"),
                        ckit::BytesView("0123456789ab"));
    auto encrypt_result = gcm.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = gcm.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes192gcmTest, key_mismatch) {
    EXPECT_THROW(
        ckit::Aes192gcm(ckit::BytesView{}, ckit::BytesView("0123456789ab")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes192gcm(ckit::BytesView("0123456789"),
                                 ckit::BytesView("0123456789ab")),
                 std::runtime_error);

    EXPECT_THROW(
        ckit::Aes192gcm(ckit::BytesView(""), ckit::BytesView("0123456789ab")),
        std::runtime_error);

    EXPECT_THROW(
        ckit::Aes192gcm(
            ckit::BytesView("0123456789abcdef0123456789abcdef0123456789abcdef"),
            ckit::BytesView("0123456789ab")),
        std::runtime_error);
}

TEST(Aes192gcmTest, iv_mismatch) {
    EXPECT_THROW(ckit::Aes192gcm(ckit::BytesView("0123456789abcdef01234567"),
                                 ckit::BytesView{}),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192gcm(ckit::BytesView("0123456789abcdef01234567"),
                                 ckit::BytesView("1234")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192gcm(ckit::BytesView("0123456789abcdef01234567"),
                                 ckit::BytesView("")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes192gcm(
                     ckit::BytesView("0123456789abcdef01234567"),
                     ckit::BytesView(
                         "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}

TEST(Aes256gcmTest, encrypt_decrypt) {
    std::string plain = "abcdef";

    ckit::Aes256gcm gcm(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView("0123456789ab"));
    auto encrypt_result = gcm.Encrypt(plain);
    EXPECT_TRUE(encrypt_result.has_value());
    auto decrypt_result = gcm.Decrypt(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.has_value());
    EXPECT_EQ(decrypt_result->size(), plain.size());
    for (size_t idx = 0; idx < decrypt_result->size(); ++idx) {
        EXPECT_EQ(decrypt_result->at(idx), plain[idx]);
    }
}

TEST(Aes256gcmTest, key_mismatch) {
    EXPECT_THROW(
        ckit::Aes256gcm(ckit::BytesView{}, ckit::BytesView("0123456789ab")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes256gcm(ckit::BytesView("0123456789"),
                                 ckit::BytesView("0123456789ab")),
                 std::runtime_error);

    EXPECT_THROW(
        ckit::Aes256gcm(ckit::BytesView(""), ckit::BytesView("0123456789ab")),
        std::runtime_error);

    EXPECT_THROW(
        ckit::Aes256gcm(
            ckit::BytesView("0123456789abcdef0123456789abcdef0123456789abcdef"),
            ckit::BytesView("0123456789ab")),
        std::runtime_error);
}

TEST(Aes256gcmTest, iv_mismatch) {
    EXPECT_THROW(
        ckit::Aes256gcm(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView{}),
        std::runtime_error);

    EXPECT_THROW(
        ckit::Aes256gcm(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView("0123456789")),
        std::runtime_error);

    EXPECT_THROW(
        ckit::Aes256gcm(ckit::BytesView("0123456789abcdef0123456789abcdef"),
                        ckit::BytesView("")),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes256gcm(
                     ckit::BytesView("0123456789abcdef0123456789abcdef"),
                     ckit::BytesView(
                         "0123456789abcdef0123456789abcdef0123456789abcdef")),
                 std::runtime_error);
}