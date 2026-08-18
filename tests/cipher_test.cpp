#include "cryptokit/cipher.hpp"

#include <gtest/gtest.h>

#include <limits>
#include <stdexcept>
#include <type_traits>

#include "cryptokit/byte_view.hpp"
#include "gtest/gtest.h"

static_assert(!std::is_constructible_v<ckit::Aes256gcm,
                                       const ckit::Aes128gcm&>);
static_assert(!std::is_assignable_v<ckit::Aes256gcm&,
                                    const ckit::Aes128gcm&>);

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

TEST(Aes128gcmTest, matches_nist_known_answer) {
    const ckit::ByteArr<16> key{};
    const ckit::ByteArr<12> iv{};
    const ckit::ByteArr<16> plain{};
    const ckit::ByteVec expected{
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    };

    ckit::Aes128gcm gcm(key, iv);
    const auto encrypted = gcm.Encrypt(plain);
    ASSERT_TRUE(encrypted.has_value());
    EXPECT_EQ(*encrypted, expected);

    const auto decrypted = gcm.Decrypt(expected);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, ckit::ByteVec(plain.begin(), plain.end()));
}

TEST(Aes128gcmTest, rejects_tampered_ciphertext_tag_and_iv) {
    const ckit::ByteArr<16> key{};
    const ckit::ByteArr<12> iv{};
    const ckit::ByteArr<16> plain{};
    ckit::Aes128gcm gcm(key, iv);

    const auto encrypted = gcm.Encrypt(plain);
    ASSERT_TRUE(encrypted.has_value());

    auto tampered_ciphertext = *encrypted;
    tampered_ciphertext.front() ^= 0x01;
    EXPECT_FALSE(gcm.Decrypt(tampered_ciphertext).has_value());

    auto tampered_tag = *encrypted;
    tampered_tag.back() ^= 0x01;
    EXPECT_FALSE(gcm.Decrypt(tampered_tag).has_value());

    auto wrong_iv = iv;
    wrong_iv.front() ^= 0x01;
    ckit::Aes128gcm wrong_gcm(key, wrong_iv);
    EXPECT_FALSE(wrong_gcm.Decrypt(*encrypted).has_value());
}

TEST(Aes128gcmTest, rejects_input_larger_than_openssl_int_limit) {
    if constexpr (std::numeric_limits<size_t>::max() >
                  static_cast<size_t>(std::numeric_limits<int>::max())) {
        ckit::Aes128gcm gcm(ckit::BytesView("0123456789abcdef"),
                            ckit::BytesView("0123456789ab"));
        const ckit::Byte byte{};
        const ckit::BytesView oversized(
            &byte,
            static_cast<size_t>(std::numeric_limits<int>::max()) + 1U);
        EXPECT_FALSE(gcm.Encrypt(oversized).has_value());
        EXPECT_FALSE(gcm.Decrypt(oversized).has_value());
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
        ckit::Aes128gcm(ckit::BytesView("0123456789abcdef"), ckit::BytesView{}),
        std::runtime_error);

    EXPECT_THROW(ckit::Aes128gcm(ckit::BytesView("0123456789abcdef"),
                                 ckit::BytesView("1234")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes128gcm(ckit::BytesView("0123456789abcdef"),
                                 ckit::BytesView("")),
                 std::runtime_error);

    EXPECT_THROW(ckit::Aes128gcm(
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
