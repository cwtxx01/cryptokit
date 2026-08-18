#include "cryptokit/pkey.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <string>

namespace {

class RsaTest : public ::testing::Test {
protected:
    ckit::RsaPrivKey private_key_{ckit::pkey::Bits::b2048};
    ckit::RsaPubKey public_key_{private_key_};
    const std::string plain_{"rsa\0encryption payload", 22};
    const std::string message_ = "rsa signature payload";

    void SetUp() override {
        ASSERT_TRUE(private_key_.IsOk());
        ASSERT_TRUE(public_key_.IsOk());
    }
};

struct EncryptionFormat {
    const char* name;
    ckit::pkey::Padding padding;
    ckit::DigestMode oaep;
    ckit::DigestMode mgf1;
};

class RsaEncryptionFormatTest
    : public ::testing::TestWithParam<EncryptionFormat> {
protected:
    ckit::RsaPrivKey private_key_{ckit::pkey::Bits::b2048};
    ckit::RsaPubKey public_key_{private_key_};

    void SetUp() override {
        ASSERT_TRUE(private_key_.IsOk());
        ASSERT_TRUE(public_key_.IsOk());
    }
};

struct SignatureFormat {
    const char* name;
    ckit::pkey::Padding padding;
    ckit::DigestMode digest;
    ckit::DigestMode mgf1;
};

class RsaSignatureFormatTest
    : public ::testing::TestWithParam<SignatureFormat> {
protected:
    ckit::RsaPrivKey private_key_{ckit::pkey::Bits::b2048};
    ckit::RsaPubKey public_key_{private_key_};

    void SetUp() override {
        ASSERT_TRUE(private_key_.IsOk());
        ASSERT_TRUE(public_key_.IsOk());
    }
};

struct KeyBits {
    const char* name;
    ckit::pkey::Bits bits;
    std::size_t encoded_size;
};

class RsaKeyBitsTest : public ::testing::TestWithParam<KeyBits> {};

TEST_F(RsaTest, generates_and_loads_pem) {
    const auto private_pem = private_key_.Pem();
    ASSERT_TRUE(private_pem.has_value());
    EXPECT_NE(private_pem->find("-----BEGIN PRIVATE KEY-----"),
              std::string::npos);

    ckit::RsaPrivKey loaded_private{ckit::BytesView(*private_pem)};
    ASSERT_TRUE(loaded_private.IsOk());

    const auto public_pem = public_key_.Pem();
    ASSERT_TRUE(public_pem.has_value());
    EXPECT_NE(public_pem->find("-----BEGIN PUBLIC KEY-----"),
              std::string::npos);

    ckit::RsaPubKey loaded_public{ckit::BytesView(*public_pem)};
    ASSERT_TRUE(loaded_public.IsOk());

    const auto signature = loaded_private.Sign(ckit::BytesView(message_));
    ASSERT_TRUE(signature.has_value());
    EXPECT_TRUE(loaded_public.Verify(ckit::BytesView(message_),
                                     ckit::BytesView(*signature)));
}

TEST_F(RsaTest, encrypts_and_decrypts_using_all_defaults) {
    const auto encrypted = public_key_.Encrypt(ckit::BytesView(plain_));
    ASSERT_TRUE(encrypted.has_value());
    EXPECT_NE(ckit::BytesView(*encrypted).StrView(), plain_);

    const auto decrypted = private_key_.Decrypt(ckit::BytesView(*encrypted));
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(ckit::BytesView(*decrypted).StrView(), plain_);
}

TEST_F(RsaTest, defaults_oaep_digests_when_padding_is_specified) {
    const auto encrypted = public_key_.Encrypt(ckit::BytesView(plain_),
                                                ckit::pkey::Padding::oaep);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = private_key_.Decrypt(
        ckit::BytesView(*encrypted), ckit::pkey::Padding::oaep);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(ckit::BytesView(*decrypted).StrView(), plain_);
}

TEST_F(RsaTest, defaults_oaep_mgf1_when_digest_is_specified) {
    const auto encrypted = public_key_.Encrypt(
        ckit::BytesView(plain_), ckit::pkey::Padding::oaep,
        ckit::DigestMode::sha384);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = private_key_.Decrypt(
        ckit::BytesView(*encrypted), ckit::pkey::Padding::oaep,
        ckit::DigestMode::sha384);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(ckit::BytesView(*decrypted).StrView(), plain_);
}

TEST_F(RsaTest, encrypts_and_decrypts_using_explicit_parameters) {
    const auto encrypted = public_key_.Encrypt(
        ckit::BytesView(plain_), ckit::pkey::Padding::oaep,
        ckit::DigestMode::sha384, ckit::DigestMode::sha512);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = private_key_.Decrypt(
        ckit::BytesView(*encrypted), ckit::pkey::Padding::oaep,
        ckit::DigestMode::sha384, ckit::DigestMode::sha512);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(ckit::BytesView(*decrypted).StrView(), plain_);
}

TEST_P(RsaEncryptionFormatTest, encrypts_and_decrypts) {
    const auto& format = GetParam();
    const std::string plain{"common rsa encryption format"};

    const auto encrypted = public_key_.Encrypt(
        ckit::BytesView(plain), format.padding, format.oaep, format.mgf1);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = private_key_.Decrypt(
        ckit::BytesView(*encrypted), format.padding, format.oaep, format.mgf1);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(ckit::BytesView(*decrypted).StrView(), plain);
}

INSTANTIATE_TEST_SUITE_P(
    common_formats, RsaEncryptionFormatTest,
    ::testing::Values(
        EncryptionFormat{"pkcs1_v1_5", ckit::pkey::Padding::pkcs1,
                         ckit::DigestMode::sha256, ckit::DigestMode::sha256},
        EncryptionFormat{"oaep_sha1", ckit::pkey::Padding::oaep,
                         ckit::DigestMode::sha1, ckit::DigestMode::sha1},
        EncryptionFormat{"oaep_sha256", ckit::pkey::Padding::oaep,
                         ckit::DigestMode::sha256, ckit::DigestMode::sha256},
        EncryptionFormat{"oaep_sha384", ckit::pkey::Padding::oaep,
                         ckit::DigestMode::sha384, ckit::DigestMode::sha384},
        EncryptionFormat{"oaep_sha512", ckit::pkey::Padding::oaep,
                         ckit::DigestMode::sha512, ckit::DigestMode::sha512}),
    [](const ::testing::TestParamInfo<EncryptionFormat>& info) {
        return info.param.name;
    });

TEST_F(RsaTest, rejects_mismatched_oaep_digest) {
    const auto encrypted = public_key_.Encrypt(ckit::BytesView(plain_));
    ASSERT_TRUE(encrypted.has_value());

    EXPECT_FALSE(private_key_
                     .Decrypt(ckit::BytesView(*encrypted),
                              ckit::pkey::Padding::oaep,
                              ckit::DigestMode::sha384)
                     .has_value());
}

TEST_F(RsaTest, signs_and_verifies_using_all_defaults) {
    const auto signature = private_key_.Sign(ckit::BytesView(message_));
    ASSERT_TRUE(signature.has_value());
    EXPECT_TRUE(public_key_.Verify(ckit::BytesView(message_),
                                   ckit::BytesView(*signature)));

    const std::string tampered_message = "rsa signature payload!";
    EXPECT_FALSE(public_key_.Verify(ckit::BytesView(tampered_message),
                                    ckit::BytesView(*signature)));

    auto tampered_signature = *signature;
    ASSERT_FALSE(tampered_signature.empty());
    tampered_signature.front() ^= 0x01;
    EXPECT_FALSE(public_key_.Verify(ckit::BytesView(message_),
                                    ckit::BytesView(tampered_signature)));
}

TEST_F(RsaTest, defaults_sign_padding_and_verify_digest) {
    const auto signature =
        private_key_.Sign(ckit::BytesView(message_), ckit::DigestMode::sha256);
    ASSERT_TRUE(signature.has_value());

    EXPECT_TRUE(public_key_.Verify(ckit::BytesView(message_),
                                   ckit::BytesView(*signature),
                                   ckit::pkey::Padding::pss));
}

TEST_F(RsaTest, defaults_signature_mgf1_and_salt_length) {
    const auto signature = private_key_.Sign(
        ckit::BytesView(message_), ckit::DigestMode::sha384,
        ckit::pkey::Padding::pss);
    ASSERT_TRUE(signature.has_value());

    EXPECT_TRUE(public_key_.Verify(
        ckit::BytesView(message_), ckit::BytesView(*signature),
        ckit::pkey::Padding::pss, ckit::DigestMode::sha384));
}

TEST_F(RsaTest, defaults_signature_salt_length) {
    const auto signature = private_key_.Sign(
        ckit::BytesView(message_), ckit::DigestMode::sha384,
        ckit::pkey::Padding::pss, ckit::DigestMode::sha512);
    ASSERT_TRUE(signature.has_value());

    EXPECT_TRUE(public_key_.Verify(
        ckit::BytesView(message_), ckit::BytesView(*signature),
        ckit::pkey::Padding::pss, ckit::DigestMode::sha384,
        ckit::DigestMode::sha512));
}

TEST_F(RsaTest, signs_and_verifies_using_explicit_parameters) {
    constexpr int salt_length = 20;
    const auto signature = private_key_.Sign(
        ckit::BytesView(message_), ckit::DigestMode::sha384,
        ckit::pkey::Padding::pss, ckit::DigestMode::sha512, salt_length);
    ASSERT_TRUE(signature.has_value());

    EXPECT_TRUE(public_key_.Verify(
        ckit::BytesView(message_), ckit::BytesView(*signature),
        ckit::pkey::Padding::pss, ckit::DigestMode::sha384,
        ckit::DigestMode::sha512, salt_length));
}

TEST_P(RsaSignatureFormatTest, signs_and_verifies) {
    const auto& format = GetParam();
    const std::string message = "common rsa signature format";

    const auto signature = private_key_.Sign(
        ckit::BytesView(message), format.digest, format.padding, format.mgf1,
        RSA_PSS_SALTLEN_DIGEST);
    ASSERT_TRUE(signature.has_value());

    EXPECT_TRUE(public_key_.Verify(
        ckit::BytesView(message), ckit::BytesView(*signature), format.padding,
        format.digest, format.mgf1, RSA_PSS_SALTLEN_DIGEST));
}

INSTANTIATE_TEST_SUITE_P(
    common_formats, RsaSignatureFormatTest,
    ::testing::Values(
        SignatureFormat{"pkcs1_sha256", ckit::pkey::Padding::pkcs1,
                        ckit::DigestMode::sha256, ckit::DigestMode::sha256},
        SignatureFormat{"pkcs1_sha384", ckit::pkey::Padding::pkcs1,
                        ckit::DigestMode::sha384, ckit::DigestMode::sha384},
        SignatureFormat{"pkcs1_sha512", ckit::pkey::Padding::pkcs1,
                        ckit::DigestMode::sha512, ckit::DigestMode::sha512},
        SignatureFormat{"pss_sha256", ckit::pkey::Padding::pss,
                        ckit::DigestMode::sha256, ckit::DigestMode::sha256},
        SignatureFormat{"pss_sha384", ckit::pkey::Padding::pss,
                        ckit::DigestMode::sha384, ckit::DigestMode::sha384},
        SignatureFormat{"pss_sha512", ckit::pkey::Padding::pss,
                        ckit::DigestMode::sha512, ckit::DigestMode::sha512}),
    [](const ::testing::TestParamInfo<SignatureFormat>& info) {
        return info.param.name;
    });

TEST_F(RsaTest, rejects_mismatched_signature_padding) {
    const auto signature = private_key_.Sign(ckit::BytesView(message_));
    ASSERT_TRUE(signature.has_value());

    EXPECT_FALSE(public_key_.Verify(
        ckit::BytesView(message_), ckit::BytesView(*signature),
        ckit::pkey::Padding::pkcs1, ckit::DigestMode::sha256));
}

TEST_P(RsaKeyBitsTest, generates_and_performs_core_operations) {
    const auto& key_bits = GetParam();
    ckit::RsaPrivKey private_key{key_bits.bits};
    ASSERT_TRUE(private_key.IsOk());

    const auto private_pem = private_key.Pem();
    ASSERT_TRUE(private_pem.has_value());

    ckit::RsaPubKey public_key{private_key};
    ASSERT_TRUE(public_key.IsOk());
    EXPECT_TRUE(public_key.Pem().has_value());

    const std::string data = "rsa key bits";
    const auto encrypted = public_key.Encrypt(ckit::BytesView(data));
    ASSERT_TRUE(encrypted.has_value());
    EXPECT_EQ(encrypted->size(), key_bits.encoded_size);

    const auto decrypted = private_key.Decrypt(ckit::BytesView(*encrypted));
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(ckit::BytesView(*decrypted).StrView(), data);

    const auto signature = private_key.Sign(ckit::BytesView(data));
    ASSERT_TRUE(signature.has_value());
    EXPECT_EQ(signature->size(), key_bits.encoded_size);
    EXPECT_TRUE(public_key.Verify(ckit::BytesView(data),
                                  ckit::BytesView(*signature)));
}

INSTANTIATE_TEST_SUITE_P(
    all_bits, RsaKeyBitsTest,
    ::testing::Values(
        KeyBits{"bits_1024", ckit::pkey::Bits::b1024, 1024 / 8},
        KeyBits{"bits_2048", ckit::pkey::Bits::b2048, 2048 / 8},
        KeyBits{"bits_3072", ckit::pkey::Bits::b3072, 3072 / 8},
        KeyBits{"bits_4096", ckit::pkey::Bits::b4096, 4096 / 8}),
    [](const ::testing::TestParamInfo<KeyBits>& info) {
        return info.param.name;
    });

}  // namespace
