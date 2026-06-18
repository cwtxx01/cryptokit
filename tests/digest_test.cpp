#include "cryptokit/digest.hpp"

#include <gtest/gtest.h>

#include "cryptokit/codec.hpp"
#include "cryptokit/common.hpp"

std::string plain = "!@#$%^(0123456789abcdefghigklmnopqrstuvwxyz,.;'[]?)";

std::string md5_check = "4868384f6743434387d2272b288b0352";

std::string sha1_check = "26b3f5a7376baac2749671bd44a54786b619e16f";

std::string sha224_check =
    "16b25486335f4658451851b01c7e48c4"
    "0e5682d261d5272eb46e9f9f";

std::string sha256_check =
    "c724a97435dfa362086d0249c2af42fd"
    "d62c2b0482c0bb7192f202857663fb60";

std::string sha384_check =
    "4b6ed63adb21977b6eff74eb1de5c18a"
    "b0a0b72f36b796c82998d495d23ed99c"
    "a7844a4172b10d5141f20714e7a1b323";

std::string sha512_check =
    "028ef4a7ad80b16ad47447da08b88a15"
    "5d4ad39550872c4cff5c88615d64186d"
    "5653f114d34404e9316bc482cd7b8908"
    "f2e4e58f983c9562509de3ef72966acb";

TEST(Md5Test, basic) {
    auto result = ckit::Md5::Once(plain);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), md5_check);
}

TEST(Md5Test, stream) {
    ckit::Md5 md5;
    md5 << plain.substr(0, plain.size() / 2) << plain.substr(plain.size() / 2);
    auto result = md5.Out();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), md5_check);
}

TEST(Sha1Test, basic) {
    auto result = ckit::Sha1::Once(plain);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha1_check);
}

TEST(Sha1Test, stream) {
    ckit::Sha1 sha1;
    sha1 << plain.substr(0, plain.size() / 2) << plain.substr(plain.size() / 2);
    auto result = sha1.Out();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha1_check);
}

TEST(Sha224, basic) {
    auto result = ckit::Sha224::Once(plain);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha224_check);
}

TEST(Sha224Test, stream) {
    ckit::Sha224 sha224;
    sha224 << plain.substr(0, plain.size() / 2)
           << plain.substr(plain.size() / 2);
    auto result = sha224.Out();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha224_check);
}

TEST(Sha256Test, basic) {
    auto result = ckit::Sha256::Once(plain);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha256_check);
}

TEST(Sha256Test, stream) {
    ckit::Sha256 sha256;
    sha256 << plain.substr(0, plain.size() / 2)
           << plain.substr(plain.size() / 2);
    auto result = sha256.Out();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha256_check);
}

TEST(Sha384Test, basic) {
    auto result = ckit::Sha384::Once(plain);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha384_check);
}

TEST(Sha384Test, stream) {
    ckit::Sha384 sha384;
    sha384 << plain.substr(0, plain.size() / 2)
           << plain.substr(plain.size() / 2);
    auto result = sha384.Out();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha384_check);
}

TEST(Sha512Test, basic) {
    auto result = ckit::Sha512::Once(plain);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha512_check);
}

TEST(Sha512Test, stream) {
    ckit::Sha512 sha512;
    sha512 << plain.substr(0, plain.size() / 2)
           << plain.substr(plain.size() / 2);
    auto result = sha512.Out();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(ckit::Hex{ckit::Character::lower}.Encode(result), sha512_check);
}