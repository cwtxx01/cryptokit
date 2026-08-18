#include "cryptokit/codec.hpp"

#include <gtest/gtest.h>

#include "cryptokit/common.hpp"

TEST(Base64Test, encode_decode) {
    std::string plain = "abcdefg";
    auto enc_text = ckit::Base64::Encode(plain);
    EXPECT_TRUE(enc_text.has_value());
    auto dec_text = ckit::Base64::Decode(enc_text.value());
    EXPECT_TRUE(dec_text.has_value());
    EXPECT_EQ(dec_text.value(), plain);
}

TEST(Base64Test, encode_decode_stream) {
    std::string full_str = "0123456789abcdefghigklmnopqrstuvwxyz";

    auto enc_base64 = ckit::Base64(ckit::Crypto::enc);
    EXPECT_EQ(enc_base64.GetStatus(), ckit::codec::Status::good);
    EXPECT_EQ((enc_base64 << full_str).GetStatus(), ckit::codec::Status::good);
    auto enc_text = enc_base64.Out();
    EXPECT_EQ(enc_base64.GetStatus(), ckit::codec::Status::over);

    auto dec_base64 = ckit::Base64(ckit::Crypto::dec);
    EXPECT_EQ(dec_base64.GetStatus(), ckit::codec::Status::good);
    EXPECT_EQ((dec_base64 << enc_text).GetStatus(), ckit::codec::Status::good);
    auto dec_text = dec_base64.Out();
    EXPECT_EQ(dec_base64.GetStatus(), ckit::codec::Status::over);

    EXPECT_EQ(dec_text, full_str);
}

TEST(Base64Test, encode_decode_stream_long) {
    std::string full_str =
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz";

    auto enc_base64 = ckit::Base64(ckit::Crypto::enc);
    EXPECT_EQ(enc_base64.GetStatus(), ckit::codec::Status::good);

    for (size_t l = 0, r = 10 > full_str.size() ? full_str.size() : 10;
         l < full_str.size();) {
        EXPECT_EQ((enc_base64 << full_str.substr(l, r - l)).GetStatus(),
                  ckit::codec::Status::good);
        l = r;
        r += 10;
        if (r > full_str.size()) {
            r = full_str.size();
        }
    }
    auto enc_text = enc_base64.Out();
    EXPECT_EQ(enc_base64.GetStatus(), ckit::codec::Status::over);

    auto dec_base64 = ckit::Base64(ckit::Crypto::dec);
    EXPECT_EQ(dec_base64.GetStatus(), ckit::codec::Status::good);
    for (size_t l = 0, r = 10 > enc_text.size() ? enc_text.size() : 10;
         l < enc_text.size();) {
        EXPECT_EQ((dec_base64 << enc_text.substr(l, r - l)).GetStatus(),
                  ckit::codec::Status::good);
        l = r;
        r += 10;
        if (r > enc_text.size()) {
            r = enc_text.size();
        }
    }
    auto dec_text = dec_base64.Out();
    EXPECT_EQ(dec_base64.GetStatus(), ckit::codec::Status::over);

    EXPECT_EQ(dec_text, full_str);
}

TEST(Base64Test, encode_decode_stream_mime) {
    std::string full_str =
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz"
        "0123456789abcdefghigklmnopqrstuvwxyz";

    auto enc_base64 = ckit::Base64(ckit::Crypto::enc, true);
    EXPECT_EQ(enc_base64.GetStatus(), ckit::codec::Status::good);

    for (size_t l = 0, r = 10 > full_str.size() ? full_str.size() : 10;
         l < full_str.size();) {
        EXPECT_EQ((enc_base64 << full_str.substr(l, r - l)).GetStatus(),
                  ckit::codec::Status::good);
        l = r;
        r += 10;
        if (r > full_str.size()) {
            r = full_str.size();
        }
    }
    auto enc_text = enc_base64.Out();
    EXPECT_EQ(enc_base64.GetStatus(), ckit::codec::Status::over);

    auto dec_base64 = ckit::Base64(ckit::Crypto::dec);
    EXPECT_EQ(dec_base64.GetStatus(), ckit::codec::Status::good);
    for (size_t l = 0, r = 10 > enc_text.size() ? enc_text.size() : 10;
         l < enc_text.size();) {
        EXPECT_EQ((dec_base64 << enc_text.substr(l, r - l)).GetStatus(),
                  ckit::codec::Status::good);
        l = r;
        r += 10;
        if (r > enc_text.size()) {
            r = enc_text.size();
        }
    }
    auto dec_text = dec_base64.Out();
    EXPECT_EQ(dec_base64.GetStatus(), ckit::codec::Status::over);

    EXPECT_EQ(dec_text, full_str);
}

TEST(Base64Test, stream_handles_input_larger_than_configured_block) {
    const std::string plain(8192, 'x');
    ckit::Base64 encoder(ckit::Crypto::enc, false, 8);
    const auto encoded = (encoder << plain).Out();
    ASSERT_EQ(encoder.GetStatus(), ckit::codec::Status::over);

    ckit::Base64 decoder(ckit::Crypto::dec, false, 8);
    EXPECT_EQ((decoder << encoded).Out(), plain);
}

TEST(Base64Test, supports_empty_input_and_reinitialization) {
    const auto decoded = ckit::Base64::Decode(std::string{});
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->empty());

    ckit::Base64 codec(ckit::Crypto::enc);
    EXPECT_EQ((codec << std::string("first")).Out(), "Zmlyc3Q=");
    codec.Init(ckit::Crypto::enc);
    EXPECT_EQ(codec.GetStatus(), ckit::codec::Status::good);
    EXPECT_EQ((codec << std::string("second")).Out(), "c2Vjb25k");
}

TEST(HexTest, non_delim_with_upper) {
    std::string plain = "0123456789abcdefghigklmnopqrstuvwxyz";
    ckit::Hex hex(ckit::Character::upper);
    auto enc_text = hex.Encode(plain);
    for (auto ch : enc_text) {
        if (ch < '0' || ch > '9') {
            EXPECT_GE(ch, 'A');
            EXPECT_LE(ch, 'F');
        }
    }
    auto dec_text = hex.Decode(enc_text);
    EXPECT_EQ(plain, dec_text);
}

TEST(HexTest, non_delim_with_lower) {
    std::string plain = "0123456789abcdefghigklmnopqrstuvwxyz";
    ckit::Hex hex(ckit::Character::lower);
    auto enc_text = hex.Encode(plain);
    for (auto ch : enc_text) {
        if (ch < '0' || ch > '9') {
            EXPECT_GE(ch, 'a');
            EXPECT_LE(ch, 'f');
        }
    }
    auto dec_text = hex.Decode(enc_text);
    EXPECT_EQ(plain, dec_text);
}

TEST(HexTest, non_delim_with_prefix) {
    std::string plain = "0123456789abcdefghigklmnopqrstuvwxyz";
    ckit::Hex hex("0x");
    auto enc_text = hex.Encode(plain);
    EXPECT_EQ(enc_text.find("0x"), 0);
    auto dec_text = hex.Decode(enc_text);
    EXPECT_EQ(plain, dec_text);
}

constexpr char COLON = ':';

TEST(HexTest, delim_with_upper) {
    std::string plain = "\x01\xab\xcd\xef";
    ckit::Hex<COLON> hex(ckit::Character::upper);
    auto enc_text = hex.Encode(plain);
    EXPECT_EQ(enc_text.size(), 11);
    EXPECT_EQ(enc_text[0], '0');
    EXPECT_EQ(enc_text[1], '1');
    EXPECT_EQ(enc_text[2], COLON);
    EXPECT_EQ(enc_text[3], 'A');
    EXPECT_EQ(enc_text[4], 'B');
    EXPECT_EQ(enc_text[5], COLON);
    EXPECT_EQ(enc_text[6], 'C');
    EXPECT_EQ(enc_text[7], 'D');
    EXPECT_EQ(enc_text[8], COLON);
    EXPECT_EQ(enc_text[9], 'E');
    EXPECT_EQ(enc_text[10], 'F');
    auto dec_text = hex.Decode(enc_text);
    EXPECT_EQ(plain, dec_text);
}

TEST(HexTest, delim_with_lower) {
    std::string plain = "\x01\xab\xcd\xef";
    ckit::Hex<COLON> hex(ckit::Character::lower);
    auto enc_text = hex.Encode(plain);
    EXPECT_EQ(enc_text.size(), 11);
    EXPECT_EQ(enc_text[0], '0');
    EXPECT_EQ(enc_text[1], '1');
    EXPECT_EQ(enc_text[2], COLON);
    EXPECT_EQ(enc_text[3], 'a');
    EXPECT_EQ(enc_text[4], 'b');
    EXPECT_EQ(enc_text[5], COLON);
    EXPECT_EQ(enc_text[6], 'c');
    EXPECT_EQ(enc_text[7], 'd');
    EXPECT_EQ(enc_text[8], COLON);
    EXPECT_EQ(enc_text[9], 'e');
    EXPECT_EQ(enc_text[10], 'f');
    auto dec_text = hex.Decode(enc_text);
    EXPECT_EQ(plain, dec_text);
}

TEST(HexTest, delim_with_prefix) {
    std::string plain = "\x01\xab\xcd\xef";
    ckit::Hex<COLON> hex("0x");
    auto enc_text = hex.Encode(plain);
    EXPECT_EQ(enc_text.find("0x"), 0);
    EXPECT_EQ(enc_text.size(), 13);
    EXPECT_EQ(enc_text[0], '0');
    EXPECT_EQ(enc_text[1], 'x');
    EXPECT_EQ(enc_text[2], '0');
    EXPECT_EQ(enc_text[3], '1');
    EXPECT_EQ(enc_text[4], COLON);
    EXPECT_EQ(enc_text[5], 'A');
    EXPECT_EQ(enc_text[6], 'B');
    EXPECT_EQ(enc_text[7], COLON);
    EXPECT_EQ(enc_text[8], 'C');
    EXPECT_EQ(enc_text[9], 'D');
    EXPECT_EQ(enc_text[10], COLON);
    EXPECT_EQ(enc_text[11], 'E');
    EXPECT_EQ(enc_text[12], 'F');
    auto dec_text = hex.Decode(enc_text);
    EXPECT_EQ(plain, dec_text);
}

TEST(HexTest, handles_empty_and_rejects_malformed_input) {
    ckit::Hex<COLON> hex;
    EXPECT_TRUE(hex.Encode(ckit::BytesView{}).empty());
    EXPECT_TRUE(hex.Decode(std::string("A")).empty());
    EXPECT_TRUE(hex.Decode(std::string("AA-BB")).empty());
    EXPECT_TRUE(hex.Decode(std::string("AA:")).empty());
    EXPECT_EQ(hex.Decode(std::string("AA:BB")), std::string("\xAA\xBB", 2));
}
