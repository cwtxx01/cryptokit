#include "cryptokit/codec.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string>

#include "cryptokit/common.hpp"

namespace {
std::string MakeBinaryData(size_t size) {
    std::string data(size, '\0');
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<char>((i * 131 + 17) & 0xff);
    }
    return data;
}
}  // namespace

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

TEST(Base64Test, round_trips_binary_data_at_encoding_boundaries) {
    constexpr std::array<size_t, 16> sizes{
        0, 1, 2, 3, 4, 47, 48, 49, 63, 64, 65, 1023, 1024, 1025, 4095, 4096};

    for (const auto size : sizes) {
        SCOPED_TRACE(size);
        const auto plain = MakeBinaryData(size);
        const auto encoded = ckit::Base64::Encode(plain);
        ASSERT_TRUE(encoded.has_value());
        const auto decoded = ckit::Base64::Decode(*encoded);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(*decoded, plain);
    }
}

TEST(Base64Test, stream_round_trips_large_binary_input_in_one_update) {
    const auto plain = MakeBinaryData(1024 * 1024 + 3);

    ckit::Base64 encoder(ckit::Crypto::enc, false, 1);
    const auto encoded = (encoder << plain).Out();
    ASSERT_EQ(encoder.GetStatus(), ckit::codec::Status::over);

    ckit::Base64 decoder(ckit::Crypto::dec, false, 1);
    const auto decoded = (decoder << encoded).Out();
    EXPECT_EQ(decoder.GetStatus(), ckit::codec::Status::over);
    EXPECT_EQ(decoded, plain);
}

TEST(Base64Test, stream_round_trips_when_updated_one_byte_at_a_time) {
    const auto plain = MakeBinaryData(257);
    ckit::Base64 encoder(ckit::Crypto::enc, false, 1);
    for (const char byte : plain) {
        encoder << ckit::BytesView(&byte, 1);
        ASSERT_EQ(encoder.GetStatus(), ckit::codec::Status::good);
    }
    const auto encoded = encoder.Out();

    ckit::Base64 decoder(ckit::Crypto::dec, false, 1);
    for (const char byte : encoded) {
        decoder << ckit::BytesView(&byte, 1);
        ASSERT_EQ(decoder.GetStatus(), ckit::codec::Status::good);
    }
    EXPECT_EQ(decoder.Out(), plain);
}

TEST(Base64Test, rejects_malformed_static_and_stream_input) {
    for (const std::string invalid :
         {"!", "abc", "abc!", "====", "A===", "Z=m9", "Zm9v*"}) {
        SCOPED_TRACE(invalid);
        EXPECT_FALSE(ckit::Base64::Decode(invalid).has_value());
    }

    ckit::Base64 decoder(ckit::Crypto::dec);
    decoder << std::string("Zm9v*===");
    EXPECT_EQ(decoder.GetStatus(), ckit::codec::Status::error);
    EXPECT_TRUE(decoder.Out().empty());

    ckit::Base64 incomplete_decoder(ckit::Crypto::dec);
    incomplete_decoder << std::string("Zg");
    EXPECT_EQ(incomplete_decoder.GetStatus(), ckit::codec::Status::good);
    EXPECT_TRUE(incomplete_decoder.Out().empty());
    EXPECT_EQ(incomplete_decoder.GetStatus(), ckit::codec::Status::error);
}

TEST(Base64Test, finalization_is_idempotent_and_ignores_late_input) {
    ckit::Base64 encoder(ckit::Crypto::enc);
    encoder << std::string("first");
    EXPECT_EQ(encoder.Out(), "Zmlyc3Q=");
    EXPECT_EQ(encoder.GetStatus(), ckit::codec::Status::over);

    encoder << std::string("ignored");
    EXPECT_EQ(encoder.GetStatus(), ckit::codec::Status::over);
    EXPECT_TRUE(encoder.Out().empty());
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

TEST(HexTest, round_trips_every_byte_value) {
    std::string plain(256, '\0');
    for (size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<char>(i);
    }

    ckit::Hex<> compact(ckit::Character::lower, "0x");
    EXPECT_EQ(compact.Decode(compact.Encode(plain)), plain);

    ckit::Hex<COLON> delimited(ckit::Character::upper, "hex:");
    EXPECT_EQ(delimited.Decode(delimited.Encode(plain)), plain);
}

TEST(HexTest, validates_prefix_and_mixed_case_input) {
    ckit::Hex<> prefixed("0x");
    EXPECT_TRUE(prefixed.Decode(std::string{}).empty());
    EXPECT_TRUE(prefixed.Decode(std::string("0")).empty());
    EXPECT_TRUE(prefixed.Decode(std::string("1a2b")).empty());
    EXPECT_EQ(prefixed.Decode(std::string("0xAaFf")),
              std::string("\xAA\xFF", 2));
}
