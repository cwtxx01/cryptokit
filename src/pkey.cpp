#include "cryptokit/pkey.hpp"

#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/decoder.h>
#include <openssl/pem.h>

#include "cryptokit/common.hpp"

namespace ckit::pkey {
namespace {
using SmartCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

SmartCtx MakeCtx(EVP_PKEY_CTX* ctx) { return SmartCtx(ctx, EVP_PKEY_CTX_free); }

struct Pkey {
    EVP_PKEY* pointer_ = nullptr;

    Pkey() = default;

    ~Pkey() {
        if (pointer_) {
            EVP_PKEY_free(pointer_);
        }
    }
};

}  // namespace

namespace fs = std::filesystem;

struct RsaPrivKey::Impl {
    Pkey pkey_;

    bool IsOk() const noexcept { return pkey_.pointer_ != nullptr; }

    std::optional<ByteVec> DoDecrypt(BytesView&& data, Padding padding,
                                     digest::Mode oaep,
                                     digest::Mode mgf1) const {
        auto ctx = MakeCtx(
            EVP_PKEY_CTX_new_from_pkey(nullptr, pkey_.pointer_, nullptr));

        if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(),
                                         static_cast<int>(padding)) <= 0) {
            return std::nullopt;
        }

        if (padding == Padding::oaep) {
            if (EVP_PKEY_CTX_set_rsa_oaep_md_name(
                    ctx.get(), digest::detail::ToStrView(oaep).data(),
                    nullptr) <= 0 ||
                EVP_PKEY_CTX_set_rsa_mgf1_md_name(
                    ctx.get(), digest::detail::ToStrView(mgf1).data(),
                    nullptr) <= 0) {
                return std::nullopt;
            }
        }

        size_t plain_len = 0;
        if (EVP_PKEY_decrypt(ctx.get(), nullptr, &plain_len, data.Data(),
                             data.Length()) <= 0) {
            return std::nullopt;
        }

        ByteVec buf(plain_len);
        if (EVP_PKEY_decrypt(ctx.get(), buf.data(), &plain_len, data.Data(),
                             data.Length()) <= 0) {
            return std::nullopt;
        }
        buf.resize(plain_len);
        return buf;
    }

    bool DoSign(BytesView data, Padding padding, digest::Mode digest,
                digest::Mode mgf1, int saltlen) const {}

    explicit Impl(Bits bits) {
        auto ctx = MakeCtx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));

        if (ctx && EVP_PKEY_keygen_init(ctx.get()) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(),
                                             static_cast<int>(bits)) > 0 &&
            EVP_PKEY_generate(ctx.get(), &pkey_.pointer_) > 0) {
        }
    }

    explicit Impl(BytesView&& pem) {
        bio::SmartBio bio(BIO_new_mem_buf(pem.Data(), pem.Length()));
        if (bio) {
            pkey_.pointer_ =
                PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        }
    }

    explicit Impl(const fs::path& path) {
        bio::SmartBio bio(BIO_new_file(path.c_str(), "rb"));
        if (bio) {
            pkey_.pointer_ =
                PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        }
    }
};

struct RsaPubKey::Impl {
    Pkey pkey_;

    bool IsOk() const noexcept { return pkey_.pointer_ != nullptr; }

    std::optional<ByteVec> DoEncrypt(BytesView&& data, Padding padding,
                                     digest::Mode oaep,
                                     digest::Mode mgf1) const {
        auto ctx = MakeCtx(
            EVP_PKEY_CTX_new_from_pkey(nullptr, pkey_.pointer_, nullptr));

        if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(),
                                         static_cast<int>(padding)) <= 0) {
            return std::nullopt;
        }

        if (padding == Padding::oaep) {
            if (EVP_PKEY_CTX_set_rsa_oaep_md_name(
                    ctx.get(), digest::detail::ToStrView(oaep).data(),
                    nullptr) <= 0 ||
                EVP_PKEY_CTX_set_rsa_mgf1_md_name(
                    ctx.get(), digest::detail::ToStrView(mgf1).data(),
                    nullptr) <= 0) {
                return std::nullopt;
            }
        }

        size_t enc_len = 0;
        if (EVP_PKEY_encrypt(ctx.get(), nullptr, &enc_len, data.Data(),
                             data.Length()) <= 0) {
            return std::nullopt;
        }

        ByteVec buf(enc_len);
        if (EVP_PKEY_encrypt(ctx.get(), buf.data(), &enc_len, data.Data(),
                             data.Length()) <= 0) {
            return std::nullopt;
        }
        buf.resize(enc_len);
        return buf;
    }

    bool DoVerify(BytesView data, Padding padding, digest::Mode digest,
                  digest::Mode mgf1, int saltlen) const {}

    explicit Impl(BytesView&& pem) {
        bio::SmartBio bio(BIO_new_mem_buf(pem.Data(), pem.Length()));
        if (bio) {
            pkey_.pointer_ =
                PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        }
    }

    explicit Impl(const Pkey& pkey) {
        const int der_len = i2d_PublicKey(pkey.pointer_, nullptr);
        if (der_len <= 0) {
            return;
        }

        ByteVec der(der_len);
        Byte* p = der.data();
        if (i2d_PUBKEY(pkey.pointer_, &p) != der_len) {
            return;
        }
        const Byte* q = der.data();
        pkey_.pointer_ = d2i_PUBKEY(nullptr, &q, der_len);
    }

    explicit Impl(const fs::path& path) {
        bio::SmartBio bio(BIO_new_file(path.c_str(), "rb"));
        if (bio) {
            pkey_.pointer_ =
                PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        }
    }
};

RsaPubKey::RsaPubKey(BytesView pem)
    : impl_(std::make_unique<Impl>(std::move(pem))) {}

RsaPubKey::RsaPubKey(const RsaPrivKey& rsa)
    : impl_(rsa.IsOk() ? std::make_unique<Impl>(rsa.impl_->pkey_) : nullptr) {}

RsaPubKey::RsaPubKey(const std::filesystem::path& path)
    : impl_(fs::exists(path) && fs::is_regular_file(path)
                ? std::make_unique<Impl>(path)
                : nullptr) {}

RsaPubKey::~RsaPubKey() {}

std::optional<std::string> RsaPubKey::Pem() const {
    return IsOk() ? impl_->DoPem() : std::nullopt;
}

std::optional<ByteVec> RsaPubKey::Encrypt(BytesView data, Padding padding,
                                          digest::Mode oaep,
                                          digest::Mode mgf1) const {
    return IsOk() ? impl_->DoEncrypt(std::move(data), padding, oaep, mgf1)
                  : std::nullopt;
}

bool RsaPubKey::Verify(BytesView data, Padding padding, digest::Mode digest,
                       digest::Mode mgf1, int saltlen) const {
    return IsOk() ? impl_->DoVerify(std::move(data), padding, digest, mgf1,
                                    saltlen)
                  : false;
}

bool RsaPubKey::IsOk() const noexcept { return impl_ && impl_->IsOk(); }

RsaPrivKey::RsaPrivKey(BytesView pem)
    : impl_(std::make_unique<Impl>(std::move(pem))) {}

RsaPrivKey::RsaPrivKey(Bits bits) : impl_(std::make_unique<Impl>(bits)) {}

RsaPrivKey::RsaPrivKey(const std::filesystem::path& path)
    : impl_(fs::exists(path) && fs::is_regular_file(path)
                ? std::make_unique<Impl>(path)
                : nullptr) {}

RsaPrivKey::~RsaPrivKey() {}

std::optional<std::string> RsaPrivKey::Pem() const {
    return IsOk() ? impl_->DoPem() : std::nullopt;
}

std::optional<ByteVec> RsaPrivKey::Decrypt(BytesView data, Padding padding,
                                           digest::Mode oaep,
                                           digest::Mode mgf1) const {
    return IsOk() ? impl_->DoDecrypt(std::move(data), padding, oaep, mgf1)
                  : std::nullopt;
}

bool RsaPrivKey::Sign(BytesView data, Padding padding, digest::Mode digest,
                      digest::Mode mgf1, int saltlen) const {
    return IsOk()
               ? impl_->DoSign(std::move(data), padding, digest, mgf1, saltlen)
               : false;
}

bool RsaPrivKey::IsOk() const noexcept { return impl_ && impl_->IsOk(); }
}  // namespace ckit::pkey