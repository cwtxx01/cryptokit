#include "cryptokit/codec.hpp"

#include <openssl/evp.h>
#include <openssl/types.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "cryptokit/byte_view.hpp"
#include "cryptokit/common.hpp"

namespace ckit::codec {
namespace {
struct CtxDeleter {
    void operator()(EVP_ENCODE_CTX* ctx) { EVP_ENCODE_CTX_free(ctx); }
};

using SmartCtx = std::unique_ptr<EVP_ENCODE_CTX, CtxDeleter>;

SmartCtx MakeSmartCtx() { return SmartCtx(EVP_ENCODE_CTX_new()); }
}  // namespace

namespace detail {
struct Base64Impl {
    explicit Base64Impl(bool new_line, size_t blk_size)
        : ctx_(MakeSmartCtx()), blk_size_(blk_size), mime_(new_line) {
        if (!ctx_) {
            throw std::runtime_error("invalid encode context");
        }
    }

    Base64Impl(const Base64Impl& other) = delete;

    Base64Impl(Base64Impl&& other) noexcept
        : out_(std::move(other.out_)),
          ctx_(std::move(other.ctx_)),
          blk_size_(other.blk_size_),
          mime_(other.mime_) {}

    virtual ~Base64Impl() = default;

    Base64Impl& operator=(const Base64Impl& rhs) = delete;

    Base64Impl& operator=(Base64Impl&& rhs) noexcept {
        if (&rhs != this) {
            out_ = std::move(rhs.out_);
            ctx_ = std::move(rhs.ctx_);
            blk_size_ = rhs.blk_size_;
            mime_ = rhs.mime_;
        }

        return *this;
    }

    virtual Status Update(BytesView stream) = 0;

    virtual std::string Out() = 0;

    std::string out_{};
    SmartCtx ctx_{};
    size_t blk_size_;
    bool mime_;
};

struct EncImpl : public Base64Impl {
    using Base64Impl::Base64Impl;

    Status Update(BytesView stream) override {
        if (stream.Length() >
            static_cast<size_t>(std::numeric_limits<int>::max())) {
            return Status::error;
        }
        auto cur_insert_pos = out_.size();
        const auto required = stream.Length() * 2 + 80;
        out_.resize(out_.size() + std::max(blk_size_, required));
        int len = 0;
        if (!EVP_EncodeUpdate(
                ctx_.get(),
                reinterpret_cast<Byte*>(out_.data() + cur_insert_pos), &len,
                stream.Data(), static_cast<int>(stream.Length()))) {
            out_.resize(cur_insert_pos);
            return Status::error;
        }

        out_.resize(cur_insert_pos + len);

        if (!mime_) {
            for (auto pos = out_.find_first_of('\n', cur_insert_pos);
                 pos != std::string::npos;
                 pos = out_.find_first_of('\n', pos)) {
                out_.erase(pos, 1);
            }
        }

        return Status::good;
    }

    std::string Out() override {
        auto cur_insert_pos = out_.size();
        out_.resize(out_.size() + std::max<size_t>(blk_size_, 80));
        int len = 0;
        EVP_EncodeFinal(ctx_.get(),
                        reinterpret_cast<Byte*>(out_.data() + cur_insert_pos),
                        &len);

        out_.resize(cur_insert_pos + len);

        if (!mime_) {
            if (!out_.empty() && out_.back() == '\n') {
                out_.pop_back();
            }
        }

        std::string res;
        res.swap(out_);
        return res;
    }
};

struct DecImpl : public Base64Impl {
    using Base64Impl::Base64Impl;

    Status Update(BytesView stream) override {
        if (stream.Length() >
            static_cast<size_t>(std::numeric_limits<int>::max())) {
            return Status::error;
        }
        auto cur_insert_pos = out_.size();
        out_.resize(out_.size() + std::max(blk_size_, stream.Length() + 80));
        int len = 0;
        if (EVP_DecodeUpdate(
                ctx_.get(),
                reinterpret_cast<Byte*>(out_.data() + cur_insert_pos), &len,
                stream.Data(), static_cast<int>(stream.Length())) < 0) {
            out_.resize(cur_insert_pos);
            return Status::error;
        }

        out_.resize(cur_insert_pos + len);

        return Status::good;
    }

    std::string Out() override {
        auto cur_insert_pos = out_.size();
        out_.resize(out_.size() + std::max<size_t>(blk_size_, 80));
        int len = 0;
        EVP_DecodeFinal(ctx_.get(),
                        reinterpret_cast<Byte*>(out_.data() + cur_insert_pos),
                        &len);
        out_.resize(cur_insert_pos + len);
        std::string res;
        res.swap(out_);
        return res;
    }
};
}  // namespace detail

Base64::Base64(Crypto codec, bool mime, size_t blk_size) {
    Init(codec, mime, blk_size);
}

Base64::~Base64() {}

std::optional<std::string> Base64::Encode(BytesView plain) {
    if (plain.Length() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    std::string out(1 + (4 * (plain.Length() + 2) / 3), 0);
    auto len = EVP_EncodeBlock(reinterpret_cast<Byte*>(out.data()),
                               plain.Data(), plain.Length());
    out.resize(len);
    return out;
}

std::optional<std::string> Base64::Decode(BytesView b64) {
    if (b64.Empty()) {
        return std::string{};
    }
    if (b64.Length() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    if (b64.Length() % 4 != 0) {
        return std::nullopt;
    }

    size_t padding = 0;
    while (padding < b64.Length() &&
           b64[b64.Length() - padding - 1] == '=') {
        ++padding;
    }
    if (padding > 2) {
        return std::nullopt;
    }
    for (size_t i = 0; i < b64.Length() - padding; ++i) {
        if (b64[i] == '=') {
            return std::nullopt;
        }
    }

    std::string out(b64.Length(), 0);
    auto len = EVP_DecodeBlock(reinterpret_cast<Byte*>(out.data()), b64.Data(),
                               b64.Length());
    if (len < 0) {
        return std::nullopt;
    }

    len -= static_cast<int>(padding);

    out.resize(len);
    return out;
}

Base64& Base64::Init(Crypto codec, bool mime, size_t blk_size) {
    impl_.reset();

    if (codec == Crypto::enc) {
        impl_ = std::make_unique<detail::EncImpl>(mime, blk_size);
    } else {
        impl_ = std::make_unique<detail::DecImpl>(mime, blk_size);
    }

    EVP_EncodeInit(impl_->ctx_.get());
    status_ = Status::good;

    return *this;
}

Base64& Base64::operator<<(BytesView stream) {
    if (status_ == Status::good) {
        status_ = impl_->Update(stream);
    }
    return *this;
}

Base64& Base64::operator>>(std::string& out) {
    out = Out();
    return *this;
}

std::string Base64::Out() {
    if (status_ != Status::good) {
        return {};
    }

    status_ = Status::over;
    return impl_->Out();
}

Status Base64::GetStatus() const noexcept { return status_; }
}  // namespace ckit::codec
