# cryptokit

`cryptokit` 是一个基于 OpenSSL EVP API 的轻量 C++17 密码工具库，提供：

- AES-128/192/256 的 GCM、CBC 和 ECB 模式
- MD5、SHA-1、SHA-224/256/384/512 摘要
- RSA 密钥生成、PEM 导入导出、OAEP 加解密和 PSS 签名验签
- Base64 与十六进制编解码

## 构建

依赖 CMake 3.28+、C++17 编译器和 OpenSSL 3.x。测试构建还需要网络可访问 GoogleTest，或系统已安装 GoogleTest。

```bash
cmake -S . -B build -DCRYPTOKIT_TEST=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

安装并在其他 CMake 项目中使用：

```bash
cmake --install build --prefix /path/to/prefix
```

```cmake
find_package(cryptokit CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE cryptokit::cryptokit)
```

## 示例

```cpp
#include <cryptokit/cipher.hpp>

#include <string>

const std::string key = "0123456789abcdef"; // 16 bytes
const std::string iv = "0123456789ab";       // 12 bytes; 每次加密必须唯一

ckit::Aes128gcm aes(ckit::BytesView(key), ckit::BytesView(iv));
auto encrypted = aes.Encrypt(ckit::BytesView("hello"));
if (!encrypted) {
    // 处理加密失败
}

auto decrypted = aes.Decrypt(*encrypted);
if (!decrypted) {
    // 认证失败或输入无效
}
```

## 安全说明

- 新代码优先使用 AES-GCM；同一密钥下绝不能重复使用 IV。
- ECB 不提供语义安全，CBC 不提供完整性认证，只应在兼容旧协议时使用。
- MD5、SHA-1、RSA-1024 和 RSA PKCS#1 v1.5 加密属于 legacy 能力，不应用于新的安全设计。
- AES 对象只允许同一模式、同一密钥位数之间复制或赋值，不支持跨类型转换。
- `BytesView` 不拥有数据；调用期间其底层缓冲区必须保持有效。
- 本库返回的失败状态不包含完整 OpenSSL error queue，调用方必须检查 `optional`、`bool` 或 `Status` 结果。

本项目尚未经过独立安全审计，不应把 API 封装本身视为完整的协议设计。
