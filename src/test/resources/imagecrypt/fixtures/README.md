# imagecrypt 测试夹具

EGTC-IMG v1 的跨端测试素材。核心按"完整原文件字节"处理输入，因此夹具必须包含**真实容器结构**
（真实 IHDR、真实 DQT/SOF、真实 RIFF 布局），而不是手写的假头部——手写样本无法暴露探测与
往返逻辑对真实标记序列的依赖。

## 文件清单

| 文件 | 格式 | 尺寸 | 说明 |
|---|---|---|---|
| `sample.png` | PNG（color type 6, RGBA） | 1280 × 720 | 真实素材，用于验证 IHDR 解析与有界读取 |
| `sample.jpg` | JPEG/JFIF | 见探测结果 | 真实素材，用于验证 marker 扫描 |
| `sample.webp` | WebP（VP8X 扩展格式，含 alpha） | 1920 × 1080 | 真实素材。JDK 无 WebP 编码器，只能以文件形式提供 |

其余格式（GIF、BMP）由测试代码在内存中合成最小合法结构，见
`ImageCryptTestSupport.minimalGif` / `minimalBmp`。

## 来源与许可

以上文件由项目作者提供的自有测试素材中选取，不含第三方版权内容。

## 完整性

```
SHA-256(sample.png)  = 36c0ceba5003090f1a39b26fa9fdd5dd2a006d0d65e400d517b910e4541589d0
SHA-256(sample.jpg)  = de433c2d9d1474a30131f8013d2aeb28bea7886b44d514b6449ac8de568305ae
SHA-256(sample.webp) = 02b6ee3199b4c0486ea0a93422accbb92fb8aab2f0ddde07a4c7032b71378213
```

这些哈希是**夹具身份**，不是协议黄金向量。协议层的冻结值（协议头、密钥、密文、认证标签）
见 `ImageCryptGoldenVectorTest`。

## 注意

- 夹具哈希与"加密产物哈希"是两回事：外部工具重新保存过的夹具会改变哈希，但协议往返仍然成立；
- 测试断言的是**往返后恢复文件的 SHA-256 等于输入文件 SHA-256**，而不是夹具哈希本身；
- 更换任何一个夹具，都必须同步更新本文件中的哈希。
