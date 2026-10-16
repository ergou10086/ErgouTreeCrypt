package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.volume.ProgressReporter;
import net.lingala.zip4j.crypto.AESDecrypter;
import net.lingala.zip4j.crypto.AESEncrypter;
import net.lingala.zip4j.model.AESExtraDataRecord;
import net.lingala.zip4j.model.enums.AesKeyStrength;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * 使用 zip4j 已有的互通实现，流式处理 WinZip AES。
 */
final class ZipxAes {
    /**
     * 禁止实例化。
     */
    private ZipxAes() {
    }

    /**
     * 使用新随机盐值和十字节认证标签写入 AE-2 AES-256 载荷。
     *
     * @param input 压缩后的明文
     * @param output 加密载荷
     * @param password 按 UTF-8 编码的归档密码
     * @param reporter 取消回调
     * @throws IOException 加密失败
     */
    static void encrypt(Path input, Path output, String password, ProgressReporter reporter) throws IOException {
        char[] chars = password.toCharArray();
        try {
            AESEncrypter aes = new AESEncrypter(chars, AesKeyStrength.KEY_STRENGTH_256, true);
            try (InputStream in = Files.newInputStream(input); OutputStream out = Files.newOutputStream(output)) {
                out.write(aes.getSaltBytes());
                out.write(aes.getDerivedPasswordVerifier());
                byte[] buffer = new byte[65536];
                int count;
                while ((count = in.readNBytes(buffer, 0, buffer.length)) > 0) {
                    checkCancelled(reporter);
                    aes.encryptData(buffer, 0, count);
                    out.write(buffer, 0, count);
                }
                out.write(Arrays.copyOf(aes.getFinalMac(), 10));
            }
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * 暂存的压缩明文交给解码器之前，先认证完整密文。
     *
     * @param input 有界的 ZIP 条目原始输入流
     * @param output 私有暂存的压缩明文
     * @param size 加密条目的完整大小
     * @param strength AES 密钥强度代码，取值一至三
     * @param password UTF-8 编码的归档密码
     * @param reporter 取消回调
     * @throws IOException 密码错误、截断或认证失败
     */
    static void decrypt(InputStream input, Path output, long size, int strength, String password,
                        ProgressReporter reporter) throws IOException {
        AesKeyStrength keyStrength = switch (strength) {
            case 1 -> AesKeyStrength.KEY_STRENGTH_128;
            case 2 -> AesKeyStrength.KEY_STRENGTH_192;
            case 3 -> AesKeyStrength.KEY_STRENGTH_256;
            default -> throw new IOException("Invalid ZIPX AES strength: " + strength);
        };
        int saltSize = strength * 4 + 4;
        long remaining = size - saltSize - 12;
        if (remaining < 0) throw new IOException("Truncated ZIPX AES payload");
        byte[] salt = readExact(input, saltSize);
        byte[] verifier = readExact(input, 2);
        AESExtraDataRecord record = new AESExtraDataRecord();
        record.setAesKeyStrength(keyStrength);
        char[] chars = password.toCharArray();
        try {
            AESDecrypter aes = new AESDecrypter(record, chars, salt, verifier, true);
            try (OutputStream out = Files.newOutputStream(output)) {
                byte[] buffer = new byte[65536];
                while (remaining > 0) {
                    checkCancelled(reporter);
                    int count = (int) Math.min(remaining, buffer.length);
                    if (input.readNBytes(buffer, 0, count) != count)
                        throw new EOFException("Truncated ZIPX ciphertext");
                    aes.decryptData(buffer, 0, count);
                    out.write(buffer, 0, count);
                    remaining -= count;
                }
            }
            byte[] tag = readExact(input, 10);
            if (!MessageDigest.isEqual(tag, Arrays.copyOf(aes.getCalculatedAuthenticationBytes(0), 10))) {
                throw new IOException("ZIPX AES authentication failed: ciphertext corrupted");
            }
            if (input.read() != -1) throw new IOException("Unexpected ZIPX AES trailing data");
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * 读取必须完整存在的定长字段。
     *
     * @param input 源输入流
     * @param size 所需字节数
     * @return 完整字段字节
     * @throws IOException 字段被截断
     */
    private static byte[] readExact(InputStream input, int size) throws IOException {
        byte[] bytes = input.readNBytes(size);
        if (bytes.length != size) throw new EOFException("Truncated ZIPX AES header or tag");
        return bytes;
    }

    /**
     * 在大型 AES 载荷处理期间响应取消。
     *
     * @param reporter 可选取消回调
     * @throws IOException 操作取消
     */
    private static void checkCancelled(ProgressReporter reporter) throws IOException {
        if (Thread.currentThread().isInterrupted() || (reporter != null && reporter.isCancelled())) {
            throw new IOException("ZIPX operation cancelled");
        }
    }
}
