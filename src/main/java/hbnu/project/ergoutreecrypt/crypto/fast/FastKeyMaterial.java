package hbnu.project.ergoutreecrypt.crypto.fast;

import com.google.crypto.tink.StreamingAead;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.KdfProgress;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.exception.CancelledException;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.header.FastHeader;
import hbnu.project.ergoutreecrypt.header.FastHeaderReaderWriter;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.spec.SecretKeySpec;

/** 每文件 FAST 密钥材料；只管理本对象持有的数组，关闭后禁止继续使用。 */
public final class FastKeyMaterial implements AutoCloseable {
    private final byte[] headerKey;
    private final byte[] streamKey;
    private boolean closed;

    /**
     * 接管两个已派生的子密钥数组。
     *
     * @param headerKey 头认证子密钥
     * @param streamKey 流子密钥
     */
    private FastKeyMaterial(byte[] headerKey, byte[] streamKey) {
        this.headerKey = headerKey;
        this.streamKey = streamKey;
    }

    /**
     * 使用固定参数及独立 HKDF 域派生，不修改全局普通模式参数。
     *
     * @param password 原始密码
     * @param argonSalt 16 字节盐值
     * @param hkdfSalt 32 字节盐值
     * @param progress 派生进度及取消回调，可为空
     * @return 须由调用方关闭的密钥材料
     * @throws CryptoException 参数非法、取消或派生失败
     */
    public static FastKeyMaterial derive(
            String password, byte[] argonSalt, byte[] hkdfSalt, KdfProgress progress)
            throws CryptoException {
        if (argonSalt == null
                || argonSalt.length != 16
                || hkdfSalt == null
                || hkdfSalt.length != 32) {
            throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 盐值尺寸错误");
        }
        checkCancelled(progress);
        byte[] encoded = FastKdfPolicy.encodePassword(password),
                master = null,
                header = null,
                stream = null;
        boolean transferred = false;
        try {
            master =
                    Argon2Kdf.deriveKey(
                            encoded,
                            argonSalt,
                            false,
                            FastKdfPolicy.MEMORY_KIB,
                            FastKdfPolicy.PASSES,
                            FastKdfPolicy.LANES,
                            progress);
            checkCancelled(progress);
            header = hkdf(master, hkdfSalt, FastHeaderReaderWriter.HEADER_KEY_INFO);
            stream = hkdf(master, hkdfSalt, FastHeaderReaderWriter.STREAM_KEY_INFO);
            var material = new FastKeyMaterial(header, stream);
            transferred = true;
            return material;
        } catch (IllegalStateException e) {
            checkCancelled(progress);
            throw new CryptoException(ErrorKind.INTERNAL_ERROR, "FAST 密钥派生失败", e);
        } finally {
            SecureZero.zeroAll(encoded, master);
            if (!transferred) SecureZero.zeroAll(header, stream);
        }
    }

    /**
     * 检查 KDF 前后取消；堆内和原生派生期间的回调能力沿用已有实现。
     *
     * @param progress 取消回调
     * @throws CancelledException 已取消
     */
    private static void checkCancelled(KdfProgress progress) throws CancelledException {
        if (Thread.currentThread().isInterrupted() || progress != null && progress.isCancelled())
            throw new CancelledException();
    }

    /**
     * 调用官方 HKDF-SHA256 实现，不复用旧格式的 SHA3 扩展流。
     *
     * @param master Argon2 主密钥
     * @param salt HKDF 盐值
     * @param info 精确 ASCII 域标签
     * @return 32 字节子密钥
     */
    private static byte[] hkdf(byte[] master, byte[] salt, String info) {
        var generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(new HKDFParameters(master, salt, info.getBytes(StandardCharsets.US_ASCII)));
        byte[] output = new byte[32];
        generator.generateBytes(output, 0, output.length);
        return output;
    }

    /**
     * 计算固定头认证标签。
     *
     * @param unsigned 头的前 128 字节
     * @return 32 字节 HMAC
     * @throws GeneralSecurityException 密码库不可用
     */
    public byte[] headerMac(byte[] unsigned) throws GeneralSecurityException {
        ensureOpen();
        if (unsigned == null || unsigned.length != 128)
            throw new GeneralSecurityException("FAST 待认证头尺寸错误");
        var mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(headerKey, "HmacSHA256"));
        mac.update(FastHeaderReaderWriter.HEADER_DOMAIN.getBytes(StandardCharsets.US_ASCII));
        return mac.doFinal(unsigned);
    }

    /**
     * 常量时间验证精确头字节，不能代替完整载荷认证。
     *
     * @param header 结构有效的头
     * @return 标签是否一致
     * @throws GeneralSecurityException 密码库不可用
     */
    public boolean authenticate(FastHeader header) throws GeneralSecurityException {
        byte[] computed = headerMac(header.authenticatedBytes());
        try {
            return MessageDigest.isEqual(computed, header.mac());
        } finally {
            SecureZero.zero(computed);
        }
    }

    /**
     * 创建本文件的官方 RAW 流原语。
     *
     * @return 流实例
     * @throws GeneralSecurityException 初始化失败
     */
    public StreamingAead streamingAead() throws GeneralSecurityException {
        ensureOpen();
        return FastStreamingAeadFactory.create(streamKey);
    }

    /** 检查本对象尚未关闭。 */
    private void ensureOpen() {
        if (closed) throw new IllegalStateException("FAST 密钥材料已关闭");
    }

    /** 尽力清零本对象拥有的子密钥，允许重复关闭。 */
    @Override
    public void close() {
        SecureZero.zeroAll(headerKey, streamKey);
        closed = true;
    }
}
