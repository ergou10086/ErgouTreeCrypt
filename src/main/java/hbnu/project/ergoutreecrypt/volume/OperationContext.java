package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.CipherSuite;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.SubkeyReader;
import hbnu.project.ergoutreecrypt.header.VolumeHeader;

/**
 * 加解密操作期可变状态 + 密钥清零，对应 Go OperationContext。
 *
 * <p>使用 try-with-resources 确保密钥材料在结束时被清零。
 *
 * @author ErgouTree
 */
public final class OperationContext implements AutoCloseable {

    // ---- 文件路径 ----
    String inputFile;
    String outputFile;
    String tempFile;

    // ---- Header ----
    VolumeHeader header;

    // ---- 密码学状态 ----
    byte[] key;
    byte[] keyfileKey;
    byte[] keyfileHash;
    byte[] passwordBytes;
    SubkeyReader subkeyReader;
    CipherSuite cipherSuite;

    // ---- 操作标志 ----
    boolean isLegacyV1;
    boolean useKeyfiles;
    boolean padded;
    boolean triedFullRSDecode;

    // ---- 进度 ----
    long total;
    long done;
    ProgressReporter reporter;

    // ---- 构造 ----
    OperationContext() {
    }

    // ---- setKey: 清零旧 key 再赋值（防止旧 backing array 残留） ----
    void setKey(byte[] k) {
        if (key != null && (k == null || k.length == 0 || k != key)) {
            SecureZero.zero(key);
        }
        key = k;
    }

    void setKeyfileKey(byte[] k) {
        if (keyfileKey != null && (k == null || k.length == 0 || k != keyfileKey)) {
            SecureZero.zero(keyfileKey);
        }
        keyfileKey = k;
    }

    void setPasswordBytes(byte[] b) {
        if (passwordBytes != null && (b == null || b.length == 0 || b != passwordBytes)) {
            SecureZero.zero(passwordBytes);
        }
        passwordBytes = b;
    }

    // ---- 进度 ----
    void setStatus(String s) {
        if (reporter != null) {
            reporter.setStatus(s);
            reporter.update();
        }
    }

    void updateProgress(float fraction, String info) {
        if (reporter != null) reporter.setProgress(fraction, info);
    }

    boolean isCancelled() {
        return reporter != null && reporter.isCancelled();
    }

    // ---- 清零 ----
    @Override
    public void close() {
        SecureZero.zero(key);
        SecureZero.zero(keyfileKey);
        SecureZero.zero(keyfileHash);
        SecureZero.zero(passwordBytes);
        key = null;
        keyfileKey = null;
        keyfileHash = null;
        passwordBytes = null;

        if (cipherSuite != null) {
            cipherSuite.close();
            cipherSuite = null;
        }
        if (header != null) {
            SecureZero.zero(header.getKeyHash());
            SecureZero.zero(header.getAuthTag());
            header.setKeyHash(null);
            header.setAuthTag(null);
        }
        subkeyReader = null;
    }
}
