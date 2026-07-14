package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.CipherSuite;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.SubkeyReader;
import hbnu.project.ergoutreecrypt.header.VolumeHeader;

/**
 * 加解密操作期的可变状态容器，负责密钥材料生命周期管理与安全清零。
 *
 * <p>使用 try-with-resources 确保密钥材料在操作结束时被清零。setKey/setKeyfileKey/setPasswordBytes
 * 方法在替换旧值前会先清零旧 backing array，防止密钥残留。
 *
 * @author ErgouTree
 */
public final class OperationContext implements AutoCloseable {

    /**
     * 当前输入文件路径。
     */
    String inputFile;

    /**
     * 输出文件路径。
     */
    String outputFile;

    /**
     * 临时文件路径（recombine / deniability 剥离产物）。
     */
    String tempFile;

    /**
     * 已解码的卷头。
     */
    VolumeHeader header;

    /**
     * 当前派生密钥。
     */
    byte[] key;

    /**
     * keyfile 派生密钥。
     */
    byte[] keyfileKey;

    /**
     * keyfile 哈希（32 字节 SHA3-256）。
     */
    byte[] keyfileHash;

    /**
     * 当前尝试的密码字节（用于候选循环）。
     */
    byte[] passwordBytes;

    /**
     * HKDF 子密钥读取器。
     */
    SubkeyReader subkeyReader;

    /**
     * 加解密套件。
     */
    CipherSuite cipherSuite;

    /**
     * 是否为 v1.x 旧版本卷。
     */
    boolean isLegacyV1;

    /**
     * 是否使用 keyfile。
     */
    boolean useKeyfiles;

    /**
     * 载荷是否经过 PKCS#7 填充。
     */
    boolean padded;

    /**
     * 是否已完成完全 RS 解码重试。
     */
    boolean triedFullRSDecode;

    /**
     * 双卷可否认解密是否已在预处理阶段完成（后续流水线应跳过）。
     */
    boolean dualDeniabilityDone;

    /**
     * 待处理的总字节数。
     */
    long total;

    /**
     * 进度回调接口。
     */
    ProgressReporter reporter;

    OperationContext() {
    }

    /**
     * 设置密钥：先清零旧 key 再赋值，防止旧 backing array 残留。
     */
    void setKey(byte[] k) {
        if (key != null && (k == null || k.length == 0 || k != key)) {
            SecureZero.zero(key);
        }
        key = k;
    }

    /**
     * 设置 keyfile 密钥：先清零旧值再赋值。
     */
    void setKeyfileKey(byte[] k) {
        if (keyfileKey != null && (k == null || k.length == 0 || k != keyfileKey)) {
            SecureZero.zero(keyfileKey);
        }
        keyfileKey = k;
    }

    /**
     * 设置密码字节：先清零旧值再赋值。
     */
    void setPasswordBytes(byte[] b) {
        if (passwordBytes != null && (b == null || b.length == 0 || b != passwordBytes)) {
            SecureZero.zero(passwordBytes);
        }
        passwordBytes = b;
    }

    /**
     * 更新状态文本（通过进度回调，默认 {@link ProgressPhase#CRYPTO}）。
     *
     * @param s 状态文案
     */
    void setStatus(String s) {
        setStatus(s, ProgressPhase.CRYPTO);
    }

    /**
     * 更新状态文本并指定进度阶段。
     *
     * @param s     状态文案
     * @param phase 进度阶段
     */
    void setStatus(String s, ProgressPhase phase) {
        if (reporter != null) {
            reporter.setStatus(s, phase);
            reporter.update();
        }
    }

    /**
     * 更新进度（默认 {@link ProgressPhase#CRYPTO}）。
     *
     * @param fraction 完成比例
     * @param info     附加信息
     */
    void updateProgress(float fraction, String info) {
        updateProgress(fraction, info, ProgressPhase.CRYPTO);
    }

    /**
     * 更新进度并指定阶段。
     *
     * @param fraction 完成比例
     * @param info     附加信息
     * @param phase    进度阶段
     */
    void updateProgress(float fraction, String info, ProgressPhase phase) {
        if (reporter != null) {
            reporter.setProgress(fraction, info, phase);
        }
    }

    /**
     * 是否已请求取消。
     */
    boolean isCancelled() {
        return reporter != null && reporter.isCancelled();
    }

    /**
     * 安全清零所有密钥材料与敏感状态。
     */
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
