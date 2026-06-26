package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;

import java.util.List;

/**
 * 完整性校验请求 DTO。
 *
 * <p>与 {@link DecryptRequest} 对应，但只包含校验所需的字段，不含输出路径、
 * 解压等解密专属选项。校验操作不产生任何明文输出。
 *
 * @author ErgouTree
 */
public final class VerifyRequest {
    private String inputFile;
    private String password;
    private List<String> keyfiles;
    private boolean forceDecrypt;
    private boolean recombine;
    private boolean deniability;
    private ProgressReporter reporter;
    private RsCodecs rsCodecs;

    /**
     * 待校验的加密文件路径（.ergou / .pcv 或分卷碎片目录）。
     */
    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String f) {
        this.inputFile = f;
    }

    /**
     * 解密密码（可为空字符串表示无密码模式）。
     */
    public String getPassword() {
        return password;
    }

    public void setPassword(String p) {
        this.password = p;
    }

    /**
     * 密钥文件路径列表，可为 {@code null} 或空。
     */
    public List<String> getKeyfiles() {
        return keyfiles;
    }

    public void setKeyfiles(List<String> kf) {
        this.keyfiles = kf;
    }

    /**
     * 即使校验失败也继续尝试（跳过 header auth / MAC 错误）。
     */
    public boolean isForceDecrypt() {
        return forceDecrypt;
    }

    public void setForceDecrypt(boolean f) {
        this.forceDecrypt = f;
    }

    /**
     * 输入是否为分卷碎片，需要先合并。
     */
    public boolean isRecombine() {
        return recombine;
    }

    public void setRecombine(boolean r) {
        this.recombine = r;
    }

    /**
     * 是否需要先剥离可否认加密外层。
     */
    public boolean isDeniability() {
        return deniability;
    }

    public void setDeniability(boolean d) {
        this.deniability = d;
    }

    /**
     * 进度 / 取消回调。
     */
    public ProgressReporter getReporter() {
        return reporter;
    }

    public void setReporter(ProgressReporter r) {
        this.reporter = r;
    }

    /**
     * Reed-Solomon 编解码器实例。
     */
    public RsCodecs getRsCodecs() {
        return rsCodecs;
    }

    public void setRsCodecs(RsCodecs rs) {
        this.rsCodecs = rs;
    }
}
