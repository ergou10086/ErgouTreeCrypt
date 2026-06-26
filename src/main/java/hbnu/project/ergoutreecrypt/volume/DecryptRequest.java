package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;

import java.util.List;

/**
 * 解密请求 DTO，聚合解密所需全部参数。
 *
 * @author ErgouTree
 */
public final class DecryptRequest {

    /**
     * 待解密的输入文件路径（.ergou / .pcv / 分卷碎片）。
     */
    private String inputFile;

    /**
     * 解密输出文件路径。
     */
    private String outputFile;

    /**
     * 解密密码（可为空字符串表示无密码模式）。
     */
    private String password;

    /**
     * 密钥文件路径列表，可为 null 或空。
     */
    private List<String> keyfiles;

    /**
     * 即使校验失败也强制解密（跳过 header auth / MAC 错误）。
     */
    private boolean forceDecrypt;

    /**
     * 解密前先校验完整性（不解密输出）。
     */
    private boolean verifyFirst;

    /**
     * 解密后自动解压归档。
     */
    private boolean autoUnzip;

    /**
     * 是否在同级目录输出。
     */
    private boolean sameLevel;

    /**
     * 输入是否为分卷碎片，需先合并。
     */
    private boolean recombine;

    /**
     * 是否需要先剥离可否认加密外层。
     */
    private boolean deniability;

    /**
     * 进度与取消回调。
     */
    private ProgressReporter reporter;

    /**
     * Reed-Solomon 编解码器实例。
     */
    private RsCodecs rsCodecs;

    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String f) {
        this.inputFile = f;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String f) {
        this.outputFile = f;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String p) {
        this.password = p;
    }

    public List<String> getKeyfiles() {
        return keyfiles;
    }

    public void setKeyfiles(List<String> kf) {
        this.keyfiles = kf;
    }

    public boolean isForceDecrypt() {
        return forceDecrypt;
    }

    public void setForceDecrypt(boolean f) {
        this.forceDecrypt = f;
    }

    public boolean isVerifyFirst() {
        return verifyFirst;
    }

    public void setVerifyFirst(boolean v) {
        this.verifyFirst = v;
    }

    public boolean isAutoUnzip() {
        return autoUnzip;
    }

    public void setAutoUnzip(boolean a) {
        this.autoUnzip = a;
    }

    public boolean isSameLevel() {
        return sameLevel;
    }

    public void setSameLevel(boolean s) {
        this.sameLevel = s;
    }

    public boolean isRecombine() {
        return recombine;
    }

    public void setRecombine(boolean r) {
        this.recombine = r;
    }

    public boolean isDeniability() {
        return deniability;
    }

    public void setDeniability(boolean d) {
        this.deniability = d;
    }

    public ProgressReporter getReporter() {
        return reporter;
    }

    public void setReporter(ProgressReporter r) {
        this.reporter = r;
    }

    public RsCodecs getRsCodecs() {
        return rsCodecs;
    }

    public void setRsCodecs(RsCodecs rs) {
        this.rsCodecs = rs;
    }
}
