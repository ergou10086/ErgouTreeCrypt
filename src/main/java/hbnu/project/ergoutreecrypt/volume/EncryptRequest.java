package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;

import java.util.List;

/**
 * 加密请求 DTO，聚合加密所需全部参数。
 *
 * @author ErgouTree
 */
public final class EncryptRequest {

    /**
     * 待加密的输入文件路径（单文件模式）。
     */
    private String inputFile;

    /**
     * 待加密的多个输入文件路径（多文件模式）。
     */
    private List<String> inputFiles;

    /**
     * 加密输出文件路径。
     */
    private String outputFile;

    /**
     * 加密密码（可为 null 或空表示无密码模式）。
     */
    private String password;

    /**
     * 密钥文件路径列表，可为 null 或空。
     */
    private List<String> keyfiles;

    /**
     * 密钥文件是否有序（顺序拼接哈希 vs XOR）。
     */
    private boolean keyfileOrdered;

    /**
     * 注释（明文存储于 header，不会被加密）。
     */
    private String comments = "";

    /**
     * 是否使用偏执模式（Argon2 8 passes + Serpent-CTR + HMAC-SHA3）。
     */
    private boolean paranoid;

    /**
     * 是否启用 Reed-Solomon 纠错编码。
     */
    private boolean reedSolomon;

    /**
     * 是否添加可否认加密外层。
     */
    private boolean deniability;

    /**
     * 是否先压缩再加密（单文件内部压缩）。
     */
    private boolean compress;

    /**
     * 是否将输出切分为固定大小的分卷碎片。
     */
    private boolean split;

    /**
     * 每分卷的最大字节数（单位 MiB）。
     */
    private int chunkSize;

    /**
     * 加密后压缩的归档格式，null 表示不压缩。
     */
    private String archiveFormat;

    /**
     * 归档加密密码，可为 null。
     */
    private String archivePassword;

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

    public List<String> getInputFiles() {
        return inputFiles;
    }

    public void setInputFiles(List<String> fs) {
        this.inputFiles = fs;
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

    public boolean isKeyfileOrdered() {
        return keyfileOrdered;
    }

    public void setKeyfileOrdered(boolean o) {
        this.keyfileOrdered = o;
    }

    public String getComments() {
        return comments;
    }

    public void setComments(String c) {
        this.comments = c;
    }

    public boolean isParanoid() {
        return paranoid;
    }

    public void setParanoid(boolean p) {
        this.paranoid = p;
    }

    public boolean isReedSolomon() {
        return reedSolomon;
    }

    public void setReedSolomon(boolean rs) {
        this.reedSolomon = rs;
    }

    public boolean isDeniability() {
        return deniability;
    }

    public void setDeniability(boolean d) {
        this.deniability = d;
    }

    public boolean isCompress() {
        return compress;
    }

    public void setCompress(boolean c) {
        this.compress = c;
    }

    public boolean isSplit() {
        return split;
    }

    public void setSplit(boolean s) {
        this.split = s;
    }

    public int getChunkSize() {
        return chunkSize;
    }

    public void setChunkSize(int s) {
        this.chunkSize = s;
    }

    public String getArchiveFormat() {
        return archiveFormat;
    }

    public void setArchiveFormat(String f) {
        this.archiveFormat = f;
    }

    public String getArchivePassword() {
        return archivePassword;
    }

    public void setArchivePassword(String p) {
        this.archivePassword = p;
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
