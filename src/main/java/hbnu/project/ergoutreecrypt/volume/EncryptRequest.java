package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.compress.ZstdCompressor;
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
     * 是否添加可否认加密外层（旧版简单包装）。
     */
    private boolean deniability;

    /**
     * 是否启用双卷可否认加密（新：真/伪双密码，一个容器两份内容）。
     */
    private boolean dualDeniability;

    /**
     * 双卷可否认加密的钓鱼文件路径。
     */
    private String decoyFilePath;

    /**
     * 双卷可否认加密的钓鱼密码（伪密码，胁迫时可安全交出）。
     */
    private String fakePassword;

    /**
     * 是否先压缩再加密（单文件内部压缩）。
     */
    private boolean compress;

    /**
     * Zstandard 压缩档位（1–22，仅在 compress=true 时生效）。
     */
    private int compressionLevel = ZstdCompressor.DEFAULT_LEVEL;

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

    /**
     * 覆写 Argon2id 内存参数（KiB），null 表示使用 CryptoConstants 默认值。
     * Android 移动端可通过此字段设置更低的内存参数以适配移动设备。
     */
    private Integer argon2MemoryKib;

    /**
     * 覆写 Argon2id 迭代次数，null 表示使用默认值。
     */
    private Integer argon2Passes;

    /**
     * 覆写 Argon2id 并行线程数，null 表示使用默认值。
     */
    private Integer argon2Threads;

    /**
     * Argon2 密钥派生的进度/取消回调（移动端用于回传进度与响应取消），null 表示无需回调。
     */
    private hbnu.project.ergoutreecrypt.crypto.KdfProgress kdfProgress;

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

    public boolean isDualDeniability() {
        return dualDeniability;
    }

    public void setDualDeniability(boolean d) {
        this.dualDeniability = d;
    }

    public String getDecoyFilePath() {
        return decoyFilePath;
    }

    public void setDecoyFilePath(String f) {
        this.decoyFilePath = f;
    }

    public String getFakePassword() {
        return fakePassword;
    }

    public void setFakePassword(String p) {
        this.fakePassword = p;
    }

    public boolean isCompress() {
        return compress;
    }

    public void setCompress(boolean c) {
        this.compress = c;
    }

    /**
     * 获取 Zstandard 压缩档位。
     *
     * @return 压缩档位（1–22）
     */
    public int getCompressionLevel() {
        return compressionLevel;
    }

    /**
     * 设置 Zstandard 压缩档位。
     *
     * @param level 压缩档位（1–22，越界自动收敛）
     */
    public void setCompressionLevel(int level) {
        this.compressionLevel = ZstdCompressor.clampLevel(level);
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

    /**
     * 获取覆写的 Argon2id 内存参数（KiB），null 表示使用默认值。
     *
     * @return 内存参数（KiB），可能为 null
     */
    public Integer getArgon2MemoryKib() {
        return argon2MemoryKib;
    }

    /**
     * 设置覆写的 Argon2id 内存参数（KiB），null 表示使用默认值。
     *
     * @param argon2MemoryKib 内存参数（KiB），可为 null
     */
    public void setArgon2MemoryKib(Integer argon2MemoryKib) {
        this.argon2MemoryKib = argon2MemoryKib;
    }

    /**
     * 获取覆写的 Argon2id 迭代次数，null 表示使用默认值。
     *
     * @return 迭代次数，可能为 null
     */
    public Integer getArgon2Passes() {
        return argon2Passes;
    }

    /**
     * 设置覆写的 Argon2id 迭代次数，null 表示使用默认值。
     *
     * @param argon2Passes 迭代次数，可为 null
     */
    public void setArgon2Passes(Integer argon2Passes) {
        this.argon2Passes = argon2Passes;
    }

    /**
     * 获取覆写的 Argon2id 并行线程数，null 表示使用默认值。
     *
     * @return 线程数，可能为 null
     */
    public Integer getArgon2Threads() {
        return argon2Threads;
    }

    /**
     * 设置覆写的 Argon2id 并行线程数，null 表示使用默认值。
     *
     * @param argon2Threads 线程数，可为 null
     */
    public void setArgon2Threads(Integer argon2Threads) {
        this.argon2Threads = argon2Threads;
    }

    /**
     * 获取 Argon2 密钥派生的进度/取消回调，null 表示无需回调。
     *
     * @return 进度回调，可能为 null
     */
    public hbnu.project.ergoutreecrypt.crypto.KdfProgress getKdfProgress() {
        return kdfProgress;
    }

    /**
     * 设置 Argon2 密钥派生的进度/取消回调（移动端专用）。
     *
     * @param kdfProgress 进度回调，可为 null
     */
    public void setKdfProgress(hbnu.project.ergoutreecrypt.crypto.KdfProgress kdfProgress) {
        this.kdfProgress = kdfProgress;
    }
}
