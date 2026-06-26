package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;

import java.util.List;

/**
 * 加密请求 DTO，对应 Go EncryptRequest。
 */
public final class EncryptRequest {

    private String inputFile;

    private List<String> inputFiles;

    private String outputFile;

    // 可为 null/empty
    private String password;

    private List<String> keyfiles;

    private boolean keyfileOrdered;

    private String comments = "";

    private boolean paranoid;

    private boolean reedSolomon;

    private boolean deniability;

    private boolean compress;

    private boolean split;

    private int chunkSize;

    // 归档（加密后压缩）
    private String archiveFormat;   // null 或 "ZIP"/"GZ"/"TAR_GZ"
    private String archivePassword; // 可为 null

    // add more fields as needed for split units later
    private ProgressReporter reporter;

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
