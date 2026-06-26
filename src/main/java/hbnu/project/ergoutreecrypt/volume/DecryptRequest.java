package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;

import java.util.List;

/**
 * 解密请求 DTO，对应 Go DecryptRequest。
 */
public final class DecryptRequest {
    private String inputFile;
    private String outputFile;
    private String password;
    private List<String> keyfiles;
    private boolean forceDecrypt;
    private boolean verifyFirst;
    private boolean autoUnzip;
    private boolean sameLevel;
    private boolean recombine;
    private boolean deniability;
    private ProgressReporter reporter;
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
