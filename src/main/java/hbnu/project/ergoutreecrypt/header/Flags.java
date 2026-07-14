package hbnu.project.ergoutreecrypt.header;

/**
 * 卷头选项标志位。
 *
 * <p>5 字节布局：{@code [paranoid, useKeyfiles, keyfileOrdered, reedSolomon, padded]}，
 * 每字节取值为 0 或 1，供卷头 RS 编码/解码使用。
 *
 * @author ErgouTree
 */
public final class Flags {

    /**
     * 偏执模式（额外 Serpent-CTR 加密层）。
     */
    private boolean paranoid;

    /**
     * 是否使用 keyfile 辅助派生密钥。
     */
    private boolean useKeyfiles;

    /**
     * keyfile 是否有序（顺序拼接 vs XOR）。
     */
    private boolean keyfileOrdered;

    /**
     * 是否启用 Reed-Solomon 纠错编码。
     */
    private boolean reedSolomon;

    /**
     * 载荷是否经过 PKCS#7 填充。
     */
    private boolean padded;

    /**
     * 是否为双卷可否认加密（EGTD）容器。
     */
    private boolean dualDeniable;

    /**
     * 创建全 false 的默认标志位。
     */
    public Flags() {
    }

    /**
     * 按位置创建标志位。
     *
     * @param paranoid       偏执模式
     * @param useKeyfiles    使用 keyfile
     * @param keyfileOrdered keyfile 有序模式
     * @param reedSolomon    启用 RS 纠错
     * @param padded         启用填充
     */
    public Flags(boolean paranoid, boolean useKeyfiles, boolean keyfileOrdered,
                 boolean reedSolomon, boolean padded) {
        this.paranoid = paranoid;
        this.useKeyfiles = useKeyfiles;
        this.keyfileOrdered = keyfileOrdered;
        this.reedSolomon = reedSolomon;
        this.padded = padded;
    }

    public boolean isParanoid() { return paranoid; }
    public void setParanoid(boolean paranoid) { this.paranoid = paranoid; }

    public boolean isUseKeyfiles() { return useKeyfiles; }
    public void setUseKeyfiles(boolean useKeyfiles) { this.useKeyfiles = useKeyfiles; }

    public boolean isKeyfileOrdered() { return keyfileOrdered; }
    public void setKeyfileOrdered(boolean keyfileOrdered) { this.keyfileOrdered = keyfileOrdered; }

    public boolean isReedSolomon() { return reedSolomon; }
    public void setReedSolomon(boolean reedSolomon) { this.reedSolomon = reedSolomon; }

    public boolean isPadded() { return padded; }
    public void setPadded(boolean padded) { this.padded = padded; }

    public boolean isDualDeniable() { return dualDeniable; }
    public void setDualDeniable(boolean dualDeniable) { this.dualDeniable = dualDeniable; }

    /**
     * 转换为 5 字节数组，按位置顺序：paranoid, useKeyfiles, keyfileOrdered, reedSolomon, padded。
     * true → 1, false → 0。供标准卷头序列化使用。
     *
     * @return 5 字节标志位数组
     */
    public byte[] toBytes() {
        byte[] b = new byte[5];
        if (paranoid) {
            b[0] = 1;
        }
        if (useKeyfiles) {
            b[1] = 1;
        }
        if (keyfileOrdered) {
            b[2] = 1;
        }
        if (reedSolomon) {
            b[3] = 1;
        }
        if (padded) {
            b[4] = 1;
        }
        return b;
    }

    /**
     * 转换为 6 字节数组（含 dualDeniable），供双卷可否认加密 MetaBlock 使用。
     * 格式同 {@link #toBytes()}，末尾追加 dualDeniable。
     *
     * @return 6 字节标志位数组
     */
    public byte[] toBytesExtended() {
        byte[] b = new byte[6];
        if (paranoid) {
            b[0] = 1;
        }
        if (useKeyfiles) {
            b[1] = 1;
        }
        if (keyfileOrdered) {
            b[2] = 1;
        }
        if (reedSolomon) {
            b[3] = 1;
        }
        if (padded) {
            b[4] = 1;
        }
        if (dualDeniable) {
            b[5] = 1;
        }
        return b;
    }

    /**
     * 从字节数组解析标志位。兼容 5 字节（旧格式，dualDeniable 默认 false）和 6 字节（新格式）。
     * 若输入为 null 或不足 5 字节则返回全 false 的默认值。
     *
     * @param b 字节数组（至少 5 字节）
     * @return 解析后的 Flags 实例
     */
    public static Flags fromBytes(byte[] b) {
        if (b == null || b.length < 5) {
            return new Flags();
        }
        Flags f = new Flags(
                b[0] == 1,
                b[1] == 1,
                b[2] == 1,
                b[3] == 1,
                b[4] == 1
        );
        if (b.length >= 6) {
            f.dualDeniable = b[5] == 1;
        }
        return f;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Flags f)) {
            return false;
        }
        return paranoid == f.paranoid
                && useKeyfiles == f.useKeyfiles
                && keyfileOrdered == f.keyfileOrdered
                && reedSolomon == f.reedSolomon
                && padded == f.padded
                && dualDeniable == f.dualDeniable;
    }

    @Override
    public int hashCode() {
        int result = paranoid ? 1 : 0;
        result = 31 * result + (useKeyfiles ? 1 : 0);
        result = 31 * result + (keyfileOrdered ? 1 : 0);
        result = 31 * result + (reedSolomon ? 1 : 0);
        result = 31 * result + (padded ? 1 : 0);
        result = 31 * result + (dualDeniable ? 1 : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Flags{paranoid=" + paranoid
                + ", useKeyfiles=" + useKeyfiles
                + ", keyfileOrdered=" + keyfileOrdered
                + ", reedSolomon=" + reedSolomon
                + ", padded=" + padded
                + ", dualDeniable=" + dualDeniable + '}';
    }
}
