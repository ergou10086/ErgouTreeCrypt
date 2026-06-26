package hbnu.project.ergoutreecrypt.header;

/**
 * 卷头选项标志
 *
 * <p>5 字节布局：{@code [paranoid, useKeyfiles, keyfileOrdered, reedSolomon, padded]}，
 * 每字节取值为 0 或 1。
 *
 * @author ErgouTree
 */
public final class Flags {

    private boolean paranoid;
    private boolean useKeyfiles;
    private boolean keyfileOrdered;
    private boolean reedSolomon;
    private boolean padded;

    public Flags() {
    }

    public Flags(boolean paranoid, boolean useKeyfiles, boolean keyfileOrdered,
                 boolean reedSolomon, boolean padded) {
        this.paranoid = paranoid;
        this.useKeyfiles = useKeyfiles;
        this.keyfileOrdered = keyfileOrdered;
        this.reedSolomon = reedSolomon;
        this.padded = padded;
    }

    // ---- accessors ----

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

    /**
     * 转换为 5 字节数组，对应 Go {@code Flags.ToBytes()}。
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
     * 从字节数组解析 Flags，对应 Go {@code FlagsFromBytes}。
     * 若输入不足 5 字节则返回全 false 的 Flags。
     */
    public static Flags fromBytes(byte[] b) {
        if (b == null || b.length < 5) {
            return new Flags();
        }
        return new Flags(
                b[0] == 1,
                b[1] == 1,
                b[2] == 1,
                b[3] == 1,
                b[4] == 1
        );
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
                && padded == f.padded;
    }

    @Override
    public int hashCode() {
        int result = paranoid ? 1 : 0;
        result = 31 * result + (useKeyfiles ? 1 : 0);
        result = 31 * result + (keyfileOrdered ? 1 : 0);
        result = 31 * result + (reedSolomon ? 1 : 0);
        result = 31 * result + (padded ? 1 : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Flags{paranoid=" + paranoid
                + ", useKeyfiles=" + useKeyfiles
                + ", keyfileOrdered=" + keyfileOrdered
                + ", reedSolomon=" + reedSolomon
                + ", padded=" + padded + '}';
    }
}
