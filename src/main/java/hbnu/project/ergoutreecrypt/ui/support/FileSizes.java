package hbnu.project.ergoutreecrypt.ui.support;

/**
 * 文件大小格式化工具。
 *
 * @author ErgouTree
 */
public final class FileSizes {

    private static final String[] UNITS = {"B", "KiB", "MiB", "GiB", "TiB"};

    private FileSizes() {
    }

    /**
     * 将字节数格式化为人类可读字符串（二进制单位）。
     */
    public static String human(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < UNITS.length - 1) {
            value /= 1024;
            unit++;
        }
        return String.format("%.2f %s", value, UNITS[unit]);
    }
}
