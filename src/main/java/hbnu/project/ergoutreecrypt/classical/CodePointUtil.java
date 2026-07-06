package hbnu.project.ergoutreecrypt.classical;

/**
 * Unicode 码点安全区间映射工具。
 *
 * <p>将 Unicode 码点空间（排除 U+D800..U+DFFF 代理对区域）映射到连续整数区间
 * [0, SAFE_RANGE)，以支持码点级的模运算（用于替换密码）。
 *
 * @author ErgouTree
 */
final class CodePointUtil {

    /**
     * 安全区间大小：全部 Unicode 码点减去 2048 个代理对码点。
     */
    static final int SAFE_RANGE = 1_112_064;

    /**
     * 代理对区域大小。
     */
    private static final int SURROGATE_COUNT = 0x800;

    private CodePointUtil() {
    }

    /**
     * 将 Unicode 码点映射到安全连续区间内的位置。
     *
     * @param cp Unicode 码点（0x0000..0x10FFFF 且非代理对）
     * @return 安全区间位置（0 .. SAFE_RANGE-1）
     */
    static int toSafePosition(final int cp) {
        if (cp <= 0xD7FF) {
            return cp;
        }
        return cp - SURROGATE_COUNT;
    }

    /**
     * 将安全区间位置映射回 Unicode 码点。
     *
     * @param pos 安全区间位置（0 .. SAFE_RANGE-1）
     * @return Unicode 码点
     */
    static int fromSafePosition(final int pos) {
        if (pos <= 0xD7FF) {
            return pos;
        }
        return pos + SURROGATE_COUNT;
    }
}
