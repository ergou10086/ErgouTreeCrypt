package hbnu.project.ergoutreecrypt.header;

/**
 * 卷头各字段的偏移与尺寸常量。
 *
 * <p>基础 header = 789 字节 + comments×3（每个注释字符 RS1 编码为 3 字节）。
 * <pre>
 *   version(15) + commentLen(15) + flags(15)
 *   + salt(48) + hkdfSalt(96) + serpentIV(48) + nonce(72)
 *   + keyHash(192) + keyfileHash(96) + authTag(192)
 *   = 789 + comments×3
 * </pre>
 *
 * <p>Auth 值（keyHash / keyfileHash / authTag）的文件偏移为 {@code 309 + comments×3}。
 *
 * @author ErgouTree
 */
public final class HeaderLayout {

    // ==================== 编码后的字段尺寸（RS 编码后写入文件） ====================

    /**
     * version 编码后尺寸：5→15（RS5）。
     */
    public static final int VERSION_ENC_SIZE = 15;

    /**
     * 注释长度编码后尺寸：5→15（RS5）。
     */
    public static final int COMMENT_LEN_ENC_SIZE = 15;

    /**
     * 单个注释字符编码后尺寸：1→3（RS1）。
     */
    public static final int COMMENT_CHAR_ENC_SIZE = 3;

    /**
     * flags 编码后尺寸：5→15（RS5）。
     */
    public static final int FLAGS_ENC_SIZE = 15;

    /**
     * salt 编码后尺寸：16→48（RS16）。
     */
    public static final int SALT_ENC_SIZE = 48;

    /**
     * hkdfSalt 编码后尺寸：32→96（RS32）。
     */
    public static final int HKDF_SALT_ENC_SIZE = 96;

    /**
     * serpentIV 编码后尺寸：16→48（RS16）。
     */
    public static final int SERPENT_IV_ENC_SIZE = 48;

    /**
     * nonce 编码后尺寸：24→72（RS24）。
     */
    public static final int NONCE_ENC_SIZE = 72;

    /**
     * keyHash 编码后尺寸：64→192（RS64）。
     */
    public static final int KEY_HASH_ENC_SIZE = 192;

    /**
     * keyfileHash 编码后尺寸：32→96（RS32）。
     */
    public static final int KEYFILE_HASH_ENC_SIZE = 96;

    /**
     * authTag 编码后尺寸：64→192（RS64）。
     */
    public static final int AUTH_TAG_ENC_SIZE = 192;

    /**
     * Argon2 参数源字段（v2.15+）：6 字节（4B memory + 1B passes + 1B threads）。
     */
    public static final int ARGON2_PARAMS_SRC_SIZE = 6;

    /**
     * Argon2 参数编码后尺寸：6→18（RS6）。
     */
    public static final int ARGON2_PARAMS_ENC_SIZE = 18;

    // ==================== 基础尺寸计算 ====================

    /**
     * 不含注释的基础 header 大小（v2.14）。
     * 15+15+15+48+96+48+72+192+96+192 = 789 字节。
     */
    public static final int BASE_HEADER_SIZE =
            VERSION_ENC_SIZE + COMMENT_LEN_ENC_SIZE + FLAGS_ENC_SIZE
                    + SALT_ENC_SIZE + HKDF_SALT_ENC_SIZE + SERPENT_IV_ENC_SIZE
                    + NONCE_ENC_SIZE + KEY_HASH_ENC_SIZE + KEYFILE_HASH_ENC_SIZE
                    + AUTH_TAG_ENC_SIZE;

    /**
     * 不含注释的基础 header 大小（v2.15+）。
     * 789 + 18 = 807 字节。
     */
    public static final int BASE_HEADER_SIZE_V215 =
            BASE_HEADER_SIZE + ARGON2_PARAMS_ENC_SIZE;

    // ==================== RS 编码前的源字段尺寸 ====================

    /**
     * version 源字段：5 字节。
     */
    public static final int VERSION_SRC_SIZE = 5;

    /**
     * 注释长度源字段：5 字节（{@code %05d} 格式化）。
     */
    public static final int COMMENT_LEN_SRC_SIZE = 5;

    /**
     * 单个注释源字符：1 字节。
     */
    public static final int COMMENT_CHAR_SRC_SIZE = 1;

    /**
     * flags 源字段：5 字节。
     */
    public static final int FLAGS_SRC_SIZE = 5;

    private HeaderLayout() {
    }

    /**
     * 计算含注释的总 header 大小（v2.14 格式）。
     *
     * @param commentsLen 注释字符数（UTF-8 字节长度）
     * @return {@code 789 + commentsLen * 3} 字节
     */
    public static int headerSize(int commentsLen) {
        return headerSize(commentsLen, "v2.14");
    }

    /**
     * 计算含注释的总 header 大小（版本感知）。
     *
     * @param commentsLen 注释字符数（UTF-8 字节长度）
     * @param version     header 版本字符串（如 "v2.14" 或 "v2.15"）
     * @return 总 header 字节数
     */
    public static int headerSize(int commentsLen, String version) {
        int base = "v2.15".compareTo(version) <= 0
                ? BASE_HEADER_SIZE_V215 : BASE_HEADER_SIZE;
        return base + commentsLen * COMMENT_CHAR_ENC_SIZE;
    }

    /**
     * Auth 值（keyHash / keyfileHash / authTag）在文件中的起始偏移（v2.14 格式）。
     *
     * <p>公式：version(15) + commentLen(15) + comments(len×3) + flags(15)
     * + salt(48) + hkdfSalt(96) + serpentIV(48) + nonce(72) = 309 + comments×3。
     *
     * @param commentsLen 注释字符数（UTF-8 字节长度）
     * @return auth 值起始偏移（字节）
     */
    public static int authValuesOffset(int commentsLen) {
        return authValuesOffset(commentsLen, "v2.14");
    }

    /**
     * Auth 值（keyHash / keyfileHash / authTag）在文件中的起始偏移（版本感知）。
     *
     * <p>v2.15 额外包含 argon2 参数块（18 字节），offset 增加相应大小。
     *
     * @param commentsLen 注释字符数（UTF-8 字节长度）
     * @param version     header 版本字符串
     * @return auth 值起始偏移（字节）
     */
    public static int authValuesOffset(int commentsLen, String version) {
        int offset = VERSION_ENC_SIZE + COMMENT_LEN_ENC_SIZE + commentsLen * COMMENT_CHAR_ENC_SIZE
                + FLAGS_ENC_SIZE + SALT_ENC_SIZE + HKDF_SALT_ENC_SIZE + SERPENT_IV_ENC_SIZE
                + NONCE_ENC_SIZE;
        if ("v2.15".compareTo(version) <= 0) {
            offset += ARGON2_PARAMS_ENC_SIZE;
        }
        return offset;
    }
}
