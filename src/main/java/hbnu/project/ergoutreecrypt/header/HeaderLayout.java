package hbnu.project.ergoutreecrypt.header;

/**
 * 卷头各字段的偏移与尺寸常量
 *
 * <p>基础 header = 789 字节 + comments×3（每个注释字符 RS1 编码）。公式：
 * <pre>
 *   version(15) + commentLen(15) + flags(15)
 *   + salt(48) + hkdfSalt(96) + serpentIV(48) + nonce(72)
 *   + keyHash(192) + keyfileHash(96) + authTag(192)
 *   = 789 + comments*3
 * </pre>
 *
 * <p>Auth 值（keyHash / keyfileHash / authTag）的偏移为 {@code 309 + comments×3}。
 *
 * @author ErgouTree
 */
public final class HeaderLayout {

    // ---- 编码后的字段尺寸 ----

    /**
     * version: 5→15（RS5）。
     */
    public static final int VERSION_ENC_SIZE = 15;
    /**
     * 注释长度: 5→15（RS5）。
     */
    public static final int COMMENT_LEN_ENC_SIZE = 15;
    /**
     * 注释单字符: 1→3（RS1）。
     */
    public static final int COMMENT_CHAR_ENC_SIZE = 3;
    /**
     * flags: 5→15（RS5）。
     */
    public static final int FLAGS_ENC_SIZE = 15;
    /**
     * salt: 16→48（RS16）。
     */
    public static final int SALT_ENC_SIZE = 48;
    /**
     * hkdfSalt: 32→96（RS32）。
     */
    public static final int HKDF_SALT_ENC_SIZE = 96;
    /**
     * serpentIV: 16→48（RS16）。
     */
    public static final int SERPENT_IV_ENC_SIZE = 48;
    /**
     * nonce: 24→72（RS24）。
     */
    public static final int NONCE_ENC_SIZE = 72;
    /**
     * keyHash: 64→192（RS64）。
     */
    public static final int KEY_HASH_ENC_SIZE = 192;
    /**
     * keyfileHash: 32→96（RS32）。
     */
    public static final int KEYFILE_HASH_ENC_SIZE = 96;
    /**
     * authTag: 64→192（RS64）。
     */
    public static final int AUTH_TAG_ENC_SIZE = 192;

    /**
     * 不含注释的基础 header 大小。
     * 15+15+15+48+96+48+72+192+96+192 = 789
     */
    public static final int BASE_HEADER_SIZE =
            VERSION_ENC_SIZE + COMMENT_LEN_ENC_SIZE + FLAGS_ENC_SIZE
                    + SALT_ENC_SIZE + HKDF_SALT_ENC_SIZE + SERPENT_IV_ENC_SIZE
                    + NONCE_ENC_SIZE + KEY_HASH_ENC_SIZE + KEYFILE_HASH_ENC_SIZE
                    + AUTH_TAG_ENC_SIZE;
    /**
     * Version 源字段：5 字节。
     */
    public static final int VERSION_SRC_SIZE = 5;
    /**
     * 注释长度源字段：5 字节（{@code %05d} 格式化）。
     */
    public static final int COMMENT_LEN_SRC_SIZE = 5;

    // ---- 编码前的源字段尺寸 ----
    /**
     * 单个注释源字符：1 字节。
     */
    public static final int COMMENT_CHAR_SRC_SIZE = 1;
    /**
     * Flags 源字段：5 字节。
     */
    public static final int FLAGS_SRC_SIZE = 5;
    private HeaderLayout() {
    }

    /**
     * 计算含注释的总 header 大小。
     *
     * @param commentsLen 注释字符数
     * @return {@code 789 + commentsLen * 3}
     */
    public static int headerSize(int commentsLen) {
        return BASE_HEADER_SIZE + commentsLen * COMMENT_CHAR_ENC_SIZE;
    }

    /**
     * Auth 值（keyHash / keyfileHash / authTag）在文件中的偏移。
     * 公式：version(15) + commentLen(15) + comments(len*3) + flags(15)
     * + salt(48) + hkdfSalt(96) + serpentIV(48) + nonce(72) = 309 + comments×3。
     *
     * @param commentsLen 注释字符数
     * @return auth 值起始偏移
     */
    public static int authValuesOffset(int commentsLen) {
        return VERSION_ENC_SIZE + COMMENT_LEN_ENC_SIZE + commentsLen * COMMENT_CHAR_ENC_SIZE
                + FLAGS_ENC_SIZE + SALT_ENC_SIZE + HKDF_SALT_ENC_SIZE + SERPENT_IV_ENC_SIZE
                + NONCE_ENC_SIZE;
    }
}
