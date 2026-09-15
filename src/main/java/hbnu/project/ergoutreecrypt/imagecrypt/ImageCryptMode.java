package hbnu.project.ergoutreecrypt.imagecrypt;

/**
 * EGTC-IMG 的保护模式。
 *
 * <p>模式由加密方显式选择，<b>不</b>用"密码是否为空"隐式推断；解密方的模式完全来自
 * 文件头（{@code protectionMode} 字段），UI 不得覆写。该字段已纳入 MAC 覆盖范围，
 * 因此篡改保护模式会导致认证失败，无法把密码文件降级为公开文件。
 *
 * <table border="1">
 *   <caption>模式语义</caption>
 *   <tr><th>模式</th><th>建议界面名称</th><th>谁能恢复</th><th>安全含义</th></tr>
 *   <tr>
 *     <td>{@link #PUBLIC_RECOVERY}</td><td>公开恢复</td>
 *     <td>任何拿到文件和本工具的人</td>
 *     <td>仅视觉混淆，<b>不提供保密性</b>，也不宣称来源真实性</td>
 *   </tr>
 *   <tr>
 *     <td>{@link #PASSWORD}</td><td>密码保护</td>
 *     <td>知道密码的人</td>
 *     <td>Argon2id 派生密钥，提供机密性与完整性</td>
 *   </tr>
 * </table>
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public enum ImageCryptMode {

    /**
     * 公开恢复：每文件生成随机主密钥，并明文写入协议头。
     *
     * <p>不需要也不应该在无密码路径上执行 Argon2——公开常量不构成密码学边界。
     */
    PUBLIC_RECOVERY(0),

    /**
     * 密码保护：主密钥由 Argon2id 从用户密码派生，文件内不保存可恢复密钥。
     */
    PASSWORD(1);

    /**
     * 写入协议头的稳定数值标识。一经发布不得更改。
     */
    private final int id;

    /**
     * @param id 协议头中的 protectionMode 取值
     */
    ImageCryptMode(final int id) {
        this.id = id;
    }

    /**
     * 返回写入协议头的数值标识。
     *
     * @return 0 表示公开恢复，1 表示密码保护
     */
    public int id() {
        return id;
    }

    /**
     * 由协议头中的 {@code protectionMode} 数值反查模式。
     *
     * @param id 协议头中的 protectionMode 取值
     * @return 对应模式
     * @throws IllegalArgumentException 未知取值
     */
    public static ImageCryptMode fromId(final int id) {
        for (ImageCryptMode mode : values()) {
            if (mode.id == id) {
                return mode;
            }
        }
        throw new IllegalArgumentException("未知的 EGTC-IMG protectionMode: " + id);
    }

    /**
     * 判断给定数值是否为合法的 {@code protectionMode}。
     *
     * @param id 待判定取值
     * @return true 表示合法
     */
    public static boolean isKnownId(final int id) {
        return id == PUBLIC_RECOVERY.id || id == PASSWORD.id;
    }
}
