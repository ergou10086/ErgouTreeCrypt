package hbnu.project.ergoutreecrypt.password;

/**
 * 无密码模式的常量定义。
 *
 * <h3>设计说明</h3>
 * <p>"无密码"并非真的不加密码学保护，而是使用一个<b>公开的默认密码</b>进行加解密。
 * 这意味着任何知道此密码的人都可以解密"无密码"文件，实现了"无需设置密码即可加解密"的目标。
 *
 * <p>安全性：<b>等于明文传输</b>——拿到文件即能解密（密码是公开的）。仅用于无保密需求的场景（如文件防篡改、格式转换等），不要用于保护敏感数据。
 *
 * <p>默认密码：
 * <pre>ErgouTree1L0EASMR,WeLcOmeTO859866811AddDiscussion</pre>
 *
 * @author ErgouTree
 */
public final class Passwordless {

    /**
     * 无密码模式使用的默认密码。加密时若用户留空密码，系统以此密码加盐派生密钥；
     * 解密时若用户未提供密码，系统尝试以此密码解密。
     */
    public static final String DEFAULT_PASSWORD = "ErgouTree1L0EASMR,WeLcOmeTO859866811AddDiscussion";

    private Passwordless() {
    }

    /**
     * 判断给定密码是否表示"无密码"请求。
     */
    public static boolean isNoPassword(String password) {
        return password == null || password.isEmpty();
    }

    /**
     * 返回实际用于加解密的密码：无密码时回退为 {@link #DEFAULT_PASSWORD}，
     * 否则返回原始密码。
     *
     * <p>这保证了"无密码"模式等价于使用公开默认密码加密——拿到文件即可用，使用默认密码解密，无需记住任何口令。
     */
    public static String effectivePassword(String password) {
        return isNoPassword(password) ? DEFAULT_PASSWORD : password;
    }
}
