package hbnu.project.ergoutreecrypt.exception;

/**
 * 全项目统一的受检异常根。
 *
 * <p>所有子系统的可预期错误（密码错误、被篡改、磁盘满、格式不支持等）最终都应抛出
 * 本类型或其子类，使前端能通过 {@link #kind()} 做类型化判断，而非字符串匹配。
 *
 * <p>取向：<b>不为每个错误建子类</b>。绝大多数场景用 {@code new CryptoException(kind, message)}
 * 即可；只有需携带结构化字段时才建子类（见 {@link CancelledException}）。{@link #args()} 携带
 * i18n 格式化参数（如暴力破解锁定阈值），由映射器在展示阶段拼入文案。
 *
 * @author ErgouTree
 * @since 2026/9/13
 */
public class CryptoException extends Exception {

    /**
     * 错误分类。
     */
    private final ErrorKind kind;

    /**
     * i18n 格式化参数，可为 null。
     */
    private final Object[] args;

    /**
     * 构造无额外消息的异常。
     *
     * @param kind 错误分类
     */
    public CryptoException(ErrorKind kind) {
        this(kind, null, (Object[]) null);
    }

    /**
     * 构造带诊断消息的异常。
     *
     * @param kind    错误分类
     * @param message 诊断消息（进日志，不直接面向用户）
     */
    public CryptoException(ErrorKind kind, String message) {
        this(kind, message, (Object[]) null);
    }

    /**
     * 构造带诊断消息与 i18n 格式化参数的异常。
     *
     * @param kind    错误分类
     * @param message 诊断消息
     * @param args    i18n 格式化参数
     */
    public CryptoException(ErrorKind kind, String message, Object... args) {
        super(message);
        this.kind = kind;
        this.args = args;
    }

    /**
     * 构造带诊断消息与原因的异常。
     *
     * @param kind    错误分类
     * @param message 诊断消息
     * @param cause   底层异常
     */
    public CryptoException(ErrorKind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.args = null;
    }

    /**
     * 返回错误分类。
     *
     * @return 错误分类，恒非 null
     */
    public ErrorKind kind() {
        return kind;
    }

    /**
     * 返回 i18n 格式化参数。
     *
     * @return 格式化参数，可为 null
     */
    public Object[] args() {
        return args;
    }
}
