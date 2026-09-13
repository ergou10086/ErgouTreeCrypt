package hbnu.project.ergoutreecrypt.exception;

import hbnu.project.ergoutreecrypt.i18n.Messages;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;

/**
 * 异常 → 友好文案的统一映射器。
 *
 * <p>供两端前端在统一捕获点把任意 {@link Throwable} 映射为「i18n key + 格式化参数」，
 * 或判定是否属于「用户取消」。映射优先级写死为类型判断，不依赖异常消息字符串：
 * <ol>
 *   <li>{@code t instanceof CryptoException} → 取 {@code kind()}/{@code args()}；</li>
 *   <li>兼容旧类型：协程取消、线程中断 → 取消；{@code NoSuchFileException}/{@code FileNotFoundException}
 *       → 文件不存在；{@code AccessDeniedException} → 无权限；{@code FileSystemException} → 文件被占用；
 *       {@code OutOfMemoryError} → 内存不足；</li>
 *   <li>其余 {@code IOException} → 兜底 I/O 错误（透出 detail）；</li>
 *   <li>其它 → 内部错误（不透出 detail）。</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/9/13
 */
public final class ExceptionMapper {

    private ExceptionMapper() {
    }

    /**
     * 映射结果：i18n key 与可选格式化参数。
     *
     * @param key  文案 key
     * @param args 格式化参数，可为 null
     */
    public record Message(String key, Object[] args) {

        /**
         * 构造仅含 key 的映射结果。
         *
         * @param key 文案 key
         */
        public Message(String key) {
            this(key, null);
        }
    }

    /**
     * 把任意异常映射为「i18n key + 格式化参数」。
     *
     * @param t 待映射异常
     * @return 映射结果，恒非 null
     */
    public static Message toMessage(Throwable t) {
        if (t instanceof CryptoException ce) {
            return new Message(ce.kind().i18nKey(), ce.args());
        }
        ErrorKind kind = classify(t);
        if (kind == ErrorKind.IO_ERROR) {
            return new Message(kind.i18nKey(), new Object[] { detail(t) });
        }
        return new Message(kind.i18nKey());
    }

    /**
     * 把任意异常解析为可直接展示的友好文案（已按当前语言解析 i18n）。
     *
     * <p>等价于 {@link #toMessage(Throwable)} 后按 args 是否为空调用
     * {@link Messages#get(String)} 或 {@link Messages#format(String, Object...)}。
     *
     * @param t 待映射异常
     * @return 已解析的友好文案，恒非空
     */
    public static String friendlyMessage(Throwable t) {
        Message m = toMessage(t);
        Object[] args = m.args();
        if (args == null || args.length == 0) {
            return Messages.get(m.key());
        }
        return Messages.format(m.key(), args);
    }

    /**
     * 返回异常对应的错误分类。
     *
     * @param t 待归类异常
     * @return 错误分类，恒非 null
     */
    public static ErrorKind kindOf(Throwable t) {
        return classify(t);
    }

    /**
     * 判断异常是否属于「用户取消」。
     *
     * <p>覆盖本项目的 {@link CancelledException}，以及历史遗留的 {@code InterruptedException}、
     * Kotlin 协程的 {@code CancellationException}。
     *
     * @param t 待判定异常
     * @return true 表示前端应静默处理、不弹错误
     */
    public static boolean isCancellation(Throwable t) {
        return t instanceof CancelledException
                || t instanceof InterruptedException
                || t instanceof java.util.concurrent.CancellationException;
    }

    /**
     * 判断是否把原始 detail 透出给用户（仅诊断场景）。
     *
     * @param t 待判定异常
     * @return true 表示应透出 detail（当前仅兜底 I/O 错误）
     */
    public static boolean showDetail(Throwable t) {
        return classify(t) == ErrorKind.IO_ERROR;
    }

    /**
     * 把异常归类为 {@link ErrorKind}。优先级见类注释。
     *
     * @param t 待归类异常
     * @return 错误分类，恒非 null
     */
    private static ErrorKind classify(Throwable t) {
        if (t instanceof CryptoException ce) {
            return ce.kind();
        }
        if (t instanceof NoSuchFileException || t instanceof FileNotFoundException) {
            return ErrorKind.INPUT_NOT_FOUND;
        }
        if (t instanceof AccessDeniedException) {
            return ErrorKind.ACCESS_DENIED;
        }
        if (t instanceof FileSystemException) {
            return ErrorKind.FILE_IN_USE;
        }
        if (t instanceof OutOfMemoryError) {
            return ErrorKind.OUT_OF_MEMORY;
        }
        if (t instanceof IOException) {
            return ErrorKind.IO_ERROR;
        }
        return ErrorKind.INTERNAL_ERROR;
    }

    /**
     * 提取异常短消息用于 detail 展示。
     *
     * @param t 异常
     * @return 非空短消息
     */
    private static String detail(Throwable t) {
        String msg = t.getMessage();
        return (msg == null || msg.isBlank()) ? t.getClass().getSimpleName() : msg;
    }
}
