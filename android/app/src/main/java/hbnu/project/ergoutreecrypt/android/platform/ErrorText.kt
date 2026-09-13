package hbnu.project.ergoutreecrypt.android.platform

import hbnu.project.ergoutreecrypt.exception.ErrorKind
import hbnu.project.ergoutreecrypt.exception.ExceptionMapper

/**
 * 将异常描述为可读的错误文本（类名 + 消息）。
 *
 * <p>共享核心的 {@code java.nio.file.AccessDeniedException} / {@code NoSuchFileException}
 * 等异常在 Android 上的 {@code localizedMessage} 往往只是裸路径（reason 为 null），
 * 仅凭消息无法区分异常类型，导致错误映射（{@code mapErrorToChineseMessage}）失效、
 * 用户看到的只是"解密失败 /storage/emulated/0/..."。此函数统一拼接类名，保证
 * 错误映射能命中"权限拒绝 / 文件不存在 / 内存不足"等分支。
 *
 * @param e 待描述的异常
 * @return "类名: 消息" 形式的可读文本
 * @author ErgouTree
 * @since 2026/8/28
 */
fun describeError(e: Throwable): String =
    "${e.javaClass.simpleName}: ${e.localizedMessage ?: ""}".trim()

/**
 * 将异常映射为友好文案（按 {@link ErrorKind} 类型判断，不依赖消息字符串）。
 *
 * <p>委托共享核心的 {@link ExceptionMapper#friendlyMessage(Throwable)}，据当前语言
 * 解析对应的 {@code messages_*.properties}。未知异常回退为「内部错误」。
 *
 * @param e 待映射异常
 * @return 已解析的友好文案
 */
fun friendlyError(e: Throwable): String = ExceptionMapper.friendlyMessage(e)

/**
 * 返回异常对应的错误分类。
 *
 * @param e 待归类异常
 * @return 错误分类，恒非 null
 */
fun errorKind(e: Throwable): ErrorKind = ExceptionMapper.kindOf(e)
