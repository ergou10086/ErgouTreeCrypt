package hbnu.project.ergoutreecrypt.log;

/**
 * 应用日志级别。
 *
 * <p>严重程度从高到低：{@link #ERROR}、{@link #WARN}、{@link #INFO}、{@link #TRACE}。
 * 设置阈值后，仅记录严重程度不低于该阈值的事件。用户设置只暴露
 * {@link #INFO}（标准）与 {@link #TRACE}（诊断）两档。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public enum LogLevel {

    /** 错误：操作失败、不可恢复异常。 */
    ERROR,

    /** 警告：可继续但值得注意的情况（如暴力破解锁定）。 */
    WARN,

    /** 信息：操作开始/结束、阶段状态、进度里程碑。默认阈值。 */
    INFO,

    /** 诊断：阶段耗时、算法参数、节流后的块进度。仅用于排障与性能分析。 */
    TRACE;

    /**
     * 判断当前阈值是否应记录给定事件级别。
     *
     * @param eventLevel 事件自身的级别
     * @return 事件级别不低于当前阈值时返回 {@code true}
     */
    public boolean includes(LogLevel eventLevel) {
        if (eventLevel == null) {
            return false;
        }
        return eventLevel.ordinal() <= ordinal();
    }

    /**
     * 从设置字符串解析级别，无法识别时回退为 {@link #INFO}。
     *
     * @param name 级别名，可为 null
     * @return 对应枚举；仅 {@code TRACE}（忽略大小写）解析为诊断级别
     */
    public static LogLevel fromName(String name) {
        if (name != null && "TRACE".equalsIgnoreCase(name.trim())) {
            return TRACE;
        }
        return INFO;
    }
}
