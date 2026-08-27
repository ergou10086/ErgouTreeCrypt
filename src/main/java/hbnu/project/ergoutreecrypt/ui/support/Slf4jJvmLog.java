package hbnu.project.ergoutreecrypt.ui.support;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy;
import ch.qos.logback.core.util.FileSize;
import hbnu.project.ergoutreecrypt.log.LogEvent;
import hbnu.project.ergoutreecrypt.log.LogSink;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

/**
 * 桌面端 SLF4J / Logback 接入：把操作日志镜像到滚动文件 {@code jvm.log}。
 *
 * <p>仅在设置开启 JVM 底层日志后启动；关闭时复位 LoggerContext，不再写文件。
 *
 * @author ErgouTree
 * @since 2026/8/27
 */
public final class Slf4jJvmLog implements LogSink {

    /** 日志目录，由 {@link #bindDirectory(Path)} 注入。 */
    private static volatile Path logDir;

    /** Logback 是否已启动。 */
    private static volatile boolean started;

    /** 配置互斥。 */
    private static final Object LOCK = new Object();

    /**
     * 绑定日志目录。应在应用启动时调用一次。
     *
     * @param dir 日志目录，不允许为 null
     */
    public static void bindDirectory(Path dir) {
        logDir = dir;
    }

    /**
     * 启动滚动文件 appender。重复调用是空操作。
     */
    public static void start() {
        synchronized (LOCK) {
            if (started) {
                return;
            }
            Path dir = logDir;
            if (dir == null) {
                return;
            }
            ILoggerFactory factory = LoggerFactory.getILoggerFactory();
            if (!(factory instanceof LoggerContext context)) {
                return;
            }
            context.reset();

            PatternLayoutEncoder encoder = new PatternLayoutEncoder();
            encoder.setContext(context);
            encoder.setPattern("%d{HH:mm:ss.SSS} [%thread] %-5level %logger{24} - %msg%n");
            encoder.start();

            RollingFileAppender<ILoggingEvent> rolling = new RollingFileAppender<>();
            rolling.setContext(context);
            rolling.setName("JVM_FILE");
            rolling.setFile(dir.resolve("jvm.log").toAbsolutePath().toString());
            rolling.setAppend(true);
            rolling.setEncoder(encoder);

            FixedWindowRollingPolicy policy = new FixedWindowRollingPolicy();
            policy.setContext(context);
            policy.setParent(rolling);
            policy.setFileNamePattern(dir.resolve("jvm.log.%i").toAbsolutePath().toString());
            policy.setMinIndex(1);
            policy.setMaxIndex(4);
            policy.start();

            SizeBasedTriggeringPolicy<ILoggingEvent> trigger = new SizeBasedTriggeringPolicy<>();
            trigger.setContext(context);
            trigger.setMaxFileSize(FileSize.valueOf("8MB"));
            trigger.start();

            rolling.setRollingPolicy(policy);
            rolling.setTriggeringPolicy(trigger);
            rolling.start();

            Logger root = context.getLogger(Logger.ROOT_LOGGER_NAME);
            root.detachAndStopAllAppenders();
            root.setLevel(Level.WARN);
            root.addAppender(rolling);

            Logger ergou = context.getLogger("ergou");
            ergou.setLevel(Level.DEBUG);
            ergou.setAdditive(true);

            started = true;
        }
    }

    /**
     * 停止 Logback 并复位上下文。未启动时忽略。
     */
    public static void stop() {
        synchronized (LOCK) {
            if (!started) {
                return;
            }
            ILoggerFactory factory = LoggerFactory.getILoggerFactory();
            if (factory instanceof LoggerContext context) {
                context.stop();
                context.reset();
            }
            started = false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void accept(LogEvent event) {
        if (!started || event == null) {
            return;
        }
        String loggerName = "ergou." + (event.category() == null ? "?" : event.category());
        org.slf4j.Logger logger = LoggerFactory.getLogger(loggerName);
        String line = event.formatLine();
        switch (event.level()) {
            case ERROR -> logger.error(line);
            case WARN -> logger.warn(line);
            case TRACE -> logger.debug(line);
            default -> logger.info(line);
        }
    }
}
