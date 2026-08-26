package hbnu.project.ergoutreecrypt.log;

/**
 * 阶段日志辅助：在 INFO 记录阶段进入，在 TRACE 记录耗时。
 *
 * <p>供加解密流水线在各 phase 边界调用，避免业务代码重复计时样板。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LogPhases {

    private LogPhases() {
    }

    /**
     * 可抛出受检异常的阶段动作。
     */
    @FunctionalInterface
    public interface Action {

        /**
         * 执行阶段逻辑。
         *
         * @throws Exception 阶段失败
         */
        void run() throws Exception;
    }

    /**
     * 执行一个命名阶段并记录日志。
     *
     * @param category 分类
     * @param phase    阶段名
     * @param action   阶段动作
     * @throws Exception 动作抛出的异常原样向上传递
     */
    public static void run(String category, String phase, Action action) throws Exception {
        LogService.info(category, "阶段: " + phase);
        long startNs = System.nanoTime();
        action.run();
        if (LogService.isTraceEnabled()) {
            long elapsed = (System.nanoTime() - startNs) / 1_000_000L;
            LogService.trace(category, "阶段完成: " + phase, elapsed);
        }
    }
}
