package hbnu.project.ergoutreecrypt.history;

import java.util.List;

/**
 * 操作历史服务门面。
 *
 * <p>提供进程级的静态入口，供各平台在加解密成功后记录历史、读取与清空。
 * 平台启动时通过 {@link #register(HistoryStore)} 注入具体存储实现；
 * 未注册时所有方法安全降级（记录静默丢弃、读取返回空列表）。
 *
 * <p>本类与任何加解密模块无依赖，历史功能可独立演进。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
public final class HistoryService {

    /** 当前存储实现，未注册时为 null */
    private static volatile HistoryStore store;

    /**
     * 私有构造器，禁止实例化。
     */
    private HistoryService() {
    }

    /**
     * 注册历史存储实现。
     *
     * <p>通常在平台启动时调用一次；重复注册会替换原实现。
     *
     * @param historyStore 存储实现；传 null 等价于未注册
     */
    public static void register(HistoryStore historyStore) {
        store = historyStore;
    }

    /**
     * 记录一次成功的加解密操作。
     *
     * <p>未注册存储、操作类型为 null 或文件名为空时静默忽略。
     * 存储写入失败由存储实现自行消化，绝不向上抛出。
     *
     * @param type       操作类型
     * @param fileName   文件名
     * @param outputPath 输出文件/目录绝对路径，可为 null
     * @param outputUri  移动端 SAF 目录树 URI 字符串，可为 null
     */
    public static void record(OperationType type, String fileName, String outputPath, String outputUri) {
        HistoryStore current = store;
        if (current == null || type == null || fileName == null || fileName.isBlank()) {
            return;
        }
        current.record(new OperationRecord(fileName, outputPath, outputUri, type,
                System.currentTimeMillis()));
    }

    /**
     * 读取全部历史记录，最新记录排在最前。
     *
     * @return 记录列表；未注册或无记录时返回空列表
     */
    public static List<OperationRecord> list() {
        HistoryStore current = store;
        return current == null ? List.of() : current.list();
    }

    /**
     * 清空全部历史记录。
     */
    public static void clear() {
        HistoryStore current = store;
        if (current != null) {
            current.clear();
        }
    }
}
