package hbnu.project.ergoutreecrypt.history;

import java.util.List;

/**
 * 操作历史存储接口。
 *
 * <p>抽象历史记录的持久化方式，供各平台注入具体实现
 * （如文件存储、数据库、云同步等），历史功能本身不依赖任何具体存储介质。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
public interface HistoryStore {

    /**
     * 追加一条历史记录。
     *
     * <p>实现必须保证线程安全，并自行维护记录数量上限（超出时丢弃最旧记录）。
     *
     * @param record 待追加的记录，不允许为 null
     */
    void record(OperationRecord record);

    /**
     * 读取全部历史记录，最新记录排在最前。
     *
     * @return 按时间倒序排列的记录列表；无记录时返回空列表
     */
    List<OperationRecord> list();

    /**
     * 清空全部历史记录。
     */
    void clear();
}
