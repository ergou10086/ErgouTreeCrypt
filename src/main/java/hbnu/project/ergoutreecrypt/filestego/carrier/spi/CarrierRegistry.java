package hbnu.project.ergoutreecrypt.filestego.carrier.spi;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 载体适配器注册表——管理所有可用的 {@link CarrierAdapter} 实现。
 *
 * <p>提供按扩展名查找、自动检测格式、获取全部适配器等功能。
 * 适配器在应用启动时通过 {@link #register(CarrierAdapter)} 注册。
 *
 * <p>查找优先级：
 * <ol>
 *   <li>遍历所有适配器的 {@link CarrierAdapter#detect} 方法</li>
 *   <li>回退：按文件扩展名匹配</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class CarrierRegistry {

    /** 按扩展名索引的适配器映射（含 "." 前缀） */
    private static final Map<String, CarrierAdapter> BY_EXTENSION = new LinkedHashMap<>();

    /** 所有已注册的适配器列表 */
    private static final List<CarrierAdapter> ALL = new ArrayList<>();

    private CarrierRegistry() {
    }

    /**
     * 注册适配器。
     *
     * <p>同一扩展名若已存在则覆盖（后注册优先）。
     *
     * @param adapter 载体适配器实例
     */
    public static void register(final CarrierAdapter adapter) {
        ALL.add(adapter);
        for (String ext : adapter.supportedExtensions()) {
            BY_EXTENSION.put(ext.toLowerCase(), adapter);
        }
    }

    /**
     * 根据文件扩展名查找适配器。
     *
     * @param extension 文件扩展名（含 "." 前缀，如 ".png"）
     * @return 匹配的适配器，未找到返回 {@link Optional#empty()}
     */
    public static Optional<CarrierAdapter> findByExtension(final String extension) {
        return Optional.ofNullable(BY_EXTENSION.get(extension.toLowerCase()));
    }

    /**
     * 自动检测文件对应的适配器。
     *
     * <p>先遍历所有适配器的 {@link CarrierAdapter#detect} 方法进行魔数检测，
     * 若全部返回 false 则回退按扩展名匹配。
     *
     * <p>注意：由于包含扩展名回退，本方法对任意已知扩展名的文件都可能返回适配器，
     * 因此<b>不可</b>用于判断文件是否真正含有隐写数据；该判断请使用
     * {@link #detectByMagic(Path)}。
     *
     * @param file 待检测文件
     * @return 匹配的适配器，未找到返回 {@link Optional#empty()}
     */
    public static Optional<CarrierAdapter> detectAdapter(final Path file) {
        // 第一优先级：魔数检测
        Optional<CarrierAdapter> byMagic = detectByMagic(file);
        if (byMagic.isPresent()) {
            return byMagic;
        }
        // 第二优先级：按扩展名匹配
        String name = file.getFileName().toString().toLowerCase();
        for (Map.Entry<String, CarrierAdapter> entry : BY_EXTENSION.entrySet()) {
            if (name.endsWith(entry.getKey())) {
                return Optional.of(entry.getValue());
            }
        }
        return Optional.empty();
    }

    /**
     * 仅通过魔数检测查找适配器（不含扩展名回退）。
     *
     * <p>用于判断文件是否真正含有本工具的隐写数据。
     *
     * @param file 待检测文件
     * @return 检测到隐写数据的适配器，未检测到返回 {@link Optional#empty()}
     */
    public static Optional<CarrierAdapter> detectByMagic(final Path file) {
        for (CarrierAdapter adapter : ALL) {
            if (adapter.detect(file)) {
                return Optional.of(adapter);
            }
        }
        return Optional.empty();
    }

    /**
     * 获取所有已注册的适配器（不可修改列表）。
     *
     * @return 适配器列表
     */
    public static List<CarrierAdapter> all() {
        return Collections.unmodifiableList(ALL);
    }

    /**
     * 获取当前已注册的适配器数量。
     *
     * @return 适配器数量
     */
    public static int count() {
        return ALL.size();
    }

    /**
     * 清空所有注册的适配器（主要用于测试）。
     */
    static void clear() {
        ALL.clear();
        BY_EXTENSION.clear();
    }
}
