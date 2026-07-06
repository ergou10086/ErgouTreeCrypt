package hbnu.project.ergoutreecrypt.classical;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 古典密码算法注册中心。
 *
 * <p>维护所有可用古典密码算法实例的注册表，提供按 id 查找及全部列举功能。
 * 注册表中的算法按插入顺序排列，UI 可据此渲染下拉列表。
 *
 * @author ErgouTree
 */
public final class CipherRegistry {

    private static final Map<String, ClassicalCipher> CIPHERS = new LinkedHashMap<>();

    static {
        register(new CaesarCipher());
        register(new AtbashCipher());
        register(new Rot13Cipher());
        register(new VigenereCipher());
        register(new AutokeyCipher());
        register(new BeaufortCipher());
        register(new RailFenceCipher());
        register(new ColumnarTranspositionCipher());
        register(new XorCipher());
        register(new ReverseCipher());
    }

    private CipherRegistry() {
    }

    /**
     * 注册一个算法实例。
     *
     * @param cipher 算法实例
     */
    private static void register(final ClassicalCipher cipher) {
        CIPHERS.put(cipher.getInfo().id(), cipher);
    }

    /**
     * 按算法 id 获取实例。
     *
     * @param id 算法唯一标识
     * @return 算法实例，未找到返回 null
     */
    public static ClassicalCipher get(final String id) {
        return CIPHERS.get(id);
    }

    /**
     * 获取所有已注册的算法信息列表，按注册顺序排列。
     *
     * @return 算法元数据列表
     */
    public static List<CipherInfo> getAll() {
        return CIPHERS.values().stream()
                .map(ClassicalCipher::getInfo)
                .toList();
    }

    /**
     * 获取默认算法（注册表中的第一个）。
     *
     * @return 默认算法实例
     */
    public static ClassicalCipher getDefault() {
        return CIPHERS.values().iterator().next();
    }
}
