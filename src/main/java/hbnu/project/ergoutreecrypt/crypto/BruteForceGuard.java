package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.digests.SHA3Digest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 暴力破解防护守卫：通过外部侧车数据库跟踪每个文件的解密失败次数。
 *
 * <h3>设计原则</h3>
 * <ul>
 *   <li><b>不修改加密文件</b>：计数器存储在用户数据目录的 JSON 侧车文件中，绝不动加密文件本身</li>
 *   <li><b>文件识别基于哈希</b>：对加密文件的前 4096 字节做 SHA3-256 哈希作为文件标识符，
 *       避免文件名变更导致计数丢失</li>
 *   <li><b>全局统一</b>：适用于通用文件加密、音视频加密、图像隐写等所有加密模块</li>
 *   <li><b>线程安全</b>：使用 ConcurrentHashMap 支持多线程并发访问</li>
 * </ul>
 *
 * <h3>计数器生命周期</h3>
 * <ol>
 *   <li>解密尝试 → 读取计数器 → 超过阈值？→ 拒绝</li>
 *   <li>密码错误 → 计数器 +1 → 写入侧车文件</li>
 *   <li>密码正确 → 计数器归零 → 写入侧车文件</li>
 * </ol>
 *
 * <h3>阈值配置</h3>
 * <ul>
 *   <li>默认阈值：10 次</li>
 *   <li>达到阈值后：显示警告，用户需手动确认继续</li>
 *   <li>确认后：计数器重置，允许重试</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class BruteForceGuard {

    /**
     * 默认最大失败尝试次数。
     */
    public static final int DEFAULT_MAX_ATTEMPTS = 10;

    /**
     * 用于文件识别的采样字节数（文件头部 4 KiB）。
     */
    private static final int SAMPLE_SIZE = 4096;

    /**
     * 侧车数据库文件名。
     */
    private static final String DB_FILENAME = "ergou_bruteforce_guard.json";

    /**
     * JSON 键：entries。
     */
    private static final String KEY_ENTRIES = "entries";

    /**
     * JSON 键：fileId。
     */
    private static final String KEY_FILE_ID = "fileId";

    /**
     * JSON 键：failCount。
     */
    private static final String KEY_FAIL_COUNT = "failCount";

    /**
     * JSON 键：firstAttempt。
     */
    private static final String KEY_FIRST_ATTEMPT = "firstAttempt";

    /**
     * JSON 键：lastAttempt。
     */
    private static final String KEY_LAST_ATTEMPT = "lastAttempt";

    /**
     * 单例实例。
     */
    private static final BruteForceGuard INSTANCE = new BruteForceGuard();

    /**
     * 内存中的计数器缓存。
     */
    private final Map<String, GuardEntry> cache = new ConcurrentHashMap<>();

    /**
     * 侧车文件路径。
     */
    private Path dbPath;

    /**
     * 当前阈值。
     */
    private int maxAttempts = DEFAULT_MAX_ATTEMPTS;

    /**
     * 是否已加载。
     */
    private boolean loaded;

    private BruteForceGuard() {
    }

    /**
     * 获取单例实例。
     *
     * @return BruteForceGuard 实例
     */
    public static BruteForceGuard getInstance() {
        return INSTANCE;
    }

    /**
     * 从 JSON 对象中提取字符串值。
     */
    private static String extractString(String obj, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIdx = obj.indexOf(searchKey);
        if (keyIdx < 0) {
            return null;
        }
        int colonIdx = obj.indexOf(':', keyIdx);
        if (colonIdx < 0) {
            return null;
        }
        int valueStart = obj.indexOf('"', colonIdx);
        if (valueStart < 0) {
            return null;
        }
        int valueEnd = obj.indexOf('"', valueStart + 1);
        if (valueEnd < 0) {
            return null;
        }
        return obj.substring(valueStart + 1, valueEnd);
    }

    /**
     * 从 JSON 对象中提取整数值。
     */
    private static int extractInt(String obj, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIdx = obj.indexOf(searchKey);
        if (keyIdx < 0) {
            return 0;
        }
        int colonIdx = obj.indexOf(':', keyIdx);
        if (colonIdx < 0) {
            return 0;
        }
        // 跳过冒号后的空白
        int numStart = colonIdx + 1;
        while (numStart < obj.length() && Character.isWhitespace(obj.charAt(numStart))) {
            numStart++;
        }
        int numEnd = numStart;
        while (numEnd < obj.length() && Character.isDigit(obj.charAt(numEnd))) {
            numEnd++;
        }
        if (numEnd == numStart) {
            return 0;
        }
        try {
            return Integer.parseInt(obj.substring(numStart, numEnd));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * 转义 JSON 字符串中的特殊字符。
     */
    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * 字节数组转十六进制字符串。
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * 初始化守卫：设置数据目录并加载已有计数器。
     *
     * @param dataDir 用户数据目录（如 ~/.ergou/ 或 AppData）
     */
    public void init(Path dataDir) {
        this.dbPath = dataDir.resolve(DB_FILENAME);
        load();
    }

    /**
     * 获取当前最大尝试次数。
     *
     * @return 最大尝试次数
     */
    public int getMaxAttempts() {
        return maxAttempts;
    }

    /**
     * 设置最大允许的失败尝试次数。
     *
     * @param max 最大次数（1-1000）
     */
    public void setMaxAttempts(int max) {
        this.maxAttempts = Math.max(1, Math.min(max, 1000));
    }

    /**
     * 检查是否允许对指定文件的解密尝试。
     *
     * @param filePath 加密文件路径
     * @return 若允许尝试（未超阈值）返回 true，否则返回 false
     */
    public boolean allowAttempt(String filePath) {
        ensureLoaded();
        String id = computeFileId(filePath);
        if (id == null) {
            return true;  // 无法识别文件时不拦截
        }
        GuardEntry entry = cache.get(id);
        if (entry == null) {
            return true;  // 新文件
        }
        return entry.failCount < maxAttempts;
    }

    /**
     * 记录一次失败的解密尝试。
     *
     * @param filePath 加密文件路径
     */
    public void recordFailure(String filePath) {
        ensureLoaded();
        String id = computeFileId(filePath);
        if (id == null) {
            return;
        }
        GuardEntry entry = cache.computeIfAbsent(id, k -> new GuardEntry(k));
        entry.failCount++;
        entry.lastAttempt = Instant.now().toString();
        save();
    }

    /**
     * 记录一次成功的解密，清零计数器。
     *
     * @param filePath 加密文件路径
     */
    public void recordSuccess(String filePath) {
        ensureLoaded();
        String id = computeFileId(filePath);
        if (id == null) {
            return;
        }
        cache.remove(id);
        save();
    }

    /**
     * 获取指定文件的当前失败次数。
     *
     * @param filePath 加密文件路径
     * @return 失败次数，若文件未记录则返回 0
     */
    public int getFailCount(String filePath) {
        ensureLoaded();
        String id = computeFileId(filePath);
        if (id == null) {
            return 0;
        }
        GuardEntry entry = cache.get(id);
        return entry != null ? entry.failCount : 0;
    }

    /**
     * 重置指定文件的计数器（用户确认继续后调用）。
     *
     * @param filePath 加密文件路径
     */
    public void resetCounter(String filePath) {
        ensureLoaded();
        String id = computeFileId(filePath);
        if (id != null) {
            cache.remove(id);
            save();
        }
    }

    /**
     * 计算文件的唯一标识符（SHA3-256 的前 4096 字节）。
     */
    private String computeFileId(String filePath) {
        try {
            Path path = Path.of(filePath);
            if (!Files.exists(path) || Files.size(path) == 0) {
                return null;
            }
            byte[] sample = new byte[(int) Math.min(SAMPLE_SIZE, Files.size(path))];
            try (InputStream in = Files.newInputStream(path)) {
                int offset = 0;
                while (offset < sample.length) {
                    int n = in.read(sample, offset, sample.length - offset);
                    if (n < 0) {
                        break;
                    }
                    offset += n;
                }
            }
            SHA3Digest sha3 = new SHA3Digest(256);
            sha3.update(sample, 0, sample.length);
            byte[] hash = new byte[32];
            sha3.doFinal(hash, 0);
            return bytesToHex(hash);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 确保数据库已加载。
     */
    private void ensureLoaded() {
        if (!loaded) {
            load();
        }
    }

    /**
     * 从 JSON 文件加载计数器数据。
     */
    private synchronized void load() {
        if (loaded || dbPath == null) {
            return;
        }
        loaded = true;
        if (!Files.exists(dbPath)) {
            return;
        }
        try {
            String json = Files.readString(dbPath, StandardCharsets.UTF_8);
            // 简易 JSON 解析：提取 entries 数组中的每个对象
            parseJson(json);
        } catch (IOException e) {
            // 文件损坏时忽略，从头开始
        }
    }

    /**
     * 简易 JSON 解析器（避免引入外部依赖）。
     */
    private void parseJson(String json) {
        int entriesStart = json.indexOf("\"entries\"");
        if (entriesStart < 0) {
            return;
        }
        int arrayStart = json.indexOf('[', entriesStart);
        if (arrayStart < 0) {
            return;
        }
        int arrayEnd = json.lastIndexOf(']');
        if (arrayEnd < 0 || arrayEnd <= arrayStart) {
            return;
        }

        // 分割每个 entry 对象
        String arrayContent = json.substring(arrayStart + 1, arrayEnd);
        int depth = 0;
        int objStart = -1;
        for (int i = 0; i < arrayContent.length(); i++) {
            char c = arrayContent.charAt(i);
            if (c == '{') {
                if (depth == 0) {
                    objStart = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && objStart >= 0) {
                    String obj = arrayContent.substring(objStart, i + 1);
                    parseEntry(obj);
                    objStart = -1;
                }
            }
        }
    }

    /**
     * 解析单个 entry JSON 对象。
     */
    private void parseEntry(String obj) {
        String fileId = extractString(obj, KEY_FILE_ID);
        int failCount = extractInt(obj, KEY_FAIL_COUNT);
        String firstAttempt = extractString(obj, KEY_FIRST_ATTEMPT);
        String lastAttempt = extractString(obj, KEY_LAST_ATTEMPT);

        if (fileId != null && !fileId.isEmpty()) {
            GuardEntry entry = new GuardEntry(fileId);
            entry.failCount = failCount;
            entry.firstAttempt = firstAttempt != null ? firstAttempt : "";
            entry.lastAttempt = lastAttempt != null ? lastAttempt : "";
            cache.put(fileId, entry);
        }
    }

    /**
     * 将内存数据序列化为 JSON 并写入文件。
     */
    private synchronized void save() {
        if (dbPath == null) {
            return;
        }
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n  \"entries\": [\n");
            boolean first = true;
            for (GuardEntry entry : cache.values()) {
                if (!first) {
                    sb.append(",\n");
                }
                first = false;
                sb.append("    {");
                sb.append("\"fileId\": \"").append(escapeJson(entry.fileId)).append("\", ");
                sb.append("\"failCount\": ").append(entry.failCount).append(", ");
                sb.append("\"firstAttempt\": \"").append(escapeJson(entry.firstAttempt)).append("\", ");
                sb.append("\"lastAttempt\": \"").append(escapeJson(entry.lastAttempt)).append("\"");
                sb.append("}");
            }
            sb.append("\n  ]\n}\n");

            // 原子写入：先写临时文件，再重命名
            Path tmp = dbPath.resolveSibling(dbPath.getFileName() + ".tmp");
            Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8);
            Files.move(tmp, dbPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            // 静默失败：计数器丢失比阻止用户解密更好
        }
    }

    /**
     * 内部计数器条目。
     */
    private static final class GuardEntry {
        final String fileId;
        int failCount;
        String firstAttempt;
        String lastAttempt;

        GuardEntry(String fileId) {
            this.fileId = fileId;
            this.firstAttempt = Instant.now().toString();
            this.lastAttempt = this.firstAttempt;
        }
    }
}
