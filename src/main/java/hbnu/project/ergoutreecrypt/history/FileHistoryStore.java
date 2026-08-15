package hbnu.project.ergoutreecrypt.history;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 基于文件的操作历史存储实现。
 *
 * <p>将历史记录以 JSONL 格式（每行一个 JSON 对象）写入 {@code <目录>/history.jsonl}。
 * 采用手写极简 JSON 编解码，不引入任何序列化库，可在桌面端与移动端（共享核心）通用。
 *
 * <p>行格式（键序固定）：
 * <pre>{@code {"ts":<毫秒>,"type":"<枚举名>","file":"<转义>","path":"<转义>|null","uri":"<转义>|null"}}</pre>
 *
 * <p>健壮性约定：
 * <ul>
 *   <li>读取时逐行容错解析，损坏行、未知枚举值的行会被跳过，不影响其余记录；</li>
 *   <li>记录数量超过 {@link #MAX_RECORDS} 时丢弃最旧记录；</li>
 *   <li>所有方法线程安全（synchronized）。</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
public final class FileHistoryStore implements HistoryStore {

    /** 历史记录数量上限，超出时丢弃最旧记录 */
    static final int MAX_RECORDS = 500;

    /** 历史文件名 */
    private static final String FILE_NAME = "history.jsonl";

    /** 存储目录 */
    private final Path dir;

    /**
     * 构造基于文件的历史存储。
     *
     * @param dir 存储目录（不存在时自动创建），不允许为 null
     */
    public FileHistoryStore(Path dir) {
        this.dir = dir;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void record(OperationRecord record) {
        Path file = dir.resolve(FILE_NAME);
        try {
            Files.createDirectories(dir);
            // 使用 Iterable 重载：Files.writeString 在 Android 端不可用
            Files.write(file, List.of(encode(record) + "\n"), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            trimIfNeeded(file);
        } catch (IOException ignored) {
            // 历史记录写入失败不影响主加解密流程，静默忽略
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized List<OperationRecord> list() {
        Path file = dir.resolve(FILE_NAME);
        if (!Files.isRegularFile(file)) {
            return List.of();
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException ignored) {
            return List.of();
        }
        List<OperationRecord> records = new ArrayList<>(lines.size());
        for (int i = lines.size() - 1; i >= 0; i--) {
            OperationRecord record = decode(lines.get(i));
            if (record != null) {
                records.add(record);
            }
        }
        return List.copyOf(records);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void clear() {
        try {
            Files.deleteIfExists(dir.resolve(FILE_NAME));
        } catch (IOException ignored) {
            // 删除失败时保留旧数据，下次清空仍可重试
        }
    }

    /**
     * 记录数超过上限时重写文件，仅保留最新的 {@link #MAX_RECORDS} 条。
     *
     * @param file 历史文件路径
     */
    private void trimIfNeeded(Path file) {
        List<OperationRecord> records = list();
        if (records.size() <= MAX_RECORDS) {
            return;
        }
        // list() 为最新在前；文件需保持最旧在前的追加序，故倒序写入
        List<String> lines = new ArrayList<>(MAX_RECORDS);
        for (int i = MAX_RECORDS - 1; i >= 0; i--) {
            lines.add(encode(records.get(i)));
        }
        try {
            Files.write(file, lines, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException ignored) {
            // 裁剪失败时保留原文件，仅影响记录上限约束
        }
    }

    /**
     * 将记录编码为一行 JSON 对象。
     *
     * @param record 记录，不允许为 null
     * @return JSON 行文本（不含换行符）
     */
    private static String encode(OperationRecord record) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("{\"ts\":").append(record.timestampEpochMillis());
        sb.append(",\"type\":\"").append(record.type().name()).append('"');
        sb.append(",\"file\":").append(quote(record.fileName()));
        sb.append(",\"path\":").append(quoteOrNull(record.outputPath()));
        sb.append(",\"uri\":").append(quoteOrNull(record.outputUri()));
        sb.append('}');
        return sb.toString();
    }

    /**
     * 将字符串编码为 JSON 字符串字面量（含双引号）。
     *
     * @param value 原始字符串，可为 null
     * @return JSON 字符串字面量；value 为 null 时返回 {@code "null"}
     */
    private static String quoteOrNull(String value) {
        return value == null ? "null" : quote(value);
    }

    /**
     * 将字符串编码为带转义的 JSON 字符串字面量。
     *
     * @param value 原始字符串，不允许为 null
     * @return 含双引号与转义序列的 JSON 字符串字面量
     */
    private static String quote(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * 将一行 JSON 文本解析为历史记录。
     *
     * <p>解析失败（损坏行、缺少字段、未知枚举值、非法数字）时返回 null，
     * 调用方跳过该行即可。
     *
     * @param line 单行 JSON 文本，可为 null
     * @return 解析出的记录；解析失败返回 null
     */
    private static OperationRecord decode(String line) {
        Map<String, String> fields = parseJsonObject(line);
        if (fields == null) {
            return null;
        }
        try {
            long ts = Long.parseLong(fields.getOrDefault("ts", ""));
            OperationType type = OperationType.valueOf(fields.getOrDefault("type", ""));
            String file = fields.get("file");
            if (file == null || file.isEmpty()) {
                return null;
            }
            return new OperationRecord(file, fields.get("path"), fields.get("uri"), type, ts);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    /**
     * 极简 JSON 对象解析器：仅支持一层平铺对象，
     * 值为字符串、数字或 null（与本存储的写入格式一一对应）。
     *
     * <p>解析器逐字符扫描并正确处理字符串转义，
     * 值中包含键名或引号等特殊字符不会导致误解析。
     *
     * @param line 待解析文本
     * @return 键值映射（null 值以键存在、值为 null 表示）；解析失败返回 null
     */
    private static Map<String, String> parseJsonObject(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        Map<String, String> map = new HashMap<>();
        int i = skipWhitespace(line, 0);
        if (i >= line.length() || line.charAt(i) != '{') {
            return null;
        }
        i++;
        while (true) {
            i = skipWhitespace(line, i);
            if (i < line.length() && line.charAt(i) == '}') {
                return map;
            }
            int keyEnd = findStringEnd(line, i);
            if (keyEnd < 0) {
                return null;
            }
            String key = unescape(line.substring(i + 1, keyEnd));
            i = skipWhitespace(line, keyEnd + 1);
            if (i >= line.length() || line.charAt(i) != ':') {
                return null;
            }
            i = skipWhitespace(line, i + 1);
            String value;
            if (i < line.length() && line.charAt(i) == '"') {
                int valueEnd = findStringEnd(line, i);
                if (valueEnd < 0) {
                    return null;
                }
                value = unescape(line.substring(i + 1, valueEnd));
                i = skipWhitespace(line, valueEnd + 1);
            } else if (line.startsWith("null", i)) {
                value = null;
                i = skipWhitespace(line, i + 4);
            } else {
                int end = i;
                while (end < line.length() && (Character.isDigit(line.charAt(end))
                        || line.charAt(end) == '-')) {
                    end++;
                }
                if (end == i) {
                    return null;
                }
                value = line.substring(i, end);
                i = skipWhitespace(line, end);
            }
            map.put(key, value);
            if (i < line.length() && line.charAt(i) == ',') {
                i++;
                continue;
            }
            if (i < line.length() && line.charAt(i) == '}') {
                return map;
            }
            return null;
        }
    }

    /**
     * 定位 JSON 字符串字面量的结束引号。
     *
     * @param text  文本
     * @param start 起始引号下标（必须指向 {@code "}）
     * @return 结束引号下标；未找到返回 -1
     */
    private static int findStringEnd(String text, int start) {
        if (start >= text.length() || text.charAt(start) != '"') {
            return -1;
        }
        for (int i = start + 1; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\') {
                i++;
                continue;
            }
            if (c == '"') {
                return i;
            }
        }
        return -1;
    }

    /**
     * 反转义 JSON 字符串内容（不含首尾引号）。
     *
     * @param value 转义后的字符串内容
     * @return 反转义后的原始字符串
     */
    private static String unescape(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) {
                sb.append(c);
                continue;
            }
            char next = value.charAt(++i);
            switch (next) {
                case '"' -> sb.append('"');
                case '\\' -> sb.append('\\');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (i + 4 < value.length()) {
                        try {
                            sb.append((char) Integer.parseInt(value.substring(i + 1, i + 5), 16));
                            i += 4;
                        } catch (NumberFormatException ignored) {
                            sb.append(next);
                        }
                    } else {
                        sb.append(next);
                    }
                }
                default -> sb.append(next);
            }
        }
        return sb.toString();
    }

    /**
     * 跳过空白字符（空格、制表符、换行、回车）。
     *
     * @param text  文本
     * @param start 起始下标
     * @return 首个非空白字符下标
     */
    private static int skipWhitespace(String text, int start) {
        int i = start;
        while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
            i++;
        }
        return i;
    }
}
