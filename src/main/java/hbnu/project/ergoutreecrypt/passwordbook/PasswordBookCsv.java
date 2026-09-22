package hbnu.project.ergoutreecrypt.passwordbook;

import java.io.IOException;
import java.io.Reader;
import java.io.PushbackReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/**
 * 密码本 CSV 的读取与写入工具。
 *
 * <p>格式固定为两列 {@code name,password}，支持引号、逗号和多行字段。
 *
 * @author ErgouTree
 * @since 2026/9/22
 */
public final class PasswordBookCsv {

    private static final String HEADER_NAME = "name";
    private static final String HEADER_PASSWORD = "password";

    private PasswordBookCsv() {
    }

    /**
     * 将密码记录写为 CSV。
     *
     * @param entries 待写入记录
     * @param writer  目标字符流
     * @throws IOException 写入失败时抛出
     */
    public static void write(List<PasswordBookEntry> entries, Writer writer) throws IOException {
        writeRow(writer, HEADER_NAME, HEADER_PASSWORD);
        for (PasswordBookEntry entry : entries) {
            if (entry == null || entry.getName().isBlank()) {
                continue;
            }
            writeRow(writer, entry.getName(), entry.getPassword());
        }
    }

    /**
     * 将密码记录编码为 CSV 文本。
     *
     * @param entries 待编码记录
     * @return CSV 文本
     */
    public static String encode(List<PasswordBookEntry> entries) {
        StringWriter writer = new StringWriter();
        try {
            write(entries, writer);
        } catch (IOException impossible) {
            throw new IllegalStateException("StringWriter 写入失败", impossible);
        }
        return writer.toString();
    }

    /**
     * 从 CSV 字符流读取密码记录。
     *
     * @param reader CSV 字符流
     * @return 有效密码记录列表
     * @throws IOException 读取失败或 CSV 格式不完整时抛出
     */
    public static List<PasswordBookEntry> read(Reader reader) throws IOException {
        List<List<String>> rows = parseRows(reader);
        int start = hasHeader(rows) ? 1 : 0;
        List<PasswordBookEntry> result = new ArrayList<>();
        for (int index = start; index < rows.size(); index++) {
            List<String> row = rows.get(index);
            if (row.size() < 2 || row.get(0).isBlank()) {
                continue;
            }
            result.add(new PasswordBookEntry(row.get(0), row.get(1)));
        }
        return List.copyOf(result);
    }

    /**
     * 从 CSV 文本读取密码记录。
     *
     * @param csv CSV 文本
     * @return 有效密码记录列表
     * @throws IOException CSV 格式不完整时抛出
     */
    public static List<PasswordBookEntry> decode(String csv) throws IOException {
        return read(new StringReader(csv == null ? "" : csv));
    }

    /**
     * 写入一行 CSV。
     *
     * @param writer   目标字符流
     * @param name     名称字段
     * @param password 密码字段
     * @throws IOException 写入失败时抛出
     */
    private static void writeRow(Writer writer, String name, String password) throws IOException {
        writer.write(escape(name));
        writer.write(',');
        writer.write(escape(password));
        writer.write("\r\n");
    }

    /**
     * 转义单个 CSV 字段。
     *
     * @param value 原字段值
     * @return 转义后的字段
     */
    private static String escape(String value) {
        String safe = value == null ? "" : value;
        if (safe.indexOf(',') < 0 && safe.indexOf('"') < 0
                && safe.indexOf('\r') < 0 && safe.indexOf('\n') < 0) {
            return safe;
        }
        return '"' + safe.replace("\"", "\"\"") + '"';
    }

    /**
     * 解析全部 CSV 行。
     *
     * @param reader CSV 字符流
     * @return 字段矩阵
     * @throws IOException 读取失败或引号未闭合时抛出
     */
    private static List<List<String>> parseRows(Reader reader) throws IOException {
        PushbackReader input = reader instanceof PushbackReader pushback
                ? pushback : new PushbackReader(reader, 1);
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        int current;
        while ((current = input.read()) != -1) {
            char ch = (char) current;
            if (quoted) {
                if (ch == '"') {
                    int next = input.read();
                    if (next == '"') {
                        field.append('"');
                    } else {
                        quoted = false;
                        if (next != -1) {
                            input.unread(next);
                        }
                    }
                } else {
                    field.append(ch);
                }
            } else if (ch == '"' && field.isEmpty()) {
                quoted = true;
            } else if (ch == ',') {
                row.add(field.toString());
                field.setLength(0);
            } else if (ch == '\n') {
                row.add(stripCarriageReturn(field));
                rows.add(List.copyOf(row));
                row.clear();
                field.setLength(0);
            } else {
                field.append(ch);
            }
        }
        if (quoted) {
            throw new IOException("CSV 字段引号未闭合");
        }
        if (!row.isEmpty() || !field.isEmpty()) {
            row.add(stripCarriageReturn(field));
            rows.add(List.copyOf(row));
        }
        return rows;
    }

    /**
     * 去除行结束符中的回车字符。
     *
     * @param field 当前字段缓冲区
     * @return 清理后的字段值
     */
    private static String stripCarriageReturn(StringBuilder field) {
        int length = field.length();
        if (length > 0 && field.charAt(length - 1) == '\r') {
            return field.substring(0, length - 1);
        }
        return field.toString();
    }

    /**
     * 判断首行是否为标准表头。
     *
     * @param rows 已解析行
     * @return 首行为标准表头时返回 true
     */
    private static boolean hasHeader(List<List<String>> rows) {
        if (rows.isEmpty() || rows.get(0).size() < 2) {
            return false;
        }
        String first = rows.get(0).get(0);
        if (!first.isEmpty() && first.charAt(0) == '\ufeff') {
            first = first.substring(1);
        }
        return HEADER_NAME.equalsIgnoreCase(first.trim())
                && HEADER_PASSWORD.equalsIgnoreCase(rows.get(0).get(1).trim());
    }
}
