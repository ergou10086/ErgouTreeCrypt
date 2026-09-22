package hbnu.project.ergoutreecrypt.passwordbook;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 密码本 CSV 编解码测试。
 */
class PasswordBookCsvTest {

    /**
     * 验证逗号、引号和换行能够无损往返。
     *
     * @throws IOException CSV 解析失败时抛出
     */
    @Test
    void roundTripsEscapedFields() throws IOException {
        List<PasswordBookEntry> expected = List.of(
                new PasswordBookEntry("常用,密码", "er\"gou"),
                new PasswordBookEntry("多行\n名称", "line1\nline2"));

        assertEquals(expected, PasswordBookCsv.decode(PasswordBookCsv.encode(expected)));
    }

    /**
     * 验证兼容没有表头的两列 CSV。
     *
     * @throws IOException CSV 解析失败时抛出
     */
    @Test
    void readsCsvWithoutHeader() throws IOException {
        List<PasswordBookEntry> entries = PasswordBookCsv.decode("常用密码,ergou\r\n");

        assertEquals(List.of(new PasswordBookEntry("常用密码", "ergou")), entries);
    }
}
