package hbnu.project.ergoutreecrypt.ui.support;

import javafx.css.CssParser;
import javafx.css.ParsedValue;
import javafx.css.Rule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/** 验证主题模块的入口、级联顺序和 JAR 内相对导入；不依赖图形环境。 */
class StylesheetTest {
    private static final String RESOURCE_ROOT = "hbnu/project/ergoutreecrypt/ui/styles/";
    private static final Pattern IMPORT = Pattern.compile("@import\\s+\"([^\"]+)\";");
    private static final List<String> MODULES = List.of(
            "win11/00-foundation.css",
            "win11/01-window-navigation.css",
            "win11/02-containers.css",
            "win11/03-input-controls.css",
            "win11/04-selection-controls.css",
            "win11/05-feedback-content.css",
            "win11/06-controlsfx.css",
            "win11/07-dialogs-data-views.css",
            "win11/08-utilities.css",
            "win11/09-log-about.css",
            "win11/10-password-book-settings.css");

    /** 统一入口只按固定顺序导入完整模块，不额外引入覆盖规则或重复模块。 */
    @Test
    void entryPreservesModuleOrderAndResources() throws IOException {
        String entry = read(resource("win11.css")).replaceAll("(?s)/\\*.*?\\*/", "");
        List<String> imports = IMPORT.matcher(entry).results().map(match -> match.group(1)).toList();
        assertEquals(MODULES, imports);
        assertTrue(IMPORT.matcher(entry).replaceAll("").isBlank());
        for (String module : imports) {
            String content = read(resource(module));
            assertFalse(content.isBlank(), module);
            assertFalse(IMPORT.matcher(content).find(), "模块不应嵌套导入：" + module);
        }
    }

    /** JavaFX 解析导入后的规则与按相同顺序拼接的单文件规则逐条一致。 */
    @Test
    void importsPreserveAllRulesAndCascadeOrder() throws IOException {
        List<Rule> expected = flattenedRules();
        assertFalse(expected.isEmpty());
        assertRulesEqual(expected, parsedRules(resource("win11.css")));
    }

    /**
     * 模拟发行 JAR，验证入口在归档内仍能加载所有相对路径模块。
     *
     * @param directory 隔离的临时目录
     * @throws IOException 创建归档或读取样式失败
     */
    @Test
    void importsResolveInsideJar(@TempDir Path directory) throws IOException {
        Path jar = directory.resolve("theme.jar");
        List<String> resources = new ArrayList<>();
        resources.add("win11.css");
        resources.addAll(MODULES);
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            for (String name : resources) {
                output.putNextEntry(new JarEntry(RESOURCE_ROOT + name));
                try (var input = resource(name).openStream()) {
                    input.transferTo(output);
                }
                output.closeEntry();
            }
        }
        URL entry = URI.create("jar:" + jar.toUri() + "!/" + RESOURCE_ROOT + "win11.css").toURL();
        boolean useCaches = URLConnection.getDefaultUseCaches("jar");
        try {
            // 避免 JAR URL 缓存在 Windows 上阻止临时归档清理，随后恢复原值。
            URLConnection.setDefaultUseCaches("jar", false);
            assertRulesEqual(flattenedRules(), parsedRules(entry));
        } finally {
            URLConnection.setDefaultUseCaches("jar", useCaches);
        }
    }

    /**
     * 逐条对比规则，失败时仅输出首条不一致的规则。
     *
     * @param expected 单文件参照规则
     * @param actual 实际导入规则
     */
    private static void assertRulesEqual(List<Rule> expected, List<Rule> actual) {
        assertEquals(expected.size(), actual.size(), "样式规则数量不同");
        for (int index = 0; index < expected.size(); index++) {
            Rule reference = expected.get(index);
            Rule imported = actual.get(index);
            String context = "第 " + index + " 条规则：" + reference.getSelectors();
            assertEquals(reference.getSelectors().toString(), imported.getSelectors().toString(), context);
            assertEquals(reference.getDeclarations().size(), imported.getDeclarations().size(), context);
            for (int declaration = 0; declaration < reference.getDeclarations().size(); declaration++) {
                var left = reference.getDeclarations().get(declaration);
                var right = imported.getDeclarations().get(declaration);
                assertEquals(left.getProperty(), right.getProperty(), context);
                assertEquals(left.isImportant(), right.isImportant(), context);
                assertEquals(valueTree(left.getParsedValue()), valueTree(right.getParsedValue()),
                        context + "，属性：" + left.getProperty());
            }
        }
    }

    /**
     * 递归展开解析值，避免数组默认字符串中的对象地址干扰等价比较。
     *
     * @param value 解析值、嵌套数组或标量
     * @return 包含转换器类型、查找标志和实际数值的可比较结构
     */
    private static Object valueTree(Object value) {
        if (value instanceof ParsedValue<?, ?> parsed) {
            return Arrays.asList(parsed.getConverter() == null ? null : parsed.getConverter().getClass(),
                    parsed.isLookup(), parsed.isContainsLookups(), valueTree(parsed.getValue()));
        }
        if (value instanceof Object[] array) {
            return Arrays.stream(array).map(StylesheetTest::valueTree).toList();
        }
        return value;
    }

    /**
     * 拼接模块并解析，作为保持原始级联顺序的单文件参照。
     *
     * @return 包含选择器及声明解析值的全部规则
     * @throws IOException 资源读取失败
     */
    private static List<Rule> flattenedRules() throws IOException {
        StringBuilder flat = new StringBuilder();
        for (String module : MODULES) {
            flat.append(read(resource(module))).append('\n');
        }
        int errorCount = CssParser.errorsProperty().size();
        List<Rule> rules = new CssParser().parse(flat.toString()).getRules();
        assertEquals(errorCount, CssParser.errorsProperty().size(),
                () -> "JavaFX CSS 解析失败：" + CssParser.errorsProperty());
        return rules;
    }

    /**
     * 通过 JavaFX 自身解析器加载入口，检查语法及相对导入错误。
     *
     * @param entry 样式入口 URL
     * @return 保持顺序的规则列表
     * @throws IOException 资源读取失败
     */
    private static List<Rule> parsedRules(URL entry) throws IOException {
        int errorCount = CssParser.errorsProperty().size();
        List<Rule> rules = new CssParser().parse(entry).getRules();
        assertEquals(errorCount, CssParser.errorsProperty().size(),
                () -> "JavaFX CSS 解析失败：" + CssParser.errorsProperty());
        return rules;
    }

    /**
     * 获取打包后的主题资源地址。
     *
     * @param name 相对于主题目录的路径
     * @return 非空资源 URL
     */
    private static URL resource(String name) {
        URL url = StylesheetTest.class.getResource("/" + RESOURCE_ROOT + name);
        assertNotNull(url, "缺少主题资源：" + name);
        return url;
    }

    /**
     * 读取资源文本并关闭输入流。
     *
     * @param url 资源地址
     * @return UTF-8 文本
     * @throws IOException 资源读取失败
     */
    private static String read(URL url) throws IOException {
        try (var input = url.openStream()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
