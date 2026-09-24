package hbnu.project.ergoutreecrypt.version;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 应用版本号解析，供主界面标题、设置与「关于」页显示。
 *
 * <p>版本号的唯一真源是 {@code pom.xml} 的 {@code <version>}：构建时由 Maven 把该值
 * 过滤进 {@code version.properties}，本类只负责在运行时把它读出来，因此无需在界面代码里
 * 重复维护版本字面量。
 *
 * <p>解析按以下优先级回退，结果在首次调用后缓存：
 * <ol>
 *   <li>{@code version.properties} —— 打包后（jar 与 jlink/jpackage 镜像）生效的主路径。</li>
 *   <li>项目根目录的 {@code pom.xml} —— 开发态兜底。资源值缺失、为空，或仍是未被替换的
 *       {@code ${...}} 占位符时启用，避免在未执行资源过滤的环境下显示出占位符。</li>
 *   <li>{@code dev} —— 以上都不可用时的展示值。</li>
 * </ol>
 *
 * <p>如需手动指定固定版本，直接把 {@code version.properties} 的 {@code version} 写成字面量
 * 即可（不含 {@code ${}} 的值不会被资源过滤替换）。
 *
 * @author ErgouTree
 */
public final class AppVersion {

    /**
     * 版本号资源在模块内的路径，按 {@code /} 分隔且不带前导斜杠。
     */
    private static final String RESOURCE = "hbnu/project/ergoutreecrypt/version.properties";

    /**
     * 版本号在资源文件中的键名。
     */
    private static final String KEY = "version";

    /**
     * 从 pom.xml 中提取本项目版本的匹配式。
     *
     * <p>仅匹配紧随本项目 {@code artifactId} 之后的 {@code <version>}，
     * 以免命中依赖与插件的版本声明。
     */
    private static final Pattern POM_VERSION = Pattern.compile(
            "<artifactId>ErgouTreeCrypt</artifactId>\\s*<version>([^<]+)</version>");

    /**
     * 所有来源都不可用时的展示值。
     */
    private static final String UNKNOWN = "dev";

    /**
     * 已解析出的版本号缓存，{@code null} 表示尚未解析。
     */
    private static volatile String cached;

    private AppVersion() {
    }

    /**
     * 返回当前应用版本号。
     *
     * @return 版本号（如 {@code 2.9.5}）；无法确定时为 {@code dev}
     */
    public static String get() {
        String version = cached;
        if (version == null) {
            version = resolve();
            cached = version;
        }
        return version;
    }

    /**
     * 按资源、pom.xml 的顺序解析版本号。
     *
     * @return 解析结果，全部失败时为 {@link #UNKNOWN}
     */
    private static String resolve() {
        String fromResource = readFromResource();
        if (isUsable(fromResource)) {
            return fromResource.trim();
        }
        String fromPom = readFromPom();
        if (isUsable(fromPom)) {
            return fromPom.trim();
        }
        return UNKNOWN;
    }

    /**
     * 判断候选版本值是否可用。
     *
     * @param candidate 候选版本值
     * @return 非空且不含未替换的 {@code ${}} 占位符时为 true
     */
    private static boolean isUsable(String candidate) {
        return candidate != null
                && !candidate.isBlank()
                && !candidate.contains("${");
    }

    /**
     * 读取构建时由 Maven 过滤生成的版本资源。
     *
     * @return 资源中的版本值；资源缺失或读取失败时为 {@code null}
     */
    private static String readFromResource() {
        try (InputStream in = openResource()) {
            if (in == null) {
                return null;
            }
            Properties properties = new Properties();
            try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                properties.load(reader);
            }
            return properties.getProperty(KEY);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 打开模块内的版本资源。
     *
     * <p>本应用是 JPMS 命名模块，而 {@link Class#getResourceAsStream} 对未
     * {@code opens} 的包不生效，因此命名模块下必须改用 {@link Module#getResourceAsStream}；
     * 非命名模块（如以 classpath 方式启动）才走类加载器的查找路径。
     *
     * @return 资源输入流；未找到时为 {@code null}
     * @throws IOException 读取资源失败
     */
    private static InputStream openResource() throws IOException {
        Module module = AppVersion.class.getModule();
        if (module.isNamed()) {
            return module.getResourceAsStream(RESOURCE);
        }
        return AppVersion.class.getResourceAsStream("/" + RESOURCE);
    }

    /**
     * 开发态兜底：从当前工作目录的 pom.xml 中读取本项目版本。
     *
     * @return pom.xml 中声明的版本；文件不存在、格式不符或读取失败时为 {@code null}
     */
    private static String readFromPom() {
        Path pom = Paths.get("pom.xml").toAbsolutePath();
        if (!Files.isRegularFile(pom)) {
            return null;
        }
        try {
            Matcher matcher = POM_VERSION.matcher(Files.readString(pom, StandardCharsets.UTF_8));
            return matcher.find() ? matcher.group(1) : null;
        } catch (IOException e) {
            return null;
        }
    }
}
