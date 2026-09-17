package hbnu.project.ergoutreecrypt.ui.support;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * FXML 与控制器接线测试。
 *
 * <p>{@code FXMLLoader} 只在真正加载界面时才解析 {@code fx:id} 与事件处理器，任何拼写
 * 不一致都要到启动那一刻才会炸。这里用静态解析替代：把每个视图里的 {@code fx:id} 与
 * {@code onXxx="#handler"} 逐个对照控制器的字段与方法，让接线错误在单元测试阶段就暴露。
 *
 * <p>不开启 JavaFX 工具包，因此可在无显示环境（CI）下运行。
 *
 * @author ErgouTree
 */
final class FxmlWiringTest {

    /**
     * 视图资源目录（相对仓库根）。
     */
    private static final Path VIEW_DIR =
            Path.of("src", "main", "resources", "hbnu", "project", "ergoutreecrypt", "ui");

    /**
     * 控制器所在包，用于把 FXML 里的类名解析成 Class。
     */
    private static final String CONTROLLER_PACKAGE = "hbnu.project.ergoutreecrypt.ui.";

    /**
     * 匹配 {@code fx:id="name"}。
     */
    private static final Pattern FX_ID = Pattern.compile("fx:id\\s*=\\s*\"([^\"]+)\"");

    /**
     * 匹配 {@code onSomething="#handler"}（含 {@code onAction} 与拖拽等事件）。
     */
    private static final Pattern HANDLER = Pattern.compile("on[A-Za-z]+\\s*=\\s*\"#([^\"]+)\"");

    /**
     * 匹配 {@code fx:controller="..."}。
     */
    private static final Pattern CONTROLLER = Pattern.compile("fx:controller\\s*=\\s*\"([^\"]+)\"");

    /**
     * 历史遗留的「声明了 fx:id 但控制器不注入」的控件。
     *
     * <p>JavaFX 允许 {@code fx:id} 只作为 FXML 内部的引用锚点（例如被 {@code $id} 引用
     * 的分组、被样式或布局引用的容器），因此这些 id 没有对应字段是合法的。
     * 把它们显式列出，可以让本测试继续拦住「新写错名字的 fx:id」——
     * 拼错的 id 不会报错，只会让控制器字段静默为 null，直到运行时才 NPE。
     */
    private static final Set<String> KNOWN_UNINJECTED_IDS = Set.of(
            "imageOperationGroup", "imageProtectionGroup",
            "minBtn", "closeBtn", "contentScroll", "contentColumn", "segmented",
            "modeGroup", "mediaView", "imageCryptView", "classicalView",
            "stegoView", "fileStegoView");

    /**
     * 每个视图声明的 {@code fx:id} 都必须能在控制器里找到同名字段
     * （{@link #KNOWN_UNINJECTED_IDS} 中的历史遗留项除外）。
     */
    @Test
    void everyFxIdHasAControllerField() throws IOException {
        List<String> problems = new ArrayList<>();
        for (Path fxml : viewFiles()) {
            Class<?> controller = loadController(fxml, problems);
            if (controller == null) {
                continue;
            }
            Set<String> fields = fieldNames(controller);
            for (String id : extract(fxml, FX_ID)) {
                if (fields.contains(id) || KNOWN_UNINJECTED_IDS.contains(id)) {
                    continue;
                }
                problems.add(fxml.getFileName() + " → fx:id=\"" + id
                        + "\" 在 " + controller.getSimpleName() + " 中没有对应字段"
                        + "（若确实只是 FXML 内部锚点，请加入 KNOWN_UNINJECTED_IDS）");
            }
        }
        assertTrue(problems.isEmpty(), "FXML fx:id 与控制器字段不一致：\n" + String.join("\n", problems));
    }

    /**
     * 每个 {@code onXxx="#handler"} 都必须能在控制器里找到同名方法。
     */
    @Test
    void everyHandlerHasAControllerMethod() throws IOException {
        List<String> problems = new ArrayList<>();
        for (Path fxml : viewFiles()) {
            Class<?> controller = loadController(fxml, problems);
            if (controller == null) {
                continue;
            }
            Set<String> methods = methodNames(controller);
            for (String handler : extract(fxml, HANDLER)) {
                if (!methods.contains(handler)) {
                    problems.add(fxml.getFileName() + " → onXxx=\"#" + handler
                            + "\" 在 " + controller.getSimpleName() + " 中没有对应方法");
                }
            }
        }
        assertTrue(problems.isEmpty(), "FXML 事件处理器与控制器方法不一致：\n" + String.join("\n", problems));
    }

    /**
     * 主界面必须保留多文件列表与两个压缩策略开关的接线，防止后续改动无声移除它们。
     */
    @Test
    void mainViewKeepsMultiFileAndCompressionWiring() throws IOException {
        Path mainView = VIEW_DIR.resolve("main-view.fxml");
        assertTrue(Files.exists(mainView), "缺少 main-view.fxml");
        Set<String> ids = new LinkedHashSet<>(extract(mainView, FX_ID));

        for (String required : List.of(
                "fileListCard", "fileListTitleLabel", "fileListMetaLabel",
                "fileListScroll", "fileListBox", "addFilesBtn", "clearFilesBtn",
                "compressCheck", "compressBeforeCheck", "compressAfterCheck",
                "compressFormatCombo", "archivePasswordField")) {
            assertTrue(ids.contains(required),
                    "main-view.fxml 缺少必需的控件 fx:id=\"" + required + "\"");
        }
        assertTrue(extract(mainView, HANDLER).contains("onAddFiles"),
                "多文件列表的「添加文件」按钮必须绑定 onAddFiles");
    }

    // ================================================================
    // 辅助方法
    // ================================================================

    /**
     * 列出视图目录下的全部 FXML 文件。
     *
     * @return FXML 路径列表
     * @throws IOException 列目录失败
     */
    private static List<Path> viewFiles() throws IOException {
        assertTrue(Files.isDirectory(VIEW_DIR), "视图目录不存在：" + VIEW_DIR.toAbsolutePath());
        try (Stream<Path> files = Files.list(VIEW_DIR)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".fxml")).sorted().toList();
        }
    }

    /**
     * 读取 FXML 的 {@code fx:controller} 并加载对应类。
     *
     * @param fxml     FXML 路径
     * @param problems 收集问题的列表
     * @return 控制器类；无 controller 声明或加载失败时返回 null
     */
    private static Class<?> loadController(Path fxml, List<String> problems) throws IOException {
        Set<String> declared = extract(fxml, CONTROLLER);
        if (declared.isEmpty()) {
            return null;
        }
        String simpleName = declared.iterator().next();
        String className = simpleName.contains(".")
                ? simpleName : CONTROLLER_PACKAGE + simpleName;
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            problems.add(fxml.getFileName() + " → 找不到控制器类 " + className);
            return null;
        }
    }

    /**
     * 取某个类（含父类）声明的全部字段名。
     *
     * @param type 类型
     * @return 字段名集合
     */
    private static Set<String> fieldNames(Class<?> type) {
        Set<String> names = new LinkedHashSet<>();
        for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                names.add(f.getName());
            }
        }
        return names;
    }

    /**
     * 取某个类（含父类、含私有）声明的全部方法名。
     *
     * @param type 类型
     * @return 方法名集合
     */
    private static Set<String> methodNames(Class<?> type) {
        Set<String> names = new LinkedHashSet<>();
        for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Method m : c.getDeclaredMethods()) {
                names.add(m.getName());
            }
        }
        return names;
    }

    /**
     * 用给定正则抽取 FXML 中的全部匹配项。
     *
     * @param fxml    FXML 路径
     * @param pattern 正则（须带一个捕获组）
     * @return 捕获到的字符串集合
     * @throws IOException 读取失败
     */
    private static Set<String> extract(Path fxml, Pattern pattern) throws IOException {
        String text = Files.readString(fxml, StandardCharsets.UTF_8);
        Set<String> found = new LinkedHashSet<>();
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            found.add(m.group(1));
        }
        return found;
    }
}
