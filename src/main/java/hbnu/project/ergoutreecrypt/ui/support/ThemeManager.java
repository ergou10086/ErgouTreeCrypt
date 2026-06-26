package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import javafx.application.Platform;
import javafx.scene.Parent;
import javafx.scene.Scene;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 主题管理器，支持浅色/深色双主题及跟随 Windows 系统主题自动切换。
 *
 * <p>通过给场景根节点切换 {@code light} / {@code dark} 样式类来驱动 CSS 变量，
 * 单一样式表 {@code win11.css} 内用 {@code .root.light} / {@code .root.dark}
 * 选择器覆盖，做到一次加载、即时切换。
 *
 * <p>三种主题模式：
 * <ul>
 *   <li>{@code SYSTEM} — 检测 Windows 注册表中的深浅色设置，自动跟随</li>
 *   <li>{@code LIGHT} — 始终使用浅色主题</li>
 *   <li>{@code DARK} — 始终使用深色主题</li>
 * </ul>
 *
 * <p>当处于 {@code SYSTEM} 模式时，后台线程每隔 2 秒轮询注册表
 * {@code HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme}，
 * 检测到变化后自动切换根节点样式类。
 *
 * @author ErgouTree
 */
public final class ThemeManager {

    /** 主题模式枚举。 */
    public enum Mode {
        /** 跟随 Windows 系统主题自动切换。 */
        SYSTEM,
        /** 始终浅色。 */
        LIGHT,
        /** 始终深色。 */
        DARK
    }

    private static final String STYLESHEET = "/hbnu/project/ergoutreecrypt/ui/styles/win11.css";

    /** 注册表轮询间隔 (秒)。 */
    private static final int POLL_INTERVAL_SEC = 2;

    /**
     * 当前实际生效的主题（浅色或深色）。
     * {@code Mode.SYSTEM} 不是实际的视觉主题，仅表示自动检测。
     */
    public enum Theme {LIGHT, DARK}

    /** 样式表是否已加载到场景，防止重复加载。 */
    private boolean stylesheetLoaded;

    private Mode mode;
    private Theme current;
    private Scene scene;
    private ScheduledExecutorService poller;

    public ThemeManager() {
        String saved = SettingsManager.getThemeMode();
        this.mode = parseMode(saved);
        this.current = Theme.LIGHT;
    }

    /**
     * 绑定场景，加载样式表并应用初始主题。
     *
     * @param scene JavaFX 场景
     */
    public void attach(Scene scene) {
        this.scene = Objects.requireNonNull(scene, "scene must not be null");
        if (!stylesheetLoaded) {
            URL css = Objects.requireNonNull(
                    ThemeManager.class.getResource(STYLESHEET),
                    "Missing stylesheet: " + STYLESHEET);
            scene.getStylesheets().add(css.toExternalForm());
            stylesheetLoaded = true;
        }
        applyMode();
    }

    // ---- 模式管理 ----

    /** 获取当前主题模式。 */
    public Mode getMode() {
        return mode;
    }

    /**
     * 设置主题模式并持久化。
     *
     * @param newMode 新模式
     */
    public void setMode(Mode newMode) {
        if (newMode == null) {
            return;
        }
        Mode old = this.mode;
        this.mode = newMode;
        SettingsManager.setThemeMode(newMode.name());
        if (newMode != old) {
            applyMode();
        }
    }

    // ---- 当前视觉主题 ----

    /** 获取当前实际生效的视觉主题。 */
    public Theme getCurrent() {
        return current;
    }

    /** 当前是否为深色主题。 */
    public boolean isDark() {
        return current == Theme.DARK;
    }

    /**
     * 在浅色 / 深色之间手动切换。
     * 如果当前为 {@code SYSTEM} 模式，调用此方法将自动切换到对应的固定模式。
     */
    public void toggle() {
        if (mode == Mode.SYSTEM) {
            // 从系统模式切换到固定模式：锚定到当前实际视觉主题的相反值
            setMode(current == Theme.LIGHT ? Mode.DARK : Mode.LIGHT);
        } else {
            setMode(mode == Mode.LIGHT ? Mode.DARK : Mode.LIGHT);
        }
    }

    // ---- 内部实现 ----

    /** 根据当前 mode 确定实际视觉主题并应用。 */
    private void applyMode() {
        switch (mode) {
            case LIGHT -> {
                stopPolling();
                apply(Theme.LIGHT);
            }
            case DARK -> {
                stopPolling();
                apply(Theme.DARK);
            }
            case SYSTEM -> {
                apply(detectSystemTheme());
                startPolling();
            }
        }
    }

    /** 应用视觉主题到场景根节点及所有已打开的窗口。 */
    private void apply(Theme t) {
        this.current = t;
        if (scene == null || scene.getRoot() == null) {
            return;
        }
        // 更新主场景根节点及所有已知窗口（包括弹出窗口如 ComboBox popup / ContextMenu）
        for (javafx.stage.Window w : javafx.stage.Window.getWindows()) {
            if (w.getScene() != null && w.getScene().getRoot() != null) {
                updateRootClass(w.getScene().getRoot(), t);
            }
        }
        // 确保场景根节点也被更新（可能不在 Window.getWindows() 中）
        updateRootClass(scene.getRoot(), t);
    }

    /** 给指定根节点的样式类添加/移除 light 和 dark。 */
    private static void updateRootClass(javafx.scene.Parent root, Theme t) {
        var classes = root.getStyleClass();
        classes.removeAll("light", "dark");
        classes.add(t == Theme.DARK ? "dark" : "light");
    }

    // ---- 系统主题检测 ----

    /**
     * 通过读取 Windows 注册表检测当前系统深浅色模式。
     *
     * <p>键路径：
     * {@code HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme}
     * <ul>
     *   <li>{@code 0x1} (或含 "0x1") → 浅色模式</li>
     *   <li>{@code 0x0} (或含 "0x0") → 深色模式</li>
     * </ul>
     *
     * @return 系统主题
     */
    private static Theme detectSystemTheme() {
        try {
            Process proc = Runtime.getRuntime().exec(
                    "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"
                            + " /v AppsUseLightTheme");
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("0x0")) {
                        // 深色模式
                        return Theme.DARK;
                    }
                    if (line.contains("0x1")) {
                        // 浅色模式
                        return Theme.LIGHT;
                    }
                }
            }
            proc.waitFor();
        } catch (Exception ignored) {
            // 非 Windows 系统或注册表读取失败，回退到浅色
        }
        return Theme.LIGHT;
    }

    /**
     * 启动后台轮询线程，定时检测系统主题变化。
     * 仅在 {@code SYSTEM} 模式下调用。
     */
    private synchronized void startPolling() {
        stopPolling();
        poller = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "theme-poller");
            t.setDaemon(true);
            return t;
        });
        poller.scheduleWithFixedDelay(() -> {
            if (mode != Mode.SYSTEM) {
                stopPolling();
                return;
            }
            Theme sys = detectSystemTheme();
            if (sys != current) {
                Platform.runLater(() -> {
                    // 再次检查 mode 未变（可能在 runLater 排队期间被切换）
                    if (mode == Mode.SYSTEM) {
                        apply(sys);
                    }
                });
            }
        }, POLL_INTERVAL_SEC, POLL_INTERVAL_SEC, TimeUnit.SECONDS);
    }

    /** 停止后台轮询线程。 */
    private synchronized void stopPolling() {
        if (poller != null && !poller.isShutdown()) {
            poller.shutdownNow();
            poller = null;
        }
    }

    // ---- 工具 ----

    /**
     * 关闭管理器，释放后台资源。
     * 在应用退出前调用，确保轮询线程被终止。
     */
    public void shutdown() {
        stopPolling();
    }

    private static Mode parseMode(String s) {
        if ("DARK".equalsIgnoreCase(s)) {
            return Mode.DARK;
        }
        if ("LIGHT".equalsIgnoreCase(s)) {
            return Mode.LIGHT;
        }
        return Mode.SYSTEM;
    }
}
