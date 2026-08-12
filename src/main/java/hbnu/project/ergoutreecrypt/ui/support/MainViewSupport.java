package hbnu.project.ergoutreecrypt.ui.support;

import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.util.Duration;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 主界面控制器的无状态辅助工具集合。
 *
 * <p>集中存放与 UI 控件绑定无关的纯函数式逻辑（提示气泡安装、路径转换、
 * 异常判定、默认输出名推导、默认钓鱼文件解包），以减小主控制器体积、
 * 提升可测试性。所有方法均为静态且不持有任何 UI 状态。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class MainViewSupport {

    /** 默认钓鱼文件在资源目录中的路径。 */
    private static final String DEFAULT_DECOY_RESOURCE =
            "/other/2025年高考全国一卷语文高考真题文档版（含答案）.zip";

    private MainViewSupport() {
    }

    /**
     * 为 ⓘ 图标标签安装统一样式的提示气泡。
     *
     * <p>直接安装到节点，比 {@code Label.setTooltip} 更稳定地响应 hover。
     *
     * @param label 目标标签（为 null 时忽略）
     * @param text  提示文案
     */
    public static void installTooltip(final Label label, final String text) {
        if (label == null) {
            return;
        }
        Tooltip tip = new Tooltip(text);
        tip.getStyleClass().add("info-tooltip");
        tip.setShowDelay(Duration.millis(120));
        tip.setShowDuration(Duration.seconds(20));
        tip.setHideDelay(Duration.millis(120));
        tip.setWrapText(true);
        tip.setMaxWidth(300);
        Tooltip.install(label, tip);
        label.setTooltip(tip);
    }

    /**
     * 将文件列表转换为绝对路径字符串列表。
     *
     * @param files 文件列表
     * @return 绝对路径列表
     */
    public static List<String> toPaths(final List<File> files) {
        List<String> paths = new ArrayList<>(files.size());
        for (File f : files) {
            paths.add(f.getAbsolutePath());
        }
        return paths;
    }

    /**
     * 判断异常是否与加密/密码相关（ZIP 加密条目、AES 封装等）。
     *
     * @param t 待判定异常
     * @return true 表示异常与加密/密码相关
     */
    public static boolean isEncryptionRelated(final Throwable t) {
        if (t == null) {
            return false;
        }
        String msg = t.getMessage();
        if (msg == null) {
            msg = "";
        }
        String lower = msg.toLowerCase();
        return lower.contains("encrypt") || lower.contains("password")
                || lower.contains("unsupported compression method")
                || lower.contains("unsupported feature");
    }

    /**
     * 依据输入文件名推导单文件解密的默认输出路径。
     *
     * <p>去除 {@code .ergou} / {@code .pcv} 扩展名；其它情况追加 {@code .decrypted}。
     *
     * @param in 输入文件绝对路径
     * @return 默认输出路径
     */
    public static String deriveDecryptOutput(final String in) {
        String lower = in.toLowerCase();
        if (lower.endsWith(".ergou")) {
            return in.substring(0, in.length() - ".ergou".length());
        }
        if (lower.endsWith(".pcv")) {
            return in.substring(0, in.length() - ".pcv".length());
        }
        return in + ".decrypted";
    }

    /**
     * 将内置的默认钓鱼文件解包到临时目录并返回其绝对路径。
     *
     * @return 临时钓鱼文件的绝对路径；资源缺失或复制失败时返回 null
     */
    public static String extractDefaultDecoyFile() {
        try {
            Path tmp = Files.createTempFile("ergou_decoy_", ".zip");
            try (InputStream in = MainViewSupport.class.getResourceAsStream(DEFAULT_DECOY_RESOURCE)) {
                if (in == null) {
                    return null;
                }
                Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
            }
            return tmp.toAbsolutePath().toString();
        } catch (IOException ignored) {
            return null;
        }
    }
}
