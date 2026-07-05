package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.util.Duration;

/**
 * 设置对话框，通过菜单栏"设置 → 打开设置..."打开。
 *
 * <p>包含解密设置、加密默认值、行为设置及主题模式选择。
 * 主题修改即时生效，其他设置通过 {@link SettingsManager} 持久化。
 *
 * @author ErgouTree
 * @since 2026/6/23
 */
public final class SettingsDialog {

    private SettingsDialog() {}

    /**
     * 显示设置对话框。
     *
     * @param owner        父窗口
     * @param themeManager 主题管理器，用于实时响应主题模式变更
     */
    public static void show(javafx.stage.Window owner, ThemeManager themeManager) {
        Dialog<Void> dialog = new Dialog<>();
        dialog.initOwner(owner);
        dialog.setTitle(Messages.get("settings.title"));
        dialog.setHeaderText(null);

        DialogPane pane = dialog.getDialogPane();

        // ---- 继承主窗口主题：CSS 变量定义在 .root.light / .root.dark 上 ----
        pane.getStyleClass().add("root");
        if (owner != null && owner.getScene() != null) {
            javafx.scene.Scene ownerScene = owner.getScene();
            for (String cls : ownerScene.getRoot().getStyleClass()) {
                if ("light".equals(cls) || "dark".equals(cls)) {
                    pane.getStyleClass().add(cls);
                    break;
                }
            }
            if (!pane.getStyleClass().contains("light") && !pane.getStyleClass().contains("dark")) {
                pane.getStyleClass().add("light");
            }
        } else {
            pane.getStyleClass().add("light");
        }

        // 加载样式表
        pane.getStylesheets().add(
                SettingsDialog.class.getResource(
                        "/hbnu/project/ergoutreecrypt/ui/styles/win11.css").toExternalForm());

        // ---- 内容区 ----
        GridPane grid = new GridPane();
        grid.setHgap(16);
        grid.setVgap(12);
        grid.setPadding(new Insets(20, 24, 12, 24));

        int row = 0;

        // === 主题 ===
        grid.add(section(Messages.get("settings.section.theme")), 0, row++, 3, 1);

        ComboBox<String> themeCombo = new ComboBox<>();
        themeCombo.getItems().setAll(
                Messages.get("theme.system"),
                Messages.get("theme.light"),
                Messages.get("theme.dark"));
        themeCombo.setPrefWidth(160);
        HBox themeBox = new HBox(8,
                new Label(Messages.get("theme.mode") + ":"), themeCombo);
        themeBox.setAlignment(Pos.CENTER_LEFT);
        grid.add(themeBox, 0, row++, 3, 1);

        // === 解密 ===
        grid.add(section(Messages.get("settings.section.decrypt")), 0, row++, 3, 1);

        CheckBox autoDecompress = checkBox(Messages.get("settings.autoDecompress"));
        grid.add(autoDecompress, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.autoDecompress.tip")), 2, row);
        row++;

        CheckBox confirmOverwrite = checkBox(Messages.get("settings.confirmOverwrite"));
        grid.add(confirmOverwrite, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.confirmOverwrite.tip")), 2, row);
        row++;

        // === 加密默认值 ===
        grid.add(section(Messages.get("settings.section.encrypt")), 0, row++, 3, 1);

        CheckBox defaultPasswordless = checkBox(Messages.get("settings.defaultPasswordless"));
        grid.add(defaultPasswordless, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.defaultPasswordless.tip")), 2, row);
        row++;

        CheckBox defaultParanoid = checkBox(Messages.get("settings.defaultParanoid"));
        grid.add(defaultParanoid, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.defaultParanoid.tip")), 2, row);
        row++;

        CheckBox defaultReedSolomon = checkBox(Messages.get("settings.defaultReedSolomon"));
        grid.add(defaultReedSolomon, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.defaultReedSolomon.tip")), 2, row);
        row++;

        // 默认压缩格式
        ComboBox<String> defaultFormat = new ComboBox<>();
        defaultFormat.getItems().setAll("ZIP", "GZ", "TAR.GZ", "7Z");
        defaultFormat.setPrefWidth(120);
        HBox fmtBox = new HBox(8,
                new Label(Messages.get("settings.defaultFormat")), defaultFormat);
        fmtBox.setAlignment(Pos.CENTER_LEFT);
        grid.add(fmtBox, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.defaultFormat.tip")), 2, row);
        row++;

        // 默认分卷大小
        Spinner<Integer> defaultSplitSize = new Spinner<>(1, 102400, 100);
        defaultSplitSize.setPrefWidth(110);
        defaultSplitSize.setEditable(true);
        HBox splitBox = new HBox(6,
                new Label(Messages.get("settings.defaultSplitSize")),
                defaultSplitSize,
                new Label("MiB"));
        splitBox.setAlignment(Pos.CENTER_LEFT);
        grid.add(splitBox, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.defaultSplitSize.tip")), 2, row);
        row++;

        // === 行为 ===
        grid.add(section(Messages.get("settings.section.behavior")), 0, row++, 3, 1);

        CheckBox rememberOutputDir = checkBox(Messages.get("settings.rememberOutputDir"));
        grid.add(rememberOutputDir, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.rememberOutputDir.tip")), 2, row);
        row++;

        CheckBox autoClearPassword = checkBox(Messages.get("settings.autoClearPassword"));
        grid.add(autoClearPassword, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.autoClearPassword.tip")), 2, row);
        row++;

        // 加密线程数
        Spinner<Integer> threadCountSpinner = new Spinner<>(1, 16, 4);
        threadCountSpinner.setPrefWidth(90);
        threadCountSpinner.setEditable(true);
        HBox threadBox = new HBox(6,
                new Label(Messages.get("settings.threadCount")),
                threadCountSpinner);
        threadBox.setAlignment(Pos.CENTER_LEFT);
        grid.add(threadBox, 0, row, 2, 1);
        grid.add(infoIcon(Messages.get("settings.threadCount.tip")), 2, row);
        row++;

        // ---- 加载当前值 ----
        // 主题模式
        ThemeManager.Mode savedMode = themeManager != null
                ? themeManager.getMode() : parseMode(SettingsManager.getThemeMode());
        switch (savedMode) {
            case LIGHT -> themeCombo.setValue(Messages.get("theme.light"));
            case DARK -> themeCombo.setValue(Messages.get("theme.dark"));
            default -> themeCombo.setValue(Messages.get("theme.system"));
        }

        autoDecompress.setSelected(SettingsManager.isAutoDecompressDecrypt());
        confirmOverwrite.setSelected(SettingsManager.isConfirmOverwrite());
        defaultPasswordless.setSelected(SettingsManager.isDefaultPasswordless());
        defaultParanoid.setSelected(SettingsManager.isDefaultParanoid());
        defaultReedSolomon.setSelected(SettingsManager.isDefaultReedSolomon());
        defaultFormat.setValue(SettingsManager.getDefaultCompressFormat());
        defaultSplitSize.getValueFactory().setValue(SettingsManager.getDefaultSplitSize());
        rememberOutputDir.setSelected(SettingsManager.isRememberOutputDir());
        autoClearPassword.setSelected(SettingsManager.isAutoClearPassword());
        threadCountSpinner.getValueFactory().setValue(SettingsManager.getThreadCount());

        // ---- 监听即时写入 ----
        themeCombo.valueProperty().addListener((o, a, b) -> {
            if (b == null) return;
            ThemeManager.Mode m;
            if (b.equals(Messages.get("theme.dark"))) {
                m = ThemeManager.Mode.DARK;
            } else if (b.equals(Messages.get("theme.light"))) {
                m = ThemeManager.Mode.LIGHT;
            } else {
                m = ThemeManager.Mode.SYSTEM;
            }
            if (themeManager != null) {
                themeManager.setMode(m);
            }
            SettingsManager.setThemeMode(m.name());
        });

        autoDecompress.selectedProperty().addListener((o, a, b) ->
                SettingsManager.setAutoDecompressDecrypt(b));
        confirmOverwrite.selectedProperty().addListener((o, a, b) ->
                SettingsManager.setConfirmOverwrite(b));
        defaultPasswordless.selectedProperty().addListener((o, a, b) ->
                SettingsManager.setDefaultPasswordless(b));
        defaultParanoid.selectedProperty().addListener((o, a, b) ->
                SettingsManager.setDefaultParanoid(b));
        defaultReedSolomon.selectedProperty().addListener((o, a, b) ->
                SettingsManager.setDefaultReedSolomon(b));
        defaultFormat.valueProperty().addListener((o, a, b) ->
                SettingsManager.setDefaultCompressFormat(b));
        defaultSplitSize.valueProperty().addListener((o, a, b) ->
                SettingsManager.setDefaultSplitSize(b));
        rememberOutputDir.selectedProperty().addListener((o, a, b) ->
                SettingsManager.setRememberOutputDir(b));
        autoClearPassword.selectedProperty().addListener((o, a, b) ->
                SettingsManager.setAutoClearPassword(b));
        threadCountSpinner.valueProperty().addListener((o, a, b) ->
                SettingsManager.setThreadCount(b));

        pane.setContent(grid);

        // ---- 按钮 ----
        pane.getButtonTypes().add(
                new ButtonType(Messages.get("dialog.close"), ButtonBar.ButtonData.OK_DONE));

        dialog.showAndWait();
    }

    private static Label section(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("card-title");
        l.setPadding(new Insets(6, 0, 2, 0));
        return l;
    }

    private static CheckBox checkBox(String text) {
        CheckBox cb = new CheckBox(text);
        cb.getStyleClass().add("check");
        return cb;
    }

    private static Label infoIcon(String tip) {
        Label icon = new Label("i");
        icon.getStyleClass().add("info-icon");
        Tooltip tooltip = new Tooltip(tip);
        tooltip.getStyleClass().add("info-tooltip");
        tooltip.setShowDelay(Duration.millis(120));
        tooltip.setShowDuration(Duration.seconds(20));
        tooltip.setHideDelay(Duration.millis(120));
        tooltip.setWrapText(true);
        tooltip.setMaxWidth(300);
        Tooltip.install(icon, tooltip);
        icon.setTooltip(tooltip);
        return icon;
    }

    private static ThemeManager.Mode parseMode(String s) {
        if ("DARK".equalsIgnoreCase(s)) return ThemeManager.Mode.DARK;
        if ("LIGHT".equalsIgnoreCase(s)) return ThemeManager.Mode.LIGHT;
        return ThemeManager.Mode.SYSTEM;
    }
}
