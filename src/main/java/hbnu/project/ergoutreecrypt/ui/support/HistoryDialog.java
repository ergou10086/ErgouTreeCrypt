package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.history.HistoryService;
import hbnu.project.ergoutreecrypt.history.OperationRecord;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import javafx.beans.binding.Bindings;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.input.MouseButton;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

import java.awt.Desktop;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * 操作历史对话框，通过菜单栏"历史"按钮打开。
 *
 * <p>以表格展示全部加解密操作记录（文件名 / 操作类型 / 操作时间），
 * 单击任意记录直接打开其输出文件所在的文件夹；输出文件夹已被删除或
 * 无法打开时以 Toast 友好提示，绝不抛出异常打断用户。
 *
 * <p>交互逻辑与移动端历史列表保持一致：点按记录 = 打开输出文件夹，
 * 并提供一键清空。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
public final class HistoryDialog {

    /** 时间列展示格式 */
    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private HistoryDialog() {
    }

    /**
     * 显示操作历史对话框。
     *
     * @param owner 父窗口
     */
    public static void show(javafx.stage.Window owner) {
        Dialog<Void> dialog = new Dialog<>();
        dialog.initOwner(owner);
        dialog.setTitle(Messages.get("history.title"));
        dialog.setHeaderText(null);
        dialog.setResizable(true);

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
                HistoryDialog.class.getResource(
                        "/hbnu/project/ergoutreecrypt/ui/styles/win11.css").toExternalForm());

        // ---- 历史表格 ----
        TableView<OperationRecord> table = new TableView<>();
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPrefHeight(380);

        TableColumn<OperationRecord, String> fileCol = new TableColumn<>(Messages.get("history.col.fileName"));
        fileCol.setCellValueFactory(cd -> new ReadOnlyStringWrapper(cd.getValue().fileName()));
        fileCol.setPrefWidth(240);

        TableColumn<OperationRecord, String> typeCol = new TableColumn<>(Messages.get("history.col.type"));
        typeCol.setCellValueFactory(cd ->
                new ReadOnlyStringWrapper(Messages.get(cd.getValue().type().getI18nKey())));
        typeCol.setPrefWidth(140);

        TableColumn<OperationRecord, String> timeCol = new TableColumn<>(Messages.get("history.col.time"));
        timeCol.setCellValueFactory(cd -> new ReadOnlyStringWrapper(formatTime(cd.getValue())));
        timeCol.setPrefWidth(170);

        table.getColumns().addAll(fileCol, typeCol, timeCol);

        // ---- 空状态提示 ----
        Label emptyLabel = new Label(Messages.get("history.empty"));
        emptyLabel.getStyleClass().add("field-hint");
        emptyLabel.setMaxWidth(Double.MAX_VALUE);
        emptyLabel.setAlignment(Pos.CENTER);
        emptyLabel.visibleProperty().bind(Bindings.isEmpty(table.getItems()));

        VBox content = new VBox(10, table, emptyLabel);
        content.setPadding(new Insets(16, 20, 12, 20));
        VBox.setVgrow(table, Priority.ALWAYS);

        // ---- 内容根节点（StackPane 同时作为 Toast 宿主） ----
        StackPane root = new StackPane(content);
        Toast toast = new Toast(root);
        pane.setContent(root);

        // ---- 单击记录 → 打开输出文件夹 ----
        table.setRowFactory(tv -> {
            TableRow<OperationRecord> row = new TableRow<>();
            row.setOnMouseClicked(e -> {
                if (e.getButton() == MouseButton.PRIMARY && !row.isEmpty()) {
                    openOutputFolder(row.getItem(), toast);
                }
            });
            return row;
        });

        table.getItems().setAll(HistoryService.list());

        pane.getButtonTypes().add(
                new ButtonType(Messages.get("dialog.close"), ButtonBar.ButtonData.OK_DONE));

        // 「清空历史」按钮：插入按钮栏最左侧，与「关闭」同行；点击后只清空不关闭对话框
        Button clearBtn = new Button(Messages.get("history.clear"));
        clearBtn.getStyleClass().add("btn-ghost");
        clearBtn.setOnAction(e -> {
            HistoryService.clear();
            table.getItems().clear();
        });
        dialog.setOnShown(e -> {
            ButtonBar buttonBar = (ButtonBar) pane.lookup(".button-bar");
            if (buttonBar != null && !buttonBar.getButtons().contains(clearBtn)) {
                ButtonBar.setButtonData(clearBtn, ButtonBar.ButtonData.LEFT);
                buttonBar.getButtons().add(0, clearBtn);
            }
        });

        dialog.showAndWait();
    }

    /**
     * 打开记录对应输出文件所在的文件夹。
     *
     * <p>文件夹不存在、被删除或系统不支持打开时，以 Toast 给出友好提示，
     * 不抛出任何异常。
     *
     * @param record 历史记录
     * @param toast  Toast 提示宿主
     */
    private static void openOutputFolder(OperationRecord record, Toast toast) {
        String pathStr = record.outputPath();
        if (pathStr == null || pathStr.isBlank()) {
            toast.error(Messages.get("history.folderMissing"));
            return;
        }
        try {
            Path target = Path.of(pathStr);
            if (!Files.isDirectory(target)) {
                target = target.getParent();
            }
            if (target == null || !Files.exists(target) || !Desktop.isDesktopSupported()) {
                toast.error(Messages.get("history.folderMissing"));
                return;
            }
            Desktop.getDesktop().open(target.toFile());
        } catch (java.io.IOException | RuntimeException ex) {
            // 路径非法、无权限、桌面不可用等一律转为友好提示
            toast.error(Messages.get("history.folderMissing"));
        }
    }

    /**
     * 将记录时间戳格式化为本地时区的时间字符串。
     *
     * @param record 历史记录
     * @return 形如 {@code 2026-08-14 15:30:00} 的时间文本
     */
    private static String formatTime(OperationRecord record) {
        return TIME_FORMAT.format(
                Instant.ofEpochMilli(record.timestampEpochMillis()).atZone(ZoneId.systemDefault()));
    }
}
