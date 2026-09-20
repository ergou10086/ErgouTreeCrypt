package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import javafx.beans.binding.Bindings;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.util.List;
import java.util.Optional;

/**
 * 存储空间占用对话框，通过顶栏"存储"按钮打开。
 *
 * <p>以表格逐项展示本工具产生的缓存占用（类别 / 落盘位置 / 占用 / 文件数），
 * 并在底部给出合计占用与一键「清理缓存」。清理前弹出确认框列明将删除的类别，
 * 清理后立即刷新表格，以实际释放量提示结果。
 *
 * <p>清理只针对中间产物，不会删除用户已生成的加密/解密结果文件。
 *
 * @author ErgouTree
 * @since 2026/9/20
 */
public final class StorageDialog {

    private StorageDialog() {
    }

    /**
     * 显示存储空间占用对话框。
     *
     * <p>加解密任务运行期间禁用「清理缓存」：进行中的操作仍在使用系统临时目录里的中间产物，
     * 删除会导致其中断失败。
     *
     * @param owner       父窗口
     * @param taskRunning 当前是否有加解密任务正在运行
     */
    public static void show(javafx.stage.Window owner, boolean taskRunning) {
        Dialog<Void> dialog = new Dialog<>();
        dialog.initOwner(owner);
        dialog.setTitle(Messages.get("storage.title"));
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
                StorageDialog.class.getResource(
                        "/hbnu/project/ergoutreecrypt/ui/styles/win11.css").toExternalForm());

        // ---- 占用明细表格 ----
        TableView<StorageUsage.Entry> table = new TableView<>();
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPrefHeight(320);

        TableColumn<StorageUsage.Entry, String> categoryCol =
                new TableColumn<>(Messages.get("storage.col.category"));
        categoryCol.setCellValueFactory(cd ->
                new ReadOnlyStringWrapper(Messages.get(cd.getValue().labelKey())));
        categoryCol.setPrefWidth(150);

        TableColumn<StorageUsage.Entry, String> pathCol =
                new TableColumn<>(Messages.get("storage.col.path"));
        pathCol.setCellValueFactory(cd ->
                new ReadOnlyStringWrapper(cd.getValue().path()));
        pathCol.setPrefWidth(300);

        TableColumn<StorageUsage.Entry, String> sizeCol =
                new TableColumn<>(Messages.get("storage.col.size"));
        sizeCol.setCellValueFactory(cd ->
                new ReadOnlyStringWrapper(FileSizes.human(cd.getValue().bytes())));
        sizeCol.setPrefWidth(110);

        TableColumn<StorageUsage.Entry, String> filesCol =
                new TableColumn<>(Messages.get("storage.col.files"));
        filesCol.setCellValueFactory(cd ->
                new ReadOnlyStringWrapper(String.valueOf(cd.getValue().files())));
        filesCol.setPrefWidth(80);

        table.getColumns().addAll(List.of(categoryCol, pathCol, sizeCol, filesCol));

        Label totalLabel = new Label();
        totalLabel.getStyleClass().add("status-text");

        Label emptyLabel = new Label(Messages.get("storage.empty"));
        emptyLabel.getStyleClass().add("field-hint");
        emptyLabel.setMaxWidth(Double.MAX_VALUE);
        emptyLabel.setAlignment(Pos.CENTER);
        emptyLabel.visibleProperty().bind(Bindings.createBooleanBinding(
                () -> StorageUsage.totalBytes(table.getItems()) == 0L,
                table.getItems()));

        Button refreshBtn = new Button(Messages.get("storage.refresh"));
        refreshBtn.getStyleClass().add("btn-ghost");

        Button clearBtn = new Button(Messages.get("storage.clear"));
        clearBtn.getStyleClass().add("btn-ghost");

        Region spacer = new Region();
        HBox footer = new HBox(10, totalLabel, spacer, refreshBtn, clearBtn);
        footer.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label busyLabel = new Label(Messages.get("storage.clear.busy"));
        busyLabel.getStyleClass().add("field-hint");
        busyLabel.setVisible(taskRunning);

        VBox content = new VBox(10, table, emptyLabel, footer, busyLabel);
        content.setPadding(new Insets(16, 20, 12, 20));
        VBox.setVgrow(table, Priority.ALWAYS);

        pane.setContent(content);

        // ---- 首次加载明细 ----
        reload(table, totalLabel, clearBtn, taskRunning);

        refreshBtn.setOnAction(e -> reload(table, totalLabel, clearBtn, taskRunning));

        clearBtn.setOnAction(e -> {
            List<StorageUsage.Entry> before = List.copyOf(table.getItems());
            if (StorageUsage.totalBytes(before) == 0L) {
                reload(table, totalLabel, clearBtn, taskRunning);
                return;
            }
            if (!confirmClear(owner, before)) {
                return;
            }
            long freed = StorageUsage.clearAll();
            reload(table, totalLabel, clearBtn, taskRunning);
            Alert done = new Alert(Alert.AlertType.INFORMATION);
            done.initOwner(owner);
            done.setTitle(Messages.get("storage.title"));
            done.setHeaderText(null);
            done.setContentText(Messages.format("storage.clear.done", FileSizes.human(freed)));
            done.showAndWait();
        });

        pane.getButtonTypes().add(
                new ButtonType(Messages.get("dialog.close"), ButtonBar.ButtonData.OK_DONE));

        dialog.showAndWait();
    }

    /**
     * 重新扫描并刷新表格、合计与清理按钮的可用状态。
     *
     * @param table       明细表格
     * @param totalLabel  合计占用标签
     * @param clearBtn    清理按钮，无内容可清理或有任务运行时禁用
     * @param taskRunning 当前是否有加解密任务正在运行
     */
    private static void reload(TableView<StorageUsage.Entry> table, Label totalLabel, Button clearBtn,
                               boolean taskRunning) {
        List<StorageUsage.Entry> entries = StorageUsage.scan();
        table.getItems().setAll(entries);
        totalLabel.setText(Messages.format("storage.total", FileSizes.human(StorageUsage.totalBytes(entries))));
        clearBtn.setDisable(taskRunning || StorageUsage.totalBytes(entries) == 0L);
    }

    /**
     * 弹出清理确认框，列明将被删除的类别与合计占用。
     *
     * @param owner   父窗口
     * @param entries 当前明细，用于生成确认文案
     * @return 用户确认清理时返回 {@code true}
     */
    private static boolean confirmClear(javafx.stage.Window owner, List<StorageUsage.Entry> entries) {
        StringBuilder detail = new StringBuilder();
        for (StorageUsage.Entry entry : entries) {
            if (entry.bytes() <= 0L) {
                continue;
            }
            if (!detail.isEmpty()) {
                detail.append('\n');
            }
            detail.append("· ").append(Messages.get(entry.labelKey()))
                    .append(" — ").append(FileSizes.human(entry.bytes()));
        }

        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(owner);
        alert.setTitle(Messages.get("storage.title"));
        alert.setHeaderText(Messages.get("storage.clear.confirm.header"));
        alert.setContentText(Messages.format("storage.clear.confirm.body", detail.toString()));
        alert.getDialogPane().setPrefWidth(460);

        ButtonType confirm = new ButtonType(
                Messages.get("storage.clear"), ButtonBar.ButtonData.OK_DONE);
        ButtonType cancel = new ButtonType(
                Messages.get("action.cancel"), ButtonBar.ButtonData.CANCEL_CLOSE);
        alert.getButtonTypes().setAll(confirm, cancel);

        Optional<ButtonType> choice = alert.showAndWait();
        return choice.isPresent() && choice.get() == confirm;
    }
}
