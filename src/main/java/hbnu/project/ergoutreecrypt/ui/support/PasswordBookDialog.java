package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.passwordbook.DesktopPasswordBookStore;
import hbnu.project.ergoutreecrypt.passwordbook.PasswordBookEntry;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * 桌面端密码本编辑、导入与导出对话框。
 *
 * @author ErgouTree
 * @since 2026/9/22
 */
public final class PasswordBookDialog {

    private PasswordBookDialog() {
    }

    /**
     * 显示密码本编辑对话框。
     *
     * @param owner 父窗口
     */
    public static void show(Window owner) {
        Dialog<ButtonType> dialog = new Dialog<>();
        dialog.initOwner(owner);
        dialog.setTitle(Messages.get("passwordBook.title"));
        dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);

        ObservableList<EditableEntry> rows = FXCollections.observableArrayList();
        DesktopPasswordBookStore.load().stream().map(EditableEntry::new).forEach(rows::add);

        TableView<EditableEntry> table = createTable(rows);
        Button add = new Button(Messages.get("passwordBook.add"));
        Button remove = new Button(Messages.get("passwordBook.remove"));
        Button importButton = new Button(Messages.get("passwordBook.import"));
        Button exportButton = new Button(Messages.get("passwordBook.export"));

        add.setOnAction(event -> {
            EditableEntry entry = new EditableEntry(new PasswordBookEntry("", ""));
            rows.add(entry);
            table.getSelectionModel().select(entry);
            table.scrollTo(entry);
            table.edit(rows.size() - 1, table.getColumns().get(0));
        });
        remove.setOnAction(event -> rows.remove(table.getSelectionModel().getSelectedItem()));
        importButton.setOnAction(event -> importCsv(owner, rows));
        exportButton.setOnAction(event -> exportCsv(owner, rows));

        HBox actions = new HBox(8, add, remove, importButton, exportButton);
        VBox content = new VBox(10,
                new Label(Messages.get("passwordBook.description")), table, actions);
        content.setPadding(new Insets(12));
        VBox.setVgrow(table, Priority.ALWAYS);
        dialog.getDialogPane().setContent(content);
        dialog.getDialogPane().setPrefSize(640, 440);

        dialog.showAndWait().filter(ButtonType.OK::equals).ifPresent(result -> {
            try {
                DesktopPasswordBookStore.save(toEntries(rows));
            } catch (IOException exception) {
                showError(owner, exception);
            }
        });
    }

    /**
     * 创建可编辑的两列表格。
     *
     * @param rows 表格数据
     * @return 密码本表格
     */
    private static TableView<EditableEntry> createTable(ObservableList<EditableEntry> rows) {
        TableView<EditableEntry> table = new TableView<>(rows);
        table.setEditable(true);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        TableColumn<EditableEntry, String> name = new TableColumn<>(
                Messages.get("passwordBook.column.name"));
        name.setCellValueFactory(value -> value.getValue().nameProperty());
        name.setCellFactory(TextFieldTableCell.forTableColumn());
        name.setOnEditCommit(event -> event.getRowValue().setName(event.getNewValue()));

        TableColumn<EditableEntry, String> password = new TableColumn<>(
                Messages.get("passwordBook.column.password"));
        password.setCellValueFactory(value -> value.getValue().passwordProperty());
        password.setCellFactory(TextFieldTableCell.forTableColumn());
        password.setOnEditCommit(event -> event.getRowValue().setPassword(event.getNewValue()));
        table.getColumns().add(name);
        table.getColumns().add(password);
        return table;
    }

    /**
     * 从用户选择的 CSV 文件导入并替换当前表格。
     *
     * @param owner 父窗口
     * @param rows  当前表格数据
     */
    private static void importCsv(Window owner, ObservableList<EditableEntry> rows) {
        FileChooser chooser = csvChooser(Messages.get("passwordBook.import"));
        File source = chooser.showOpenDialog(owner);
        if (source == null) {
            return;
        }
        try {
            List<PasswordBookEntry> imported = DesktopPasswordBookStore.importCsv(source.toPath());
            rows.setAll(imported.stream().map(EditableEntry::new).toList());
        } catch (IOException exception) {
            showError(owner, exception);
        }
    }

    /**
     * 将当前表格导出到用户选择的 CSV 文件。
     *
     * @param owner 父窗口
     * @param rows  当前表格数据
     */
    private static void exportCsv(Window owner, ObservableList<EditableEntry> rows) {
        FileChooser chooser = csvChooser(Messages.get("passwordBook.export"));
        chooser.setInitialFileName("password-book.csv");
        File target = chooser.showSaveDialog(owner);
        if (target == null) {
            return;
        }
        try {
            DesktopPasswordBookStore.save(toEntries(rows));
            DesktopPasswordBookStore.exportCsv(target.toPath());
        } catch (IOException exception) {
            showError(owner, exception);
        }
    }

    /**
     * 创建仅选择 CSV 的文件选择器。
     *
     * @param title 对话框标题
     * @return 文件选择器
     */
    private static FileChooser csvChooser(String title) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("CSV (*.csv)", "*.csv"));
        return chooser;
    }

    /**
     * 将编辑行转换为有效密码记录。
     *
     * @param rows 编辑行
     * @return 名称非空的密码记录
     */
    private static List<PasswordBookEntry> toEntries(List<EditableEntry> rows) {
        return rows.stream()
                .filter(row -> !row.getName().isBlank())
                .map(row -> new PasswordBookEntry(row.getName(), row.getPassword()))
                .toList();
    }

    /**
     * 显示密码本读写错误。
     *
     * @param owner     父窗口
     * @param exception 失败原因
     */
    private static void showError(Window owner, Exception exception) {
        Alert alert = new Alert(Alert.AlertType.ERROR,
                Messages.get("passwordBook.error") + "\n" + exception.getMessage(), ButtonType.OK);
        alert.initOwner(owner);
        alert.showAndWait();
    }

    /**
     * TableView 使用的可编辑密码记录。
     */
    private static final class EditableEntry {

        private final SimpleStringProperty name;
        private final SimpleStringProperty password;

        /**
         * 创建编辑行。
         *
         * @param entry 初始密码记录
         */
        private EditableEntry(PasswordBookEntry entry) {
            name = new SimpleStringProperty(entry.getName());
            password = new SimpleStringProperty(entry.getPassword());
        }

        /**
         * 获取名称属性。
         *
         * @return 名称属性
         */
        private SimpleStringProperty nameProperty() {
            return name;
        }

        /**
         * 获取密码属性。
         *
         * @return 密码属性
         */
        private SimpleStringProperty passwordProperty() {
            return password;
        }

        /**
         * 获取名称。
         *
         * @return 名称
         */
        private String getName() {
            return name.get();
        }

        /**
         * 修改名称。
         *
         * @param value 新名称
         */
        private void setName(String value) {
            name.set(value == null ? "" : value);
        }

        /**
         * 获取密码。
         *
         * @return 密码
         */
        private String getPassword() {
            return password.get();
        }

        /**
         * 修改密码。
         *
         * @param value 新密码
         */
        private void setPassword(String value) {
            password.set(value == null ? "" : value);
        }
    }
}
