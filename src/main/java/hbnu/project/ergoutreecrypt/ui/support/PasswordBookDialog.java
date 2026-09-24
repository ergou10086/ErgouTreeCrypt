package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.passwordbook.DesktopPasswordBookStore;
import hbnu.project.ergoutreecrypt.passwordbook.PasswordBookEntry;
import hbnu.project.ergoutreecrypt.passwordbook.PasswordBookCsv;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.event.ActionEvent;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TableCell;
import javafx.scene.control.TextField;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.function.Function;

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
        try {
            createDialog(owner, DesktopPasswordBookStore.load(), DesktopPasswordBookStore::save)
                    .showAndWait();
        } catch (IOException | SecurityException exception) {
            showError(owner, exception);
        }
    }

    /**
     * 创建使用独立编辑副本的密码本窗口，只有保存成功才关闭。
     *
     * @param owner 父窗口
     * @param entries 初始记录
     * @param saveAction 保存操作
     * @return 尚未显示的对话框
     */
    static Dialog<ButtonType> createDialog(Window owner, List<PasswordBookEntry> entries,
                                           SaveAction saveAction) {
        Dialog<ButtonType> dialog = new Dialog<>();
        DialogSupport.configure(dialog, owner, 680, 560);
        dialog.setTitle(Messages.get("passwordBook.title"));
        dialog.getDialogPane().getStyleClass().add("password-book-dialog");
        ButtonType save = new ButtonType(Messages.get("passwordBook.save"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(save, ButtonType.CANCEL);

        ObservableList<EditableEntry> rows = FXCollections.observableArrayList();
        entries.stream().map(EditableEntry::new).forEach(rows::add);

        TableView<EditableEntry> table = createTable(rows);
        Button add = new Button(Messages.get("passwordBook.add"));
        Button remove = new Button(Messages.get("passwordBook.remove"));
        Button importButton = new Button(Messages.get("passwordBook.import"));
        Button exportButton = new Button(Messages.get("passwordBook.export"));
        add.setId("password-book-add");
        remove.setId("password-book-remove");
        remove.disableProperty().bind(table.getSelectionModel().selectedItemProperty().isNull());
        for (Button button : List.of(add, remove, importButton, exportButton)) {
            button.getStyleClass().add("btn-secondary");
        }

        add.setOnAction(event -> {
            EditableEntry entry = new EditableEntry(new PasswordBookEntry("", ""));
            rows.add(entry);
            table.getSelectionModel().select(entry);
            table.scrollTo(entry);
            Platform.runLater(() -> {
                table.applyCss();
                table.layout();
                for (Node node : table.lookupAll(".table-cell")) {
                    if (node instanceof EntryCell cell && cell.boundProperty == entry.nameProperty()) {
                        cell.editor.requestFocus();
                        break;
                    }
                }
            });
        });
        remove.setOnAction(event -> rows.remove(table.getSelectionModel().getSelectedItem()));
        importButton.setOnAction(event -> importCsv(dialog.getDialogPane().getScene().getWindow(), rows));
        exportButton.setOnAction(event -> exportCsv(dialog.getDialogPane().getScene().getWindow(), rows));

        FlowPane actions = new FlowPane(8, 8, add, remove, importButton, exportButton);
        Label description = new Label(Messages.get("passwordBook.description"));
        description.setWrapText(true);
        description.setMinWidth(0);
        description.setMinHeight(Region.USE_PREF_SIZE);
        Label location = new Label(Messages.format("passwordBook.location", DesktopPasswordBookStore.getStorePath()));
        location.setWrapText(true);
        location.setMinWidth(0);
        location.setMinHeight(Region.USE_PREF_SIZE);
        location.getStyleClass().add("field-hint");
        Label error = new Label();
        error.setId("password-book-error");
        error.setWrapText(true);
        error.setMinWidth(0);
        error.setMinHeight(Region.USE_PREF_SIZE);
        error.getStyleClass().add("password-book-error");
        error.visibleProperty().bind(error.textProperty().isNotEmpty());
        error.managedProperty().bind(error.visibleProperty());
        VBox content = new VBox(10, description, location, table, actions, error);
        content.setMinSize(0, 0);
        content.setPadding(new Insets(16));
        VBox.setVgrow(table, Priority.ALWAYS);
        dialog.getDialogPane().setContent(content);

        dialog.getDialogPane().lookupButton(save).addEventFilter(ActionEvent.ACTION, event -> {
            try {
                saveAction.save(toEntries(rows));
            } catch (IOException | IllegalArgumentException | SecurityException exception) {
                event.consume();
                error.setText(Messages.get("passwordBook.error") + "\n" + exception.getMessage());
            }
        });
        return dialog;
    }

    /** 密码本保存回调。 */
    @FunctionalInterface
    interface SaveAction {
        /**
         * 保存本次编辑的全部记录。
         *
         * @param entries 待保存的记录
         * @throws IOException 持久化失败时抛出
         */
        void save(List<PasswordBookEntry> entries) throws IOException;
    }

    /**
     * 创建可编辑的两列表格。
     *
     * @param rows 表格数据
     * @return 密码本表格
     */
    private static TableView<EditableEntry> createTable(ObservableList<EditableEntry> rows) {
        TableView<EditableEntry> table = new TableView<>(rows);
        table.setId("password-book-table");
        table.getStyleClass().add("password-book-table");
        table.setPlaceholder(new Label(Messages.get("passwordBook.empty")));
        table.setMinSize(0, 80);
        table.setFixedCellSize(48);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        TableColumn<EditableEntry, String> name = new TableColumn<>(
                Messages.get("passwordBook.column.name"));
        name.setCellValueFactory(value -> value.getValue().nameProperty());
        name.setSortable(false);
        name.setReorderable(false);
        name.setCellFactory(column -> new EntryCell(EditableEntry::nameProperty,
                Messages.get("passwordBook.column.name")));

        TableColumn<EditableEntry, String> password = new TableColumn<>(
                Messages.get("passwordBook.column.password"));
        password.setCellValueFactory(value -> value.getValue().passwordProperty());
        password.setSortable(false);
        password.setReorderable(false);
        password.setCellFactory(column -> new EntryCell(EditableEntry::passwordProperty,
                Messages.get("passwordBook.column.password")));
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
        try (Reader reader = Files.newBufferedReader(source.toPath(), StandardCharsets.UTF_8)) {
            List<PasswordBookEntry> imported = PasswordBookCsv.read(reader);
            rows.setAll(imported.stream().map(EditableEntry::new).toList());
        } catch (IOException | SecurityException exception) {
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
            List<PasswordBookEntry> entries = toEntries(rows);
            try (Writer writer = Files.newBufferedWriter(target.toPath(), StandardCharsets.UTF_8)) {
                PasswordBookCsv.write(entries, writer);
            }
        } catch (IOException | IllegalArgumentException | SecurityException exception) {
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
        if (rows.stream().anyMatch(row -> row.getName().isBlank() && !row.getPassword().isEmpty())) {
            throw new IllegalArgumentException(Messages.get("passwordBook.nameRequired"));
        }
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
        DialogSupport.configure(alert, owner, 520, 320);
        alert.showAndWait();
    }

    /**
     * 常驻输入框单元格，输入即时同步到编辑副本，不依赖 Enter 提交。
     */
    private static final class EntryCell extends TableCell<EditableEntry, String> {
        private final TextField editor = new TextField();
        private final Function<EditableEntry, SimpleStringProperty> property;
        private SimpleStringProperty boundProperty;

        /**
         * 创建双向绑定输入框。
         *
         * @param property 行属性提取器
         * @param prompt 空值提示
         */
        private EntryCell(Function<EditableEntry, SimpleStringProperty> property, String prompt) {
            this.property = property;
            editor.setPromptText(prompt);
            editor.setAccessibleText(prompt);
            editor.setMinWidth(0);
            editor.setMaxWidth(Double.MAX_VALUE);
            editor.focusedProperty().addListener((observable, oldValue, focused) -> {
                if (focused && getIndex() >= 0) {
                    getTableView().getSelectionModel().select(getIndex());
                }
            });
        }

        /**
         * 虚拟化复用时解除旧行绑定，避免滚动后修改其他记录。
         *
         * @param value 单元格值
         * @param empty 是否为空白占位行
         */
        @Override
        protected void updateItem(String value, boolean empty) {
            super.updateItem(value, empty);
            if (boundProperty != null) {
                editor.textProperty().unbindBidirectional(boundProperty);
                boundProperty = null;
            }
            setText(null);
            if (empty || getIndex() < 0 || getIndex() >= getTableView().getItems().size()) {
                setGraphic(null);
            } else {
                boundProperty = property.apply(getTableView().getItems().get(getIndex()));
                editor.setText(boundProperty.get());
                editor.textProperty().bindBidirectional(boundProperty);
                setGraphic(editor);
            }
        }
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
         * 获取密码。
         *
         * @return 密码
         */
        private String getPassword() {
            return password.get();
        }

    }
}
