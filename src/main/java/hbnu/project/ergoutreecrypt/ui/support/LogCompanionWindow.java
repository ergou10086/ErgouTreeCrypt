package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogEvent;
import hbnu.project.ergoutreecrypt.log.LogLevel;
import hbnu.project.ergoutreecrypt.log.LogListener;
import hbnu.project.ergoutreecrypt.log.LogService;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.geometry.Rectangle2D;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ContextMenu;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.MenuItem;
import javafx.scene.control.ScrollBar;
import javafx.scene.control.SelectionMode;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.WindowEvent;
import javafx.util.Duration;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * 主窗口右侧的翻书式日志伴生窗。
 *
 * <p>以与主窗同等尺寸的无边框窗口贴靠在右侧（空间不足则改贴左侧），
 * 主窗移动或缩放时跟随，形成「两页书」的观感。内容为实时刷新的只读日志，
 * 支持按级别着色、多选行复制、清空与导出。关闭本窗不影响主窗。
 *
 * <p>正文用 {@link ListView} 而非 {@code TextArea}：JavaFX 的 {@code TextArea}
 * 无法为同一段落内的不同片段着色，而日志需要按级别区分颜色（TRACE 灰、WARN 琥珀、
 * ERROR 红）；{@code TextFlow} 在 JavaFX 21 上又没有选区与复制能力。
 * 列表自带虚拟化，长时间开启 TRACE 也不会因行数增长而卡顿。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LogCompanionWindow {

    /** 当前打开的实例；同一时刻最多一个。 */
    private static LogCompanionWindow instance;

    /** 可见性变化回调（可选）。 */
    private static Runnable visibilityListener;

    /**
     * 列表中保留的最大行数。
     *
     * <p>与内存日志缓冲区的容量同级，超出后丢弃最旧的行，避免长会话下无限增长。
     */
    private static final int MAX_LINES = 20_000;

    /** 四个级别对应的样式类，用于切换级别时先清空再添加。 */
    private static final List<String> LEVEL_STYLE_CLASSES = List.of(
            "log-line-error", "log-line-warn", "log-line-info", "log-line-trace");

    /** 本窗 Stage。 */
    private final Stage stage;

    /** 主窗。 */
    private final Stage owner;

    /** 根容器，用于入场位移动画。 */
    private final VBox rootPane;

    /** Toast 宿主。 */
    private final StackPane rootStack;

    private final Label titleLabel;
    private final Button clearBtn;
    private final Button copyBtn;
    private final Button exportBtn;

    /** 日志列表：虚拟化渲染，每行一条事件。 */
    private final ListView<LogEvent> logList;

    /** 列表数据源。 */
    private final ObservableList<LogEvent> logItems = FXCollections.observableArrayList();

    private final Toast toast;
    private final LogListener logListener;

    /** 用户未上翻时自动滚到底部。 */
    private boolean stickToBottom = true;

    /** 当前已挂上监听的垂直滚动条；皮肤重建时会重新定位。 */
    private ScrollBar trackedScrollBar;

    /** 滚动条位置变化：贴近底部则恢复自动滚动。 */
    private final ChangeListener<Number> scrollListener = (obs, oldV, newV) -> {
        ScrollBar bar = trackedScrollBar;
        stickToBottom = bar != null && bar.getValue() >= bar.getMax() - 0.08;
    };

    /** 正在根据主窗同步位置，避免重入。 */
    private boolean docking;

    /** 主窗几何变化监听。 */
    private final ChangeListener<Number> ownerGeomListener = (obs, oldV, newV) -> dockToOwner();

    /** 主窗关闭监听。 */
    private final javafx.event.EventHandler<WindowEvent> ownerCloseHandler = e -> close();

    private LogCompanionWindow(Stage owner) {
        this.owner = owner;

        titleLabel = new Label();
        titleLabel.getStyleClass().add("title-text");
        titleLabel.setMouseTransparent(true);

        Button closeBtn = new Button("✕");
        closeBtn.getStyleClass().addAll("title-win", "win-close");
        closeBtn.setOnAction(e -> close());

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        HBox titleBar = new HBox(10, titleLabel, spacer, closeBtn);
        titleBar.getStyleClass().add("title-bar");
        titleBar.setAlignment(Pos.CENTER_LEFT);
        titleBar.setPadding(new Insets(8, 4, 8, 16));

        logList = new ListView<>(logItems);
        logList.getStyleClass().add("log-list");
        logList.setCellFactory(LogCell::new);
        logList.setPlaceholder(newPlaceholder());
        logList.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
        VBox.setVgrow(logList, Priority.ALWAYS);

        // 列表皮肤就绪后才取得到垂直滚动条，故每次重建皮肤都重新挂监听
        logList.skinProperty().addListener((obs, oldSkin, newSkin) -> {
            if (newSkin != null) {
                Platform.runLater(this::attachScrollListener);
            }
        });

        logList.setOnKeyPressed(e -> {
            if (e.isControlDown() && e.getCode() == KeyCode.C) {
                copySelectionOrAll();
                e.consume();
            }
        });
        logList.setContextMenu(buildContextMenu());

        clearBtn = new Button();
        clearBtn.getStyleClass().add("btn-ghost");
        clearBtn.setOnAction(e -> LogService.clear());

        copyBtn = new Button();
        copyBtn.getStyleClass().add("btn-ghost");
        copyBtn.setOnAction(e -> copySelectionOrAll());

        exportBtn = new Button();
        exportBtn.getStyleClass().add("btn-accent");
        exportBtn.setOnAction(e -> exportLog());

        HBox footer = new HBox(10, clearBtn, copyBtn, exportBtn);
        footer.getStyleClass().add("log-footer");
        footer.setAlignment(Pos.CENTER_RIGHT);

        VBox content = new VBox(8, logList, footer);
        content.getStyleClass().add("log-body");
        VBox.setVgrow(logList, Priority.ALWAYS);

        rootPane = new VBox(titleBar, content);
        rootPane.getStyleClass().add("app-root");
        VBox.setVgrow(content, Priority.ALWAYS);

        rootStack = new StackPane(rootPane);
        rootStack.getStyleClass().add("root");
        toast = new Toast(rootStack);

        Scene scene = new Scene(rootStack);
        scene.setFill(Color.TRANSPARENT);
        scene.getStylesheets().add(
                LogCompanionWindow.class.getResource(
                        "/hbnu/project/ergoutreecrypt/ui/styles/win11.css").toExternalForm());
        copyThemeClass();

        stage = new Stage();
        stage.initOwner(owner);
        stage.initStyle(StageStyle.TRANSPARENT);
        stage.setScene(scene);
        stage.getIcons().setAll(owner.getIcons());
        stage.setMinWidth(460);
        stage.setMinHeight(560);
        stage.setOnCloseRequest(e -> {
            e.consume();
            close();
        });

        applyTexts();

        // 用内存缓冲区的快照填充已有日志，再开始接收增量事件。
        logItems.addAll(LogService.snapshot());
        scrollToBottom();

        logListener = new LogListener() {
            @Override
            public void onEvent(LogEvent event) {
                Platform.runLater(() -> appendEvent(event));
            }

            @Override
            public void onCleared() {
                Platform.runLater(() -> {
                    logItems.clear();
                    stickToBottom = true;
                });
            }
        };
        LogService.addListener(logListener);
    }

    /**
     * 注册可见性变化回调。
     *
     * @param listener 回调，可为 null
     */
    public static void setOnVisibilityChanged(Runnable listener) {
        visibilityListener = listener;
    }

    /**
     * 日志窗当前是否可见。
     *
     * @return 可见时返回 {@code true}
     */
    public static boolean isShowing() {
        return instance != null && instance.stage.isShowing();
    }

    /**
     * 切换日志窗：已打开则关闭，否则在主窗右侧弹出。
     *
     * @param owner 主窗口
     */
    public static void toggle(Stage owner) {
        if (owner == null) {
            return;
        }
        if (isShowing()) {
            instance.close();
            return;
        }
        instance = new LogCompanionWindow(owner);
        instance.showAnimated();
        fireVisibilityChanged();
    }

    /**
     * 若日志窗已打开则关闭。主窗退出时调用。
     */
    public static void closeIfOpen() {
        if (instance != null) {
            instance.close();
        }
    }

    /**
     * 刷新已打开日志窗的文案（语言切换后调用）。
     */
    public static void applyTextsIfOpen() {
        if (instance != null && instance.stage.isShowing()) {
            instance.applyTexts();
        }
    }

    /**
     * 绑定主窗几何、展示并播放短入场动画。
     */
    private void showAnimated() {
        owner.xProperty().addListener(ownerGeomListener);
        owner.yProperty().addListener(ownerGeomListener);
        owner.widthProperty().addListener(ownerGeomListener);
        owner.heightProperty().addListener(ownerGeomListener);
        owner.addEventHandler(WindowEvent.WINDOW_HIDING, ownerCloseHandler);

        dockToOwner();
        boolean dockRight = isDockedRight();
        rootPane.setTranslateX(dockRight ? -28 : 28);
        stage.setOpacity(0);
        stage.show();
        dockToOwner();

        Timeline in = new Timeline(
                new KeyFrame(Duration.ZERO,
                        new KeyValue(stage.opacityProperty(), 0),
                        new KeyValue(rootPane.translateXProperty(), dockRight ? -28 : 28)),
                new KeyFrame(Duration.millis(220),
                        new KeyValue(stage.opacityProperty(), 1),
                        new KeyValue(rootPane.translateXProperty(), 0)));
        in.play();
    }

    /**
     * 关闭窗口并解除监听。
     */
    private void close() {
        LogService.removeListener(logListener);
        owner.xProperty().removeListener(ownerGeomListener);
        owner.yProperty().removeListener(ownerGeomListener);
        owner.widthProperty().removeListener(ownerGeomListener);
        owner.heightProperty().removeListener(ownerGeomListener);
        owner.removeEventHandler(WindowEvent.WINDOW_HIDING, ownerCloseHandler);
        if (stage.isShowing()) {
            stage.hide();
        }
        if (instance == this) {
            instance = null;
        }
        fireVisibilityChanged();
    }

    /**
     * 将伴生窗贴靠到主窗右侧或左侧，并同步宽高。
     */
    private void dockToOwner() {
        if (docking || !owner.isShowing()) {
            return;
        }
        docking = true;
        try {
            double width = owner.getWidth();
            double height = owner.getHeight();
            stage.setWidth(width);
            stage.setHeight(height);
            stage.setY(owner.getY());
            if (isDockedRight()) {
                stage.setX(owner.getX() + width);
            } else {
                stage.setX(owner.getX() - width);
            }
        } finally {
            docking = false;
        }
    }

    /**
     * 右侧是否放得下同等宽度的伴生窗。
     *
     * @return 右侧空间足够时返回 {@code true}
     */
    private boolean isDockedRight() {
        double proposedRight = owner.getX() + owner.getWidth() + owner.getWidth();
        List<Screen> screens = Screen.getScreensForRectangle(
                owner.getX(), owner.getY(), Math.max(1, owner.getWidth()), Math.max(1, owner.getHeight()));
        Screen screen = screens.isEmpty() ? Screen.getPrimary() : screens.get(0);
        Rectangle2D vis = screen.getVisualBounds();
        return proposedRight <= vis.getMaxX() + 12;
    }

    /**
     * 从主窗根节点复制 light/dark 样式类。
     */
    private void copyThemeClass() {
        Scene ownerScene = owner.getScene();
        if (ownerScene == null || ownerScene.getRoot() == null) {
            rootStack.getStyleClass().add("light");
            return;
        }
        for (String cls : ownerScene.getRoot().getStyleClass()) {
            if ("light".equals(cls) || "dark".equals(cls)) {
                rootStack.getStyleClass().add(cls);
                return;
            }
        }
        rootStack.getStyleClass().add("light");
    }

    /**
     * 刷新标题、按钮与占位文案。
     */
    private void applyTexts() {
        stage.setTitle(Messages.get("logs.title"));
        titleLabel.setText(Messages.get("logs.title"));
        clearBtn.setText(Messages.get("logs.clear"));
        copyBtn.setText(Messages.get("logs.copy"));
        exportBtn.setText(Messages.get("logs.export"));
        logList.setPlaceholder(newPlaceholder());
    }

    /**
     * 构建列表为空时的占位提示。
     *
     * @return 占位标签
     */
    private Label newPlaceholder() {
        Label hint = new Label(Messages.get("logs.empty"));
        hint.getStyleClass().add("log-hint");
        return hint;
    }

    /**
     * 构建列表的右键菜单。
     *
     * @return 含「复制」「复制全部」的菜单
     */
    private ContextMenu buildContextMenu() {
        MenuItem copy = new MenuItem();
        copy.setOnAction(e -> copySelectionOrAll());
        MenuItem copyAll = new MenuItem();
        copyAll.setOnAction(e -> copyText(LogService.exportText()));
        ContextMenu menu = new ContextMenu(copy, copyAll);
        // 文案在 applyTexts 之后才可用，故用 onShowing 延迟填充
        menu.setOnShowing(e -> {
            copy.setText(Messages.get("logs.copy"));
            copyAll.setText(Messages.get("logs.copyAll"));
        });
        return menu;
    }

    /**
     * 把新事件追加到列表，并在需要时恢复粘底。
     *
     * @param event 新事件
     */
    private void appendEvent(LogEvent event) {
        logItems.add(event);
        int excess = logItems.size() - MAX_LINES;
        if (excess > 0) {
            logItems.remove(0, excess);
        }
        if (stickToBottom) {
            scrollToBottom();
        }
    }

    /**
     * 滚动到末行。
     */
    private void scrollToBottom() {
        if (!logItems.isEmpty()) {
            logList.scrollTo(logItems.size() - 1);
        }
    }

    /**
     * 定位垂直滚动条并挂上位置监听。
     *
     * <p>列表皮肤会随样式重建，因此每次皮肤变化后都要重新定位。
     */
    private void attachScrollListener() {
        ScrollBar bar = (ScrollBar) logList.lookup(".scroll-bar:vertical");
        if (bar == null || bar == trackedScrollBar) {
            return;
        }
        if (trackedScrollBar != null) {
            trackedScrollBar.valueProperty().removeListener(scrollListener);
        }
        trackedScrollBar = bar;
        bar.valueProperty().addListener(scrollListener);
    }

    /**
     * 复制当前选中的行；没有选中行时复制全部日志。
     */
    private void copySelectionOrAll() {
        List<LogEvent> selected = List.copyOf(logList.getSelectionModel().getSelectedItems());
        if (selected.isEmpty()) {
            copyText(LogService.exportText());
            return;
        }
        StringBuilder sb = new StringBuilder(selected.size() * 96);
        for (LogEvent event : selected) {
            sb.append(event.formatLine()).append('\n');
        }
        copyText(sb.toString());
    }

    /**
     * 写入系统剪贴板并给出提示。
     *
     * @param text 待复制文本，为空时不做任何事
     */
    private void copyText(String text) {
        if (text == null || text.isEmpty()) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(text);
        Clipboard.getSystemClipboard().setContent(content);
        toast.success(Messages.get("logs.copied"));
    }

    /**
     * 将当前内存日志导出为 {@code .log} 文件。
     */
    private void exportLog() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("logs.export"));
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("Log (*.log)", "*.log"));
        chooser.setInitialFileName("ergoutreecrypt.log");
        java.io.File target = chooser.showSaveDialog(stage);
        if (target == null) {
            return;
        }
        try {
            Files.writeString(target.toPath(), LogService.exportText(), StandardCharsets.UTF_8);
            toast.success(Messages.get("logs.exportSuccess"));
        } catch (Exception ex) {
            toast.error(Messages.get("logs.exportFailed"));
        }
    }

    /**
     * 通知菜单等刷新可见性相关文案。
     */
    private static void fireVisibilityChanged() {
        Runnable listener = visibilityListener;
        if (listener != null) {
            Platform.runLater(listener);
        }
    }

    /**
     * 日志行渲染单元：等宽字体、按级别着色、自动换行。
     *
     * <p>每行一个 {@link LogEvent}，文本由 {@link LogEvent#formatLine()} 生成；
     * 级别只影响文字颜色，不改变文本内容，因此复制出来的文本与导出文件完全一致。
     */
    private static final class LogCell extends ListCell<LogEvent> {

        /** 复用的行标签，避免滚动时反复创建节点。 */
        private final Label label = new Label();

        /**
         * @param list 所属列表，行标签宽度随之绑定以支持自动换行
         */
        private LogCell(ListView<LogEvent> list) {
            label.getStyleClass().add("log-line");
            label.setWrapText(true);
            label.setMaxWidth(Double.MAX_VALUE);
            label.prefWidthProperty().bind(list.widthProperty().subtract(36));
        }

        @Override
        protected void updateItem(LogEvent event, boolean empty) {
            super.updateItem(event, empty);
            setText(null);
            if (empty || event == null) {
                setGraphic(null);
                return;
            }
            label.setText(event.formatLine());
            label.getStyleClass().removeAll(LEVEL_STYLE_CLASSES);
            label.getStyleClass().add(styleClassOf(event.level()));
            setGraphic(label);
        }

        /**
         * 取级别对应的样式类名。
         *
         * @param level 日志级别，可为 null
         * @return 对应级别的样式类名
         */
        private static String styleClassOf(LogLevel level) {
            if (level == null) {
                return "log-line-info";
            }
            return switch (level) {
                case ERROR -> "log-line-error";
                case WARN -> "log-line-warn";
                case TRACE -> "log-line-trace";
                case INFO -> "log-line-info";
            };
        }
    }
}
