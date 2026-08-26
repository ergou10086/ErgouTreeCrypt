package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogEvent;
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
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.ScrollBar;
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
 * 主窗移动或缩放时跟随，形成「两页书」的观感。内容为实时虚拟化日志列表，
 * 提供清空与导出。关闭本窗不影响主窗。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LogCompanionWindow {

    /** 当前打开的实例；同一时刻最多一个。 */
    private static LogCompanionWindow instance;

    /** 可见性变化回调（可选）。 */
    private static Runnable visibilityListener;

    /** 本窗 Stage。 */
    private final Stage stage;

    /** 主窗。 */
    private final Stage owner;

    /** 日志列表数据。 */
    private final ObservableList<LogEvent> items = FXCollections.observableArrayList();

    /** 根容器，用于入场位移动画。 */
    private final VBox rootPane;

    /** Toast 宿主。 */
    private final StackPane rootStack;

    private final Label titleLabel;
    private final Label emptyLabel;
    private final Button clearBtn;
    private final Button exportBtn;
    private final ListView<LogEvent> listView;
    private final Toast toast;
    private final LogListener logListener;

    /** 用户未上翻时自动滚到底部。 */
    private boolean stickToBottom = true;

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

        listView = new ListView<>(items);
        listView.getStyleClass().add("log-list");
        listView.setCellFactory(lv -> new LogCell());
        emptyLabel = new Label();
        emptyLabel.getStyleClass().add("field-hint");
        listView.setPlaceholder(emptyLabel);
        VBox.setVgrow(listView, Priority.ALWAYS);

        listView.setOnScroll(e -> updateStickToBottom());
        listView.setOnMouseReleased(e -> updateStickToBottom());

        clearBtn = new Button();
        clearBtn.getStyleClass().add("btn-ghost");
        clearBtn.setOnAction(e -> LogService.clear());

        exportBtn = new Button();
        exportBtn.getStyleClass().add("btn-accent");
        exportBtn.setOnAction(e -> exportLog());

        HBox footer = new HBox(10, clearBtn, exportBtn);
        footer.getStyleClass().add("log-footer");
        footer.setAlignment(Pos.CENTER_RIGHT);

        VBox content = new VBox(8, listView, footer);
        content.getStyleClass().add("log-body");
        VBox.setVgrow(listView, Priority.ALWAYS);

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
        items.setAll(LogService.snapshot());

        logListener = new LogListener() {
            @Override
            public void onEvent(LogEvent event) {
                Platform.runLater(() -> appendEvent(event));
            }

            @Override
            public void onCleared() {
                Platform.runLater(() -> {
                    items.clear();
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
     * 刷新标题与按钮文案。
     */
    private void applyTexts() {
        stage.setTitle(Messages.get("logs.title"));
        titleLabel.setText(Messages.get("logs.title"));
        emptyLabel.setText(Messages.get("logs.empty"));
        clearBtn.setText(Messages.get("logs.clear"));
        exportBtn.setText(Messages.get("logs.export"));
        listView.refresh();
    }

    /**
     * 追加一条日志并按需滚到底部。
     *
     * @param event 新事件
     */
    private void appendEvent(LogEvent event) {
        items.add(event);
        if (stickToBottom) {
            listView.scrollTo(items.size() - 1);
        }
    }

    /**
     * 根据垂直滚动条位置决定是否继续粘底。
     */
    private void updateStickToBottom() {
        ScrollBar bar = (ScrollBar) listView.lookup(".scroll-bar:vertical");
        if (bar == null) {
            stickToBottom = true;
            return;
        }
        stickToBottom = bar.getValue() >= bar.getMax() - 0.08;
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
     * 按级别着色的日志行单元格。
     */
    private static final class LogCell extends ListCell<LogEvent> {

        @Override
        protected void updateItem(LogEvent item, boolean empty) {
            super.updateItem(item, empty);
            getStyleClass().removeAll("log-error", "log-warn", "log-info", "log-trace");
            if (empty || item == null) {
                setText(null);
                return;
            }
            setText(item.formatLine());
            setWrapText(true);
            switch (item.level()) {
                case ERROR -> getStyleClass().add("log-error");
                case WARN -> getStyleClass().add("log-warn");
                case TRACE -> getStyleClass().add("log-trace");
                default -> getStyleClass().add("log-info");
            }
        }
    }
}
