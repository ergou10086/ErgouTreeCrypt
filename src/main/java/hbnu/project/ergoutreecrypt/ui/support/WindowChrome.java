package hbnu.project.ergoutreecrypt.ui.support;

import javafx.geometry.Pos;
import javafx.scene.Cursor;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

import java.util.function.Supplier;

/**
 * 无边框窗口的自定义窗口装饰行为。
 *
 * <p>为使用自绘标题栏（undecorated stage）的窗口提供两类交互：
 * <ul>
 *   <li><b>标题栏拖动</b>——按住标题栏拖拽移动窗口</li>
 *   <li><b>四角缩放</b>——在窗口四角放置透明手柄，等比例缩放窗口</li>
 * </ul>
 *
 * <p>本类只负责窗口层面的交互，不依赖任何业务状态，可被任意使用自绘标题栏的窗口复用，
 * 从而将这部分与业务无关的逻辑从主控制器中剥离。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class WindowChrome {

    /** 承载缩放手柄的根容器。 */
    private final StackPane rootStack;

    /** 可拖动窗口的标题栏。 */
    private final HBox titleBar;

    /** 当前窗口 {@link Stage} 的提供者（场景就绪后才可安全获取）。 */
    private final Supplier<Stage> stageSupplier;

    /**
     * 创建窗口装饰行为绑定器。
     *
     * @param rootStack     承载缩放手柄的根 {@link StackPane}
     * @param titleBar      可拖动窗口的标题栏容器
     * @param stageSupplier 提供当前 {@link Stage} 的函数
     */
    public WindowChrome(final StackPane rootStack, final HBox titleBar,
                        final Supplier<Stage> stageSupplier) {
        this.rootStack = rootStack;
        this.titleBar = titleBar;
        this.stageSupplier = stageSupplier;
    }

    /**
     * 安装标题栏拖动与四角缩放行为。
     *
     * <p>应在场景与窗口就绪后调用（如 {@code attachScene}）。
     */
    public void install() {
        enableWindowDrag();
        enableCornerResize();
    }

    /**
     * 启用标题栏按住拖动移动窗口。
     */
    private void enableWindowDrag() {
        final double[] offset = new double[2];
        titleBar.setOnMousePressed(e -> {
            offset[0] = e.getSceneX();
            offset[1] = e.getSceneY();
        });
        titleBar.setOnMouseDragged(e -> {
            Stage s = stage();
            s.setX(e.getScreenX() - offset[0]);
            s.setY(e.getScreenY() - offset[1]);
        });
    }

    /**
     * 在窗口四角放置不可见的拖拽手柄，实现等比例缩放。
     *
     * <p>仅四角可拖拽，边框中点不响应。拖拽时保持窗口当前宽高比不变。
     * 最大化时手柄自动禁用（由 {@code .maximized} CSS 类配合隐藏）。
     */
    private void enableCornerResize() {
        final double gripSize = 8;
        Region tl = cornerGrip(gripSize, Cursor.NW_RESIZE, -1, -1);
        Region tr = cornerGrip(gripSize, Cursor.NE_RESIZE, 1, -1);
        Region bl = cornerGrip(gripSize, Cursor.SW_RESIZE, -1, 1);
        Region br = cornerGrip(gripSize, Cursor.SE_RESIZE, 1, 1);

        StackPane.setAlignment(tl, Pos.TOP_LEFT);
        StackPane.setAlignment(tr, Pos.TOP_RIGHT);
        StackPane.setAlignment(bl, Pos.BOTTOM_LEFT);
        StackPane.setAlignment(br, Pos.BOTTOM_RIGHT);

        // 手柄置于最顶层，但不阻挡内容交互（尺寸极小，仅角部区域）
        tl.setViewOrder(-100);
        tr.setViewOrder(-100);
        bl.setViewOrder(-100);
        br.setViewOrder(-100);

        rootStack.getChildren().addAll(tl, tr, bl, br);
    }

    /**
     * 创建一个透明的角部拖拽手柄。
     *
     * @param size   手柄尺寸 (px)
     * @param cursor 鼠标悬停光标
     * @param signX  宽度变化方向：1=向右扩展，-1=向左扩展
     * @param signY  高度变化方向：1=向下扩展，-1=向上扩展
     * @return 配置好交互事件的手柄区域
     */
    private Region cornerGrip(final double size, final Cursor cursor,
                             final int signX, final int signY) {
        Region grip = new Region();
        grip.setPrefSize(size, size);
        grip.setMinSize(size, size);
        grip.setMaxSize(size, size);
        grip.setCursor(cursor);
        grip.setStyle("-fx-background-color: transparent;");

        final double[] startScreenX = new double[1];
        final double[] startScreenY = new double[1];
        final double[] startW = new double[1];
        final double[] startH = new double[1];
        final double[] startStageX = new double[1];
        final double[] startStageY = new double[1];

        grip.setOnMousePressed(e -> {
            if (stage().isMaximized()) {
                return;
            }
            startScreenX[0] = e.getScreenX();
            startScreenY[0] = e.getScreenY();
            startW[0] = stage().getWidth();
            startH[0] = stage().getHeight();
            startStageX[0] = stage().getX();
            startStageY[0] = stage().getY();
            e.consume();
        });

        grip.setOnMouseDragged(e -> {
            if (stage().isMaximized()) {
                return;
            }
            double dx = (e.getScreenX() - startScreenX[0]) * signX;
            double dy = (e.getScreenY() - startScreenY[0]) * signY;

            double aspect = startW[0] / startH[0];

            // 以变化较大的维度为基准，另一维度按比例跟随
            double newW;
            double newH;
            if (Math.abs(dx / aspect) > Math.abs(dy)) {
                newW = startW[0] + dx;
                newH = newW / aspect;
            } else {
                newH = startH[0] + dy;
                newW = newH * aspect;
            }

            // 应用最小尺寸约束
            if (newW < stage().getMinWidth()) {
                newW = stage().getMinWidth();
                newH = newW / aspect;
            }
            if (newH < stage().getMinHeight()) {
                newH = stage().getMinHeight();
                newW = newH * aspect;
            }

            // 对于左/上角拖拽，同步调整窗口位置
            if (signX < 0) {
                stage().setX(startStageX[0] + (startW[0] - newW));
            }
            if (signY < 0) {
                stage().setY(startStageY[0] + (startH[0] - newH));
            }

            stage().setWidth(newW);
            stage().setHeight(newH);
            e.consume();
        });

        return grip;
    }

    /**
     * 获取当前窗口 {@link Stage}。
     *
     * @return 当前窗口
     */
    private Stage stage() {
        return stageSupplier.get();
    }
}
