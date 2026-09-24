package hbnu.project.ergoutreecrypt.ui.support;

import javafx.geometry.Rectangle2D;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.stage.Modality;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;

import java.util.Objects;

/**
 * 为桌面对话框统一提供主题、原生窗口操作和屏幕边界约束。
 */
final class DialogSupport {

    /** 禁止实例化。 */
    private DialogSupport() {
    }

    /**
     * 配置可拖动、可缩放的对话框，并继承父窗口的明暗主题。
     *
     * @param dialog 待显示的对话框
     * @param owner 父窗口，可为空
     * @param width 默认窗口宽度
     * @param height 默认窗口高度
     */
    static void configure(Dialog<?> dialog, Window owner, double width, double height) {
        dialog.initOwner(owner);
        dialog.initModality(Modality.WINDOW_MODAL);
        dialog.initStyle(StageStyle.DECORATED);
        dialog.setResizable(true);
        DialogPane pane = dialog.getDialogPane();
        if (!pane.getStyleClass().contains("root")) {
            pane.getStyleClass().add("root");
        }
        boolean dark = owner != null && owner.getScene() != null
                && owner.getScene().getRoot().getStyleClass().contains("dark");
        pane.getStyleClass().removeAll("light", "dark");
        pane.getStyleClass().add(dark ? "dark" : "light");
        pane.getStylesheets().add(Objects.requireNonNull(DialogSupport.class.getResource(
                "/hbnu/project/ergoutreecrypt/ui/styles/win11.css")).toExternalForm());
        pane.getStyleClass().add("desktop-dialog");
        pane.setMinSize(0, 0);
        pane.setPrefSize(width, height);
        dialog.setOnShown(event -> {
            Rectangle2D bounds = screenBounds(owner);
            double fittedWidth = Math.min(width, bounds.getWidth() - 24);
            double fittedHeight = Math.min(height, bounds.getHeight() - 24);
            Stage stage = (Stage) pane.getScene().getWindow();
            stage.setMinWidth(Math.min(380, fittedWidth));
            stage.setMinHeight(Math.min(300, fittedHeight));
            stage.setWidth(fittedWidth);
            stage.setHeight(fittedHeight);
            double centerX = owner == null ? bounds.getMinX() + bounds.getWidth() / 2
                    : owner.getX() + owner.getWidth() / 2;
            double centerY = owner == null ? bounds.getMinY() + bounds.getHeight() / 2
                    : owner.getY() + owner.getHeight() / 2;
            stage.setX(Math.max(bounds.getMinX() + 12,
                    Math.min(centerX - fittedWidth / 2, bounds.getMaxX() - fittedWidth - 12)));
            stage.setY(Math.max(bounds.getMinY() + 12,
                    Math.min(centerY - fittedHeight / 2, bounds.getMaxY() - fittedHeight - 12)));
        });
    }

    /**
     * 获取父窗口所在显示器的可用区域，排除任务栏。
     *
     * @param owner 父窗口，可为空
     * @return 显示器可用区域
     */
    private static Rectangle2D screenBounds(Window owner) {
        if (owner != null) {
            var screens = Screen.getScreensForRectangle(
                    owner.getX(), owner.getY(), owner.getWidth(), owner.getHeight());
            if (!screens.isEmpty()) {
                return screens.getFirst().getVisualBounds();
            }
        }
        return Screen.getPrimary().getVisualBounds();
    }
}
