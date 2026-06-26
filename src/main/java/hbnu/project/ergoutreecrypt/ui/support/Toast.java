package hbnu.project.ergoutreecrypt.ui.support;

import javafx.animation.FadeTransition;
import javafx.animation.PauseTransition;
import javafx.animation.SequentialTransition;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.util.Duration;

/**
 * 轻量级 Toast 提示
 *
 * <p>挂在根 {@link StackPane} 底部居中，淡入 → 停留 → 淡出后自动移除，不打断用户操作。
 *
 * @author ErgouTree
 */
public final class Toast {

    private final StackPane host;

    public Toast(StackPane host) {
        this.host = host;
    }

    public void info(String text) {
        show(text, Type.INFO);
    }

    public void success(String text) {
        show(text, Type.SUCCESS);
    }

    public void error(String text) {
        show(text, Type.ERROR);
    }

    private void show(String text, Type type) {
        Label label = new Label(text);
        label.getStyleClass().addAll("toast", switch (type) {
            case SUCCESS -> "toast-success";
            case ERROR -> "toast-error";
            default -> "toast-info";
        });
        StackPane.setAlignment(label, Pos.BOTTOM_CENTER);
        StackPane.setMargin(label, new Insets(0, 0, 32, 0));
        host.getChildren().add(label);

        FadeTransition in = new FadeTransition(Duration.millis(180), label);
        in.setFromValue(0);
        in.setToValue(1);
        PauseTransition stay = new PauseTransition(Duration.millis(2200));
        FadeTransition out = new FadeTransition(Duration.millis(280), label);
        out.setFromValue(1);
        out.setToValue(0);

        SequentialTransition seq = new SequentialTransition(in, stay, out);
        seq.setOnFinished(e -> host.getChildren().remove(label));
        seq.play();
    }

    /**
     * 提示类型，决定底色样式。
     */
    public enum Type {INFO, SUCCESS, ERROR}
}
