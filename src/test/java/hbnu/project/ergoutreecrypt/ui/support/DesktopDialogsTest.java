package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.passwordbook.PasswordBookEntry;
import hbnu.project.ergoutreecrypt.version.AppVersion;
import javafx.application.Platform;
import javafx.geometry.Orientation;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 真实 JavaFX 控件回归测试；使用 -Dergoutreecrypt.uiTests=true 在有显示器的环境运行。
 * 所有密码均为测试样例，不读取或写入用户的密码本及设置。
 */
@EnabledIfSystemProperty(named = "ergoutreecrypt.uiTests", matches = "true")
class DesktopDialogsTest {
    /** 初始化 JavaFX，允许连续打开和关闭测试窗口。 */
    @BeforeAll
    static void startToolkit() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        Platform.startup(() -> {
            Platform.setImplicitExit(false);
            started.countDown();
        });
        assertTrue(started.await(15, TimeUnit.SECONDS));
    }

    /** 每个用例结束后关闭本测试进程的全部窗口。 */
    @AfterEach
    void closeWindows() throws Exception {
        onFx(() -> {
            new ArrayList<>(Window.getWindows()).forEach(Window::hide);
            return null;
        });
    }

    /** 浅色和深色下直接输入、切换字段、不按 Enter 保存均不会丢失内容。 */
    @Test
    void editsAndSavesWithoutEnterInBothThemes() throws Exception {
        onFx(() -> {
            for (String theme : List.of("light", "dark")) {
                Stage owner = owner(theme);
                AtomicReference<List<PasswordBookEntry>> saved = new AtomicReference<>();
                Dialog<ButtonType> dialog = PasswordBookDialog.createDialog(owner, List.of(), saved::set);
                dialog.show();
                layout(dialog);
                assertTrue(dialog.getDialogPane().getStyleClass().contains(theme));
                button(dialog, "#password-book-add").fire();
                layout(dialog);
                TableView<?> table = table(dialog);
                assertEquals(1, table.getItems().size());
                TextField name = editor(table, 0, 0);
                TextField password = editor(table, 0, 1);
                name.requestFocus();
                name.setText("测试邮箱");
                password.requestFocus();
                password.setText("sample, value!");
                assertEquals("测试邮箱", table.getColumns().get(0).getCellObservableValue(0).getValue());
                assertEquals("sample, value!", table.getColumns().get(1).getCellObservableValue(0).getValue());
                assertReadable(name, theme);
                assertReadable(password, theme);
                snapshot(dialog, "password-book-" + theme);
                saveButton(dialog).fire();
                assertFalse(dialog.isShowing());
                assertEquals(List.of(new PasswordBookEntry("测试邮箱", "sample, value!")), saved.get());
                Dialog<ButtonType> reopened = PasswordBookDialog.createDialog(owner, saved.get(), saved::set);
                reopened.show();
                layout(reopened);
                assertEquals("sample, value!", editor(table(reopened), 0, 1).getText());
                reopened.close();
                owner.close();
            }
            return null;
        });
    }

    /** 保存失败后保留窗口和输入，支持在同一窗口重试。 */
    @Test
    void keepsDraftAfterSaveFailureAndRetries() throws Exception {
        onFx(() -> {
            AtomicInteger attempts = new AtomicInteger();
            AtomicReference<List<PasswordBookEntry>> saved = new AtomicReference<>();
            Dialog<ButtonType> dialog = PasswordBookDialog.createDialog(owner("dark"),
                    List.of(new PasswordBookEntry("测试", "old")), entries -> {
                        if (attempts.getAndIncrement() == 0) {
                            throw new IOException("测试写入失败");
                        }
                        saved.set(entries);
                    });
            dialog.show();
            layout(dialog);
            editor(table(dialog), 0, 1).setText("new");
            saveButton(dialog).fire();
            assertTrue(dialog.isShowing());
            assertEquals("new", editor(table(dialog), 0, 1).getText());
            assertTrue(((Label) dialog.getDialogPane().lookup("#password-book-error")).getText()
                    .contains("测试写入失败"));
            saveButton(dialog).fire();
            assertFalse(dialog.isShowing());
            assertEquals(List.of(new PasswordBookEntry("测试", "new")), saved.get());
            return null;
        });
    }

    /** 有密码但无名称时明确报错，取消不会调用保存操作。 */
    @Test
    void rejectsUnnamedPasswordAndCancelDiscardsDraft() throws Exception {
        onFx(() -> {
            AtomicInteger saves = new AtomicInteger();
            Dialog<ButtonType> dialog = PasswordBookDialog.createDialog(owner("light"),
                    List.of(new PasswordBookEntry("", "sample")), entries -> saves.incrementAndGet());
            dialog.show();
            layout(dialog);
            saveButton(dialog).fire();
            assertTrue(dialog.isShowing());
            assertEquals(0, saves.get());
            assertFalse(((Label) dialog.getDialogPane().lookup("#password-book-error")).getText().isBlank());
            ((Button) dialog.getDialogPane().lookupButton(ButtonType.CANCEL)).fire();
            assertFalse(dialog.isShowing());
            assertEquals(0, saves.get());
            return null;
        });
    }

    /** 滚动复用单元格及删除记录后，输入仍绑定正确记录。 */
    @Test
    void virtualizedCellsKeepTheirOwnRows() throws Exception {
        onFx(() -> {
            List<PasswordBookEntry> entries = new ArrayList<>();
            for (int i = 0; i < 80; i++) {
                entries.add(new PasswordBookEntry("测试" + i, "value" + i));
            }
            AtomicReference<List<PasswordBookEntry>> saved = new AtomicReference<>();
            Dialog<ButtonType> dialog = PasswordBookDialog.createDialog(owner("light"), entries, saved::set);
            dialog.show();
            layout(dialog);
            TableView<?> table = table(dialog);
            editor(table, 0, 1).setText("first-updated");
            table.scrollTo(79);
            layout(dialog);
            editor(table, 79, 1).setText("last-updated");
            table.getSelectionModel().select(1);
            button(dialog, "#password-book-remove").fire();
            layout(dialog);
            saveButton(dialog).fire();
            assertEquals(79, saved.get().size());
            assertEquals("first-updated", saved.get().getFirst().getPassword());
            assertEquals("last-updated", saved.get().getLast().getPassword());
            assertEquals(new PasswordBookEntry("测试2", "value2"), saved.get().get(1));
            return null;
        });
    }

    /** 设置窗口在两个主题下均限高、可缩放、可移动，并保持关闭按钮可见。 */
    @Test
    void settingsScrollAndResizeInBothThemes() throws Exception {
        for (String theme : List.of("light", "dark")) {
            Dialog<Void> dialog = onFx(() -> {
                Dialog<Void> created = SettingsDialog.createDialog(owner(theme), null);
                created.show();
                return created;
            });
            onFx(() -> {
                layout(dialog);
                Stage stage = (Stage) dialog.getDialogPane().getScene().getWindow();
                assertEquals(StageStyle.DECORATED, stage.getStyle());
                assertTrue(stage.isResizable());
                assertEquals(520, stage.getWidth(), 1);
                assertTrue(stage.getHeight() <= 720);
                assertTrue(stage.getHeight() <= Screen.getPrimary().getVisualBounds().getHeight());
                ScrollPane scroll = (ScrollPane) dialog.getDialogPane().getContent();
                assertTrue(scroll.isFitToWidth());
                assertEquals(ScrollPane.ScrollBarPolicy.NEVER, scroll.getHbarPolicy());
                assertTrue(scroll.getContent().getLayoutBounds().getHeight() > scroll.getViewportBounds().getHeight());
                assertEquals(7, dialog.getDialogPane().lookupAll(".settings-divider").size());
                assertTrue(scroll.lookupAll(".scroll-bar").stream()
                        .anyMatch(node -> node instanceof ScrollBar bar
                                && bar.getOrientation() == Orientation.VERTICAL && bar.isVisible()));
                snapshot(dialog, "settings-" + theme);
                stage.setWidth(420);
                stage.setHeight(380);
                stage.setX(stage.getX() + 8);
                stage.setY(stage.getY() + 8);
                return null;
            });
            onFx(() -> {
                layout(dialog);
                ScrollPane scroll = (ScrollPane) dialog.getDialogPane().getContent();
                scroll.setVvalue(1);
                layout(dialog);
                Node close = dialog.getDialogPane().lookupButton(dialog.getDialogPane().getButtonTypes().getFirst());
                assertTrue(close.isVisible());
                assertTrue(close.localToScene(close.getBoundsInLocal()).getMaxY()
                        <= dialog.getDialogPane().getScene().getHeight() + 1);
                assertTrue(scroll.getContent().lookupAll(".label").stream()
                        .anyMatch(node -> node instanceof Label label && label.getText().contains(AppVersion.get())));
                snapshot(dialog, "settings-small-" + theme);
                dialog.close();
                return null;
            });
        }
    }

    /**
     * 创建仅用于测试的主题父窗口。
     *
     * @param theme 主题样式类
     * @return 已显示的父窗口
     */
    private static Stage owner(String theme) {
        StackPane root = new StackPane();
        root.getStyleClass().add(theme);
        Stage owner = new Stage();
        owner.setScene(new Scene(root, 520, 720));
        owner.show();
        return owner;
    }

    /**
     * 应用样式并执行布局。
     *
     * @param dialog 测试对话框
     */
    private static void layout(Dialog<?> dialog) {
        dialog.getDialogPane().applyCss();
        dialog.getDialogPane().layout();
    }

    /**
     * 获取密码本表格。
     *
     * @param dialog 密码本窗口
     * @return 表格控件
     */
    private static TableView<?> table(Dialog<?> dialog) {
        return (TableView<?>) dialog.getDialogPane().lookup("#password-book-table");
    }

    /**
     * 获取指定按钮。
     *
     * @param dialog 对话框
     * @param selector 按钮选择器
     * @return 按钮
     */
    private static Button button(Dialog<?> dialog, String selector) {
        return (Button) dialog.getDialogPane().lookup(selector);
    }

    /**
     * 获取保存按钮。
     *
     * @param dialog 密码本对话框
     * @return 保存按钮
     */
    private static Button saveButton(Dialog<?> dialog) {
        return (Button) dialog.getDialogPane().lookupButton(dialog.getDialogPane().getButtonTypes().getFirst());
    }

    /**
     * 获取已渲染行的常驻输入框。
     *
     * @param table 密码表格
     * @param row 行号
     * @param column 列号
     * @return 输入框
     */
    private static TextField editor(TableView<?> table, int row, int column) {
        return table.lookupAll(".table-cell").stream()
                .filter(node -> node instanceof TableCell<?, ?> cell && cell.getIndex() == row
                        && cell.getTableColumn() == table.getColumns().get(column))
                .map(node -> (TextField) ((TableCell<?, ?>) node).getGraphic())
                .findFirst().orElseThrow();
    }

    /**
     * 验证输入文字和背景不是透明色，且当前主题使用正确的文字色。
     *
     * @param field 输入框
     * @param theme 主题名称
     */
    private static void assertReadable(TextField field, String theme) {
        Color foreground = (Color) field.lookupAll(".text").stream()
                .filter(node -> node instanceof javafx.scene.text.Text text && text.getText().equals(field.getText()))
                .map(node -> ((javafx.scene.text.Text) node).getFill()).findFirst().orElseThrow();
        assertEquals(1, foreground.getOpacity());
        assertEquals(Color.web(theme.equals("dark") ? "#f2f2f2" : "#1a1a1a"), foreground);
        Color background = (Color) field.getBackground().getFills().getFirst().getFill();
        assertEquals(1, background.getOpacity());
        assertNotEquals(background, foreground);
    }

    /**
     * 保存仅含测试数据的渲染快照用于人工核验。
     *
     * @param dialog 测试窗口
     * @param name 快照文件名
     * @throws IOException 保存失败时抛出
     */
    private static void snapshot(Dialog<?> dialog, String name) throws IOException {
        WritableImage image = dialog.getDialogPane().snapshot(null, null);
        BufferedImage output = new BufferedImage((int) image.getWidth(), (int) image.getHeight(), BufferedImage.TYPE_INT_ARGB);
        for (int y = 0; y < output.getHeight(); y++) {
            for (int x = 0; x < output.getWidth(); x++) {
                output.setRGB(x, y, image.getPixelReader().getArgb(x, y));
            }
        }
        Path path = Path.of("target", "ui-regression", name + ".png");
        Files.createDirectories(path.getParent());
        ImageIO.write(output, "png", path.toFile());
    }

    /**
     * 在 JavaFX 线程执行并将异常传回测试线程。
     *
     * @param action 待执行操作
     * @param <T> 返回值类型
     * @return 执行结果
     * @throws Exception 操作失败或等待超时时抛出
     */
    private static <T> T onFx(Callable<T> action) throws Exception {
        FutureTask<T> task = new FutureTask<>(action);
        Platform.runLater(task);
        return task.get(30, TimeUnit.SECONDS);
    }
}
