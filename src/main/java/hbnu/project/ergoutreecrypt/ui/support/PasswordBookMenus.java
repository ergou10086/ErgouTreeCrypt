package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.passwordbook.DesktopPasswordBookStore;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.passwordbook.PasswordBookEntry;
import javafx.scene.control.MenuButton;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextInputControl;
import org.controlsfx.control.textfield.CustomPasswordField;
import org.controlsfx.control.textfield.CustomTextField;

import java.io.IOException;
import java.util.List;

/**
 * 为桌面端密码输入框安装密码本下拉菜单。
 *
 * @author ErgouTree
 * @since 2026/9/22
 */
public final class PasswordBookMenus {

    private PasswordBookMenus() {
    }

    /**
     * 为单个密码输入框安装下拉菜单。
     *
     * @param field 密码输入框，必须是 ControlsFX 自定义输入框
     */
    public static void install(TextInputControl field) {
        install(field, null);
    }

    /**
     * 为隐藏与明文显示状态共用的密码输入框安装下拉菜单。
     *
     * @param primary   主要密码输入框，必须是 ControlsFX 自定义输入框
     * @param alternate 可选的同步输入框
     */
    public static void install(TextInputControl primary, TextInputControl alternate) {
        MenuButton menu = new MenuButton("▾");
        menu.getStyleClass().add("password-book-menu");
        menu.setFocusTraversable(false);
        menu.setOnShowing(event -> refresh(menu, primary, alternate));
        setRightNode(primary, menu);

        if (alternate != null) {
            MenuButton alternateMenu = new MenuButton("▾");
            alternateMenu.getStyleClass().add("password-book-menu");
            alternateMenu.setFocusTraversable(false);
            alternateMenu.setOnShowing(event -> refresh(alternateMenu, primary, alternate));
            setRightNode(alternate, alternateMenu);
        }
    }

    /**
     * 按最新密码本内容刷新菜单项。
     *
     * @param menu      待刷新菜单
     * @param primary   主要密码输入框
     * @param alternate 可选的同步输入框
     */
    private static void refresh(MenuButton menu, TextInputControl primary,
                                TextInputControl alternate) {
        menu.getItems().clear();
        List<PasswordBookEntry> entries;
        try {
            entries = DesktopPasswordBookStore.load();
        } catch (IOException | SecurityException exception) {
            MenuItem error = new MenuItem(Messages.get("passwordBook.error"));
            error.setDisable(true);
            menu.getItems().add(error);
            return;
        }
        if (entries.isEmpty()) {
            MenuItem empty = new MenuItem(Messages.get("passwordBook.empty"));
            empty.setDisable(true);
            menu.getItems().add(empty);
            return;
        }
        for (PasswordBookEntry entry : entries) {
            MenuItem item = new MenuItem(entry.getName());
            item.setOnAction(event -> {
                primary.setText(entry.getPassword());
                if (alternate != null) {
                    alternate.setText(entry.getPassword());
                }
            });
            menu.getItems().add(item);
        }
    }

    /**
     * 设置 ControlsFX 输入框的右侧节点。
     *
     * @param field 输入框
     * @param menu  密码本菜单按钮
     */
    private static void setRightNode(TextInputControl field, MenuButton menu) {
        if (field instanceof CustomPasswordField passwordField) {
            passwordField.setRight(menu);
        } else if (field instanceof CustomTextField textField) {
            textField.setRight(menu);
        } else {
            throw new IllegalArgumentException("密码本菜单需要 CustomPasswordField 或 CustomTextField");
        }
    }
}
