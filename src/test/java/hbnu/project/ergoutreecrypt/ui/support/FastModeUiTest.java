package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.ui.MainController;
import hbnu.project.ergoutreecrypt.volume.*;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TextArea;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** 实际 JavaFX FXML 模式切换、标准配置恢复及任务快照回归。 */
@EnabledIfSystemProperty(named="ergoutreecrypt.uiTests", matches="true")
final class FastModeUiTest {
    /** @throws Exception 实际界面加载或快照验证失败 */
    @Test void switchRestoresStandardAndSnapshotsFolderMode() throws Exception {
        var ready = new CountDownLatch(1);
        Platform.startup(() -> { Platform.setImplicitExit(false); ready.countDown(); });
        assertTrue(ready.await(15, TimeUnit.SECONDS));
        var task = new FutureTask<Void>(() -> {
            var loader = new FXMLLoader(MainController.class.getResource("main-view.fxml"));
            Parent root = loader.load();
            new Scene(root);
            var controller = loader.<MainController>getController();
            var fast = (CheckBox) loader.getNamespace().get("fastCheck");
            var rs = (CheckBox) loader.getNamespace().get("reedSolomonCheck");
            var comments = (TextArea) loader.getNamespace().get("commentsArea");
            rs.setSelected(true);
            comments.setText("标准备注");
            fast.setSelected(true);
            assertFalse(rs.isSelected());
            assertTrue(rs.isDisabled());
            assertTrue(comments.isDisabled());
            assertEquals("", comments.getText());
            var build = MainController.class.getDeclaredMethod("buildFolderEncryptOptions",
                    String.class, String.class, String.class, String.class, String.class);
            build.setAccessible(true);
            var queued = (FolderCrypt.EncryptOptions) build.invoke(controller,"密码", "ZIP", "归档密码", null, null);
            assertEquals(EncryptionMode.FAST, queued.mode);
            assertNull(queued.argon2MemoryKib);
            assertEquals("归档密码", queued.preArchivePassword);
            fast.setSelected(false);
            assertTrue(rs.isSelected());
            assertFalse(rs.isDisabled());
            assertEquals("标准备注", comments.getText());
            assertEquals(EncryptionMode.FAST, queued.mode);
            assertFalse(queued.reedSolomon);
            return null;
        });
        Platform.runLater(task);
        task.get(45, TimeUnit.SECONDS);
    }
}
