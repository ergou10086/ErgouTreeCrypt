package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode;
import hbnu.project.ergoutreecrypt.version.AppVersion;
import hbnu.project.ergoutreecrypt.volume.EncryptRequest;
import javafx.application.Platform;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ScrollPane;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** 实际设置对话框的切换、重新打开与任务快照验证。 */
@EnabledIfSystemProperty(named="ergoutreecrypt.uiTests", matches="true")
class SplitSettingsUiTest {
    /** @throws Exception 设置未持久化或版本资源不同步 */
    @Test void bothModesPersistAndReachNewTasks() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        Platform.startup(() -> { Platform.setImplicitExit(false); ready.countDown(); });
        assertTrue(ready.await(15, TimeUnit.SECONDS));
        SplitMetadataMode saved = SettingsManager.getSplitMetadataMode();
        try {
            for (SplitMetadataMode mode : SplitMetadataMode.values()) {
                fx(() -> {
                    var dialog = SettingsDialog.createDialog(null, null);
                    ComboBox<?> combo = (ComboBox<?>) ((ScrollPane) dialog.getDialogPane().getContent()).getContent().lookup("#splitMetadataMode");
                    assertNotNull(combo);
                    combo.getSelectionModel().select(mode.ordinal());
                    assertEquals(mode, SettingsManager.getSplitMetadataMode());
                    assertEquals(mode, new EncryptRequest().getSplitMetadataMode());
                    var reopened = SettingsDialog.createDialog(null, null);
                    assertEquals(Messages.get(mode.getLabelKey()), ((ComboBox<?>) ((ScrollPane) reopened.getDialogPane().getContent()).getContent().lookup("#splitMetadataMode")).getValue());
                    return null;
                });
            }
            assertEquals(System.getProperty("split.expected.version"), AppVersion.get());
        } finally { SettingsManager.setSplitMetadataMode(saved); }
    }
    /** @param action FX 操作 @param <T> 返回类型 @return 操作结果 @throws Exception FX 操作失败 */
    private static <T> T fx(Callable<T> action) throws Exception {
        FutureTask<T> task = new FutureTask<>(action); Platform.runLater(task); return task.get(20, TimeUnit.SECONDS);
    }
}
