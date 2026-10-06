package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import java.util.List;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises ZIPX format and native password controls in both actual desktop FXML views. */
@EnabledIfSystemProperty(named = "ergoutreecrypt.uiTests", matches = "true")
class ZipxDesktopUiTest {
    /** Starts JavaFX for the opt-in UI regression. */
    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        Platform.startup(() -> { Platform.setImplicitExit(false); ready.countDown(); });
        assertTrue(ready.await(15, TimeUnit.SECONDS));
    }

    /** ZIPX password fields remain visible independently of the custom encryption switch. */
    @Test void generalAndMediaViewsExposeNativeZipx() throws Exception {
        boolean saved = SettingsManager.isArchiveCustomEncryption();
        SettingsManager.setArchiveCustomEncryption(false);
        try {
            FutureTask<Void> task = new FutureTask<>(() -> {
                for (boolean media : List.of(false, true)) {
                    FXMLLoader loader = new FXMLLoader(getClass().getResource("/hbnu/project/ergoutreecrypt/ui/" + (media ? "av-view.fxml" : "main-view.fxml")));
                    loader.load();
                    var controls = loader.getNamespace();
                    @SuppressWarnings("unchecked") ComboBox<String> formats = (ComboBox<String>) controls.get(media ? "avCompressFormatCombo" : "compressFormatCombo");
                    ((CheckBox) controls.get(media ? "avCompressAfterCheck" : "compressAfterCheck")).setSelected(true);
                    assertTrue(formats.getItems().contains("ZIPX")); formats.setValue("ZIPX");
                    assertTrue(((PasswordField) controls.get(media ? "avArchivePasswordField" : "archivePasswordField")).isVisible());
                    assertFalse(((Label) controls.get(media ? "avArchiveEncryptionNotice" : "archiveEncryptionNotice")).isVisible());
                }
                return null;
            });
            Platform.runLater(task); task.get(30, TimeUnit.SECONDS);
        } finally { SettingsManager.setArchiveCustomEncryption(saved); }
    }
}
