package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import java.util.List;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Load real FXML and exercise format/password/compatibility notice visibility. */
@EnabledIfSystemProperty(named="ergoutreecrypt.uiTests", matches="true")
class Lz4DesktopUiTest {
    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        Platform.startup(() -> { Platform.setImplicitExit(false); latch.countDown(); });
        assertTrue(latch.await(15, TimeUnit.SECONDS));
    }
    @Test void generalAndMediaScreensExposeLz4AndVisibleCompatibilityNotice() throws Exception {
        boolean custom = SettingsManager.isArchiveCustomEncryption(), fallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true); SettingsManager.setArchivePasswordFallback(false);
        try {
            FutureTask<Void> task = new FutureTask<>(() -> {
                for (boolean media : List.of(false,true)) {
                    FXMLLoader loader = new FXMLLoader(getClass().getResource("/hbnu/project/ergoutreecrypt/ui/" + (media ? "av-view.fxml" : "main-view.fxml")));
                    Parent root = loader.load(); new Scene(root,1080,900); root.applyCss(); root.layout();
                    var ns = loader.getNamespace();
                    @SuppressWarnings("unchecked") ComboBox<String> formats = (ComboBox<String>) ns.get(media ? "avCompressFormatCombo" : "compressFormatCombo");
                    CheckBox compress = (CheckBox)ns.get(media ? "avCompressAfterCheck" : "compressAfterCheck");
                    PasswordField pwd = (PasswordField)ns.get(media ? "avArchivePasswordField" : "archivePasswordField");
                    Label notice = (Label)ns.get(media ? "avArchiveEncryptionNotice" : "archiveEncryptionNotice");
                    assertTrue(formats.getItems().containsAll(List.of("GZ","TAR.GZ","LZ4","TAR.LZ4")));
                    compress.setSelected(true);
                    for (String format : List.of("GZ","TAR.GZ","LZ4","TAR.LZ4","7Z")) {
                        formats.setValue(format);
                        assertTrue(pwd.isVisible()); assertTrue(notice.isVisible()); assertTrue(notice.isManaged());
                        assertTrue(notice.getText().contains("AES-256")); assertTrue(pwd.getText().isEmpty());
                    }
                    SettingsManager.setArchiveCustomEncryption(false);
                    formats.setValue("LZ4"); assertFalse(pwd.isVisible()); assertTrue(notice.isVisible());
                    SettingsManager.setArchiveCustomEncryption(true);
                    formats.setValue("ZIP"); assertFalse(notice.isVisible()); assertTrue(pwd.isVisible());
                    compress.setSelected(false); assertFalse(pwd.isVisible()); assertFalse(notice.isManaged());
                }
                return null;
            });
            Platform.runLater(task); task.get(30,TimeUnit.SECONDS);
        } finally { SettingsManager.setArchiveCustomEncryption(custom); SettingsManager.setArchivePasswordFallback(fallback); }
    }
}
