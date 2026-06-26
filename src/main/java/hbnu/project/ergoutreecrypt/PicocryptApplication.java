package hbnu.project.ergoutreecrypt;

import hbnu.project.ergoutreecrypt.ui.MainController;
import hbnu.project.ergoutreecrypt.ui.support.FileAssociation;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * JavaFX 应用入口。
 *
 * <p>ErgouTreeCrypt 是使用了 Picocrypt-NG（Go）作为部分内核 Java 文件安全加密工具。
 * 本类负责注册 BouncyCastle 密码学提供者并加载主界面。详见 {@code docs/ARCHITECTURE.md}。
 *
 * @author ErgouTree
 * @since 2026/6/17
 */
public class PicocryptApplication extends Application {

    static {
        // 注册 BouncyCastle，作为 Argon2id / Serpent / BLAKE2b / SHA3 等算法的来源。
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * 加载多分辨率窗口图标。
     *
     * <p>按分辨率从小到大注册，Windows 任务栏 / Alt-Tab / 标题栏
     * 会自动选择最合适的尺寸。资源缺失时静默跳过。
     */
    private static void loadStageIcons(Stage stage) {
        // 按分辨率从小到大排列
        String[] iconResources = {
                "ui/img/logo-120x.png",
                "ui/img/logo-240x.png",
                "ui/img/logo-480x.png",
                "ui/img/logo-square.png",
                "ui/img/logo.png"
        };
        List<Image> icons = new ArrayList<>();
        for (String res : iconResources) {
            try (InputStream in = PicocryptApplication.class.getResourceAsStream(res)) {
                if (in != null) {
                    icons.add(new Image(in));
                }
            } catch (Exception ignored) {
                // 单个图标加载失败不影响其他图标
            }
        }
        if (!icons.isEmpty()) {
            stage.getIcons().addAll(icons);
        }
    }

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(
                PicocryptApplication.class.getResource("ui/main-view.fxml"));
        Parent root = fxmlLoader.load();
        MainController controller = fxmlLoader.getController();

        Scene scene = new Scene(root, 520, 720);
        scene.setFill(Color.TRANSPARENT);

        // 无边框窗口 + 自定义标题栏，贴近 Win11 视觉。
        stage.initStyle(StageStyle.TRANSPARENT);
        stage.setTitle("ErgouTreeCrypt");
        stage.setMinWidth(460);
        stage.setMinHeight(560);
        stage.setScene(scene);

        // 窗口图标（任务栏 / Alt-Tab / 标题栏左侧），提供多种分辨率
        // JavaFX 会根据使用场景自动选择最合适的尺寸。
        loadStageIcons(stage);

        // 场景就绪后再挂主题与窗口拖动逻辑。
        controller.attachScene();
        stage.show();

        // 后台注册 .ergou 文件关联（HKCU，无需管理员权限）
        new Thread(FileAssociation::autoRegister, "file-assoc").start();
    }
}
