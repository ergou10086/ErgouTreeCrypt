package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.fileops.Splitter;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.ToggleButton;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** 实际加载主界面 FXML，验证选择目录/碎片后的卷数和缺卷预览。 */
@EnabledIfSystemProperty(named="ergoutreecrypt.uiTests",matches="true")
class SplitDesktopUiTest {
    @TempDir Path dir;
    /** @throws Exception 启动 JavaFX 失败。 */
    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready=new CountDownLatch(1);
        Platform.startup(()->{Platform.setImplicitExit(false);ready.countDown();});
        assertTrue(ready.await(15,TimeUnit.SECONDS));
    }
    /** @throws Exception 实际界面加载或显示结果失败。 */
    @Test void selectedDirectoryAndMissingLastChunkShowTotal() throws Exception {
        Path base=Files.write(dir.resolve("file.ergou"),new byte[2050]);Splitter.split(base,1024);assertFalse(Files.exists(Splitter.manifestPath(base)));Files.delete(base);Files.delete(Path.of(base+".2"));
        FXMLLoader loader=new FXMLLoader(getClass().getResource("/hbnu/project/ergoutreecrypt/ui/main-view.fxml"));
        fx(()->{
            Parent view=loader.load();new Scene(view,1100,950);view.applyCss();view.layout();
            ((ToggleButton)loader.getNamespace().get("decryptTab")).fire();
            Object controller=loader.getController();var select=controller.getClass().getDeclaredMethod("setSelectedFile",java.io.File.class);select.setAccessible(true);select.invoke(controller,dir.toFile());return null;
        });
        Label label=(Label)loader.getNamespace().get("fileMetaLabel");
        String text="";long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
        while(System.nanoTime()<deadline){text=fx(label::getText);if(text.contains(".2"))break;Thread.sleep(25);}
        assertTrue(text.contains(".2"),text);assertTrue(text.contains("3"),text);assertTrue(text.contains("2"),text);
        String preview=Splitter.describeInput(Path.of(base+".0"));assertTrue(preview.contains(".2"));
    }
    /** @param action FX 操作 @param <T> 返回类型 @return 操作返回值 @throws Exception 执行失败。 */
    private static <T>T fx(Callable<T> action) throws Exception {FutureTask<T> task=new FutureTask<>(action);Platform.runLater(task);return task.get(20,TimeUnit.SECONDS);}
}
