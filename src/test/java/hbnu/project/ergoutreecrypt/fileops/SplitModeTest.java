package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** 分卷格式设置的八方向定向入口。 */
class SplitModeTest {
    /** @throws Exception 桌面生成或读取失败 */
    @Test void generateDesktop() throws Exception {
        assumeTrue(Boolean.getBoolean("split.mode.generate"));
        Path source = Path.of(System.getProperty("split.real.file", "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a"));
        Path corpus = Path.of("target/split-mode/desktop");
        assertEquals(14, SplitInteropSupport.generateModes(corpus, source, false));
        assertEquals(14, SplitInteropSupport.verifyModes(corpus, Path.of("target/split-mode/desktop-self")));
    }
    /** @throws Exception Android 产物的桌面读取失败 */
    @Test void verifyAndroid() throws Exception {
        assumeTrue(Boolean.getBoolean("split.mode.android"));
        assertEquals(14, SplitInteropSupport.verifyModes(Path.of("target/split-mode/android"), Path.of("target/split-mode/android-on-desktop")));
    }
}
