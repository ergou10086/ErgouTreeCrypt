package hbnu.project.ergoutreecrypt.keyfile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** 可复用 JVM 生成及 Android 产物读取入口。 */
public class KeyfileInteropTest {
    @TempDir Path scratch;

    /**
     * 只有明确指定真实文件时才生成大型语料。
     * @throws Exception 测试失败
     */
    @Test void desktopProducerAndReader() throws Exception {
        assumeTrue(Boolean.getBoolean("keyfile.generate"));
        Path root = Path.of(System.getProperty("keyfile.root"));
        Path corpus = root.resolve("corpus");
        KeyfileInteropSupport.prepare(Path.of(System.getProperty("keyfile.source")), corpus);
        int count = KeyfileInteropSupport.produce(corpus, root.resolve("desktop"), false, Boolean.getBoolean("keyfile.slow"));
        assertEquals(Boolean.getBoolean("keyfile.slow") ? 172 : 164, count);
        assertEquals(count, KeyfileInteropSupport.verify(corpus, root.resolve("desktop"), scratch));
    }

    /**
     * 读取实际 ART 生成并搬运回桌面的相同字节。
     * @throws Exception 测试失败
     */
    @Test void desktopReadsAndroid() throws Exception {
        assumeTrue(Boolean.getBoolean("keyfile.android"));
        Path root = Path.of(System.getProperty("keyfile.root"));
        assertEquals(Boolean.getBoolean("keyfile.slow") ? 172 : 164,
                KeyfileInteropSupport.verify(root.resolve("corpus"), root.resolve("android"), scratch));
    }
}
