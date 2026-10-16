package hbnu.project.ergoutreecrypt.keyfile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** 目录密钥互通的桌面入口。 */
public class KeyfileBatchInteropTest {
    @TempDir Path scratch;

    /**
     * 生成目录语料并独立认证及解密。
     * @throws Exception 测试失败
     */
    @Test void desktopProducerAndReader() throws Exception {
        assumeTrue(Boolean.getBoolean("keyfile.generate"));
        Path root = Path.of(System.getProperty("keyfile.root")), corpus = root.resolve("corpus");
        KeyfileInteropSupport.prepare(Path.of(System.getProperty("keyfile.source")), corpus);
        assertEquals(12, KeyfileBatchInteropSupport.produce(corpus, root.resolve("desktop"), false,
                Boolean.parseBoolean(System.getProperty("keyfile.profiles", "true"))));
        assertEquals(12, KeyfileBatchInteropSupport.verify(corpus, root.resolve("desktop"), scratch));
    }

    /**
     * 读取实际 ART 的目录产物。
     * @throws Exception 测试失败
     */
    @Test void desktopReadsAndroid() throws Exception {
        assumeTrue(Boolean.getBoolean("keyfile.android"));
        Path root = Path.of(System.getProperty("keyfile.root"));
        int repeats = Integer.getInteger("keyfile.batch.repeats", 1);
        for (int i = 0; i < repeats; i++) {
            assertEquals(12, KeyfileBatchInteropSupport.verify(root.resolve("corpus"), root.resolve("android"), scratch));
        }
    }
}
