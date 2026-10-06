package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** 本轮内嵌元数据迁移的定向回归入口，不重跑完整高级选项矩阵。 */
class SplitMetadataTest {
    @TempDir Path dir;
    /** @throws Exception 新格式边界与批次检查失败。 */
    @Test void embeddedBoundaries() throws Exception {assertEquals(23,SplitMetadataSupport.boundaries(dir));}
    /** @throws Exception 桌面生成端与桌面读取端失败。 */
    @Test void generateDesktop() throws Exception {
        assumeTrue(Boolean.getBoolean("split.metadata.generate"));
        Path source=Path.of(System.getProperty("split.real.file","src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a"));
        Path corpus=Path.of("target/split-metadata/desktop");
        int count=SplitInteropSupport.generateMetadata(corpus,source,false,Boolean.getBoolean("split.metadata.slow"));
        assertEquals(count,SplitInteropSupport.verifyAll(corpus,Path.of("target/split-metadata/desktop-self")));
        assertEquals(20,SplitMetadataSupport.mutations(corpus,Path.of("target/split-metadata/desktop-mutated")));
    }
    /** @throws Exception 传统伪装清单回退的桌面生成和自检失败。 */
    @Test void generateLegacyFallback() throws Exception {
        assumeTrue(Boolean.getBoolean("split.legacy.generate"));
        Path source=Path.of(System.getProperty("split.real.file","src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a"));
        Path corpus=Path.of("target/split-legacy-fallback/desktop");
        assertEquals(1,SplitInteropSupport.generateLegacyFallback(corpus,source,false));
        assertEquals(1,SplitInteropSupport.verifyAll(corpus,Path.of("target/split-legacy-fallback/desktop-self")));
        assertEquals(4,SplitMetadataSupport.legacyMissing(corpus,Path.of("target/split-legacy-fallback/desktop-missing")));
    }
    /** @throws Exception 手机清单回退产物的桌面读取失败。 */
    @Test void verifyLegacyAndroid() throws Exception {
        assumeTrue(Boolean.getBoolean("split.legacy.android"));
        Path corpus=Path.of("target/split-legacy-fallback/android");
        assertEquals(1,SplitInteropSupport.verifyAll(corpus,Path.of("target/split-legacy-fallback/android-on-desktop")));
        assertEquals(4,SplitMetadataSupport.legacyMissing(corpus,Path.of("target/split-legacy-fallback/android-missing")));
    }
    /** @throws Exception 手机生成端到桌面读取端失败。 */
    @Test void verifyAndroid() throws Exception {
        assumeTrue(Boolean.getBoolean("split.metadata.android"));
        Path corpus=Path.of("target/split-metadata/android");
        assertTrue(SplitInteropSupport.verifyAll(corpus,Path.of("target/split-metadata/android-on-desktop"))>=10);
        assertEquals(20,SplitMetadataSupport.mutations(corpus,Path.of("target/split-metadata/android-mutated")));
    }
}
