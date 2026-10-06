package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.Random;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** 分卷选项矩阵和可重现的 JVM ↔ ART 真实文件互操作入口。 */
class SplitInteropTest {
    @TempDir Path dir;
    /** 小内存参数只用于测试，覆盖 16 种选项组合及全部归档格式。 */
    @Test void optionAndArchiveMatrix() throws Exception {
        byte[] bytes=new byte[3*1024*1024+129];new Random(49).nextBytes(bytes);
        Path source=Files.write(dir.resolve("真实样本.bin"),bytes);
        int count=SplitInteropSupport.generate(dir.resolve("corpus"),source,false,false);
        assertEquals(38,count);assertEquals(count,SplitInteropSupport.verifyAll(dir.resolve("corpus"),dir.resolve("verified")));
    }
    /** 同名子目录、多层深度和高级选项在串并行处理下保持目录和字节。 */
    @Test void folderDepthParallelAndArchives() throws Exception {
        assertEquals(18,SplitInteropSupport.directoryRegression(dir.resolve("folders")));
        SplitInteropSupport.corruptionRegression(dir.resolve("corruption"));
        SplitInteropSupport.readOnlySourceRegression(dir.resolve("readonly"));
        SplitInteropSupport.advancedOptionsRegression(dir.resolve("advanced"));
        SplitInteropSupport.repeatedPasswordZipSplitRegression(dir.resolve("repeat-zip"));
    }
    /** 生成电脑端真实产物并完成电脑端校验与解密。 */
    @Test void generateDesktopCorpus() throws Exception {
        assumeTrue(Boolean.getBoolean("split.interop.generate"));
        Path source=Path.of(System.getProperty("split.real.file","src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a"));
        assertTrue(Files.isRegularFile(source));
        Path output=Path.of("target/split-interop/desktop");
        int count=SplitInteropSupport.generate(output,source,false,Boolean.getBoolean("split.interop.slow"));
        assertEquals(count,SplitInteropSupport.verifyAll(output,Path.of("target/split-interop/desktop-self")));
    }
    /** 使用现有桌面语料验证最终实现，避免重新加密同一真实文件。 */
    @Test void verifyDesktopCorpus() throws Exception {
        assumeTrue(Boolean.getBoolean("split.interop.verifyDesktop"));
        Path corpus=Path.of("target/split-interop/desktop");
        assertTrue(Files.isRegularFile(corpus.resolve("manifest.properties")));
        assertTrue(SplitInteropSupport.verifyAll(corpus,Path.of("target/split-interop/desktop-final"))>=38);
    }
    /** 两种生成端的双卷诱饵密码均在桌面校验和解密。 */
    @Test void deniabilityDecoyBranches() throws Exception {
        assumeTrue(Boolean.getBoolean("split.interop.decoy"));
        for(String runtime:java.util.List.of("desktop","android")) {
            Path corpus=Path.of("target/split-interop/"+runtime);
            assertTrue(Files.isRegularFile(corpus.resolve("manifest.properties")));
            SplitInteropSupport.deniabilityDecoyRegression(corpus,dir.resolve(runtime));
        }
    }
    /** 双重可否认分卷的可恢复 RS 载荷损坏，在实际双端语料上重试。 */
    @Test void dualDeniabilityRsRecovery() throws Exception {
        assumeTrue(Boolean.getBoolean("split.interop.rsDual"));
        for(String runtime:System.getProperty("split.interop.runtimes","desktop,android").split(",")) {
            Path corpus=Path.of("target/split-interop/"+runtime);
            assertTrue(Files.isRegularFile(corpus.resolve("manifest.properties")));
            SplitInteropSupport.deniabilityRsRecoveryRegression(corpus,dir.resolve(runtime));
        }
    }
    /** Android 产物由 adb 拉回，确保电脑端读取的是同一批实际字节。 */
    @Test void verifyAndroidCorpus() throws Exception {
        Path corpus=Path.of(System.getProperty("split.interop.android","target/split-interop/android"));
        assumeTrue(Files.isRegularFile(corpus.resolve("manifest.properties")));
        assertTrue(SplitInteropSupport.verifyAll(corpus,Path.of("target/split-interop/android-on-desktop"))>=38);
    }
}
