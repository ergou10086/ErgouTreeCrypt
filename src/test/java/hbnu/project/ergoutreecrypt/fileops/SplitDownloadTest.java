package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.Random;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** 下载兼容专项测试，以及真实桌面／ART 互通与用户样本的可复用入口。 */
class SplitDownloadTest {
    @TempDir Path dir;

    /** @throws Exception 下载兼容和错误拒绝回归失败。 */
    @Test void renamedAndMissingDownloads() throws Exception {
        byte[] bytes = new byte[128 * 1024 + 13]; new Random(20261108).nextBytes(bytes);
        Path source = Files.write(dir.resolve("source"), bytes);
        SplitDownloadSupport.generate(dir.resolve("corpus"), source);
        assertEquals(36, SplitDownloadSupport.verify(dir.resolve("corpus"), dir.resolve("verified")));
    }

    /** @throws Exception 桌面产物生成、自认证或自解密失败。 */
    @Test void desktopCorpus() throws Exception {
        assumeTrue(Boolean.getBoolean("split.download.generate"));
        Path root = Path.of("target/split-downloads");
        SplitDownloadSupport.generate(root.resolve("desktop"), Path.of(System.getProperty("split.real.file")));
        assertEquals(36, SplitDownloadSupport.verify(root.resolve("desktop"), root.resolve("desktop-self")));
    }

    /** @throws Exception Android 生成的实际分卷在桌面读取失败。 */
    @Test void androidCorpus() throws Exception {
        assumeTrue(Boolean.getBoolean("split.download.android"));
        Path root = Path.of("target/split-downloads");
        assertEquals(36, SplitDownloadSupport.verify(root.resolve("android"), root.resolve("android-on-desktop")));
    }

    /** @throws Exception 用户样本认证或解密失败。 */
    @Test void realDownload() throws Exception {
        String input = System.getProperty("split.sample.input");
        assumeTrue(input != null);
        String password = System.getenv("SPLIT_SAMPLE_PASSWORD");
        assertNotNull(password, "Set SPLIT_SAMPLE_PASSWORD without logging it");
        System.out.println("REAL DOWNLOAD PASS " + SplitDownloadSupport.sample(Path.of(input), Path.of(System.getProperty("split.sample.output")), password));
    }
}
