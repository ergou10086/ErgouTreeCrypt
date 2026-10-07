package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/** 显式启用的真实 ZIPX 文件与 Android ART 设备进程交换测试。 */
class ZipxInteropTest {
    /** 生成桌面归档，并在桌面执行认证与还原。 */
    @Test void generateDesktopCorpus() throws Exception {
        assumeTrue(Boolean.getBoolean("zipx.interop.generate"));
        Path source = Path.of(System.getProperty("zipx.real.file", "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a"));
        assertTrue(Files.isRegularFile(source));
        ZipxInteropSupport.generate(Path.of("target/zipx-interop/desktop"), source, false);
    }

    /** 认证并还原 Android ART 生成的产物。 */
    @Test void readAndroidCorpus() throws Exception {
        String corpus = System.getProperty("zipx.interop.android");
        assumeTrue(corpus != null);
        ZipxInteropSupport.verifyAll(Path.of(corpus), Path.of("target/zipx-interop/android-on-desktop"));
    }

    /** 重新生成并自校验受影响的原始归档，保留完整卷语料。 */
    @Test void refreshDesktopRawArchives() throws Exception {
        assumeTrue(Boolean.getBoolean("zipx.interop.refresh"));
        ZipxInteropSupport.refreshXzArchives(Path.of("target/zipx-interop/desktop"), false);
    }

    /** 定向修复互通问题后，读取重新生成的 Android 原始归档。 */
    @Test void readAndroidRawArchives() throws Exception {
        String corpus = System.getProperty("zipx.interop.android");
        assumeTrue(corpus != null);
        ZipxInteropSupport.verifyRawArchives(Path.of(corpus), Path.of("target/zipx-interop/android-raw-on-desktop"));
    }
}
