package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/** 显式启用的真实文件与 Android 设备语料交换，不用 JVM 模拟移动端。 */
class Lz4InteropTest {
    @Test void desktopCorpusAndDesktopSelfRead() throws Exception {
        assumeTrue(Boolean.getBoolean("lz4.interop.generate"), "Opt-in corpus generation");
        Path source = Path.of(System.getProperty("lz4.real.file", "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a"));
        assertTrue(Files.isRegularFile(source), "Requested real test file missing");
        Lz4InteropSupport.generate(Path.of("target/lz4-interop/desktop"), source, false);
    }
    @Test void desktopCorpusRestoresOnDesktop() throws Exception {
        String path = System.getProperty("lz4.interop.desktop");
        assumeTrue(path != null, "Opt-in desktop corpus verification");
        Lz4InteropSupport.verifyAll(Path.of(path), Path.of("target/lz4-interop/desktop-reverified"));
    }
    @Test void androidCorpusRestoresOnDesktop() throws Exception {
        String path = System.getProperty("lz4.interop.android");
        assumeTrue(path != null, "Opt-in Android artifact verification");
        Lz4InteropSupport.verifyAll(Path.of(path), Path.of("target/lz4-interop/android-on-desktop"));
    }
}
