package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/** Opt-in real-file ZIPX exchange with an Android ART instrumentation process. */
class ZipxInteropTest {
    /** Generates desktop archives and authenticates and restores them on desktop. */
    @Test void generateDesktopCorpus() throws Exception {
        assumeTrue(Boolean.getBoolean("zipx.interop.generate"));
        Path source = Path.of(System.getProperty("zipx.real.file", "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a"));
        assertTrue(Files.isRegularFile(source));
        ZipxInteropSupport.generate(Path.of("target/zipx-interop/desktop"), source, false);
    }

    /** Authenticates and restores artifacts produced by Android ART. */
    @Test void readAndroidCorpus() throws Exception {
        String corpus = System.getProperty("zipx.interop.android");
        assumeTrue(corpus != null);
        ZipxInteropSupport.verifyAll(Path.of(corpus), Path.of("target/zipx-interop/android-on-desktop"));
    }

    /** Regenerates and self-verifies affected raw archives while retaining the full volume corpus. */
    @Test void refreshDesktopRawArchives() throws Exception {
        assumeTrue(Boolean.getBoolean("zipx.interop.refresh"));
        ZipxInteropSupport.refreshXzArchives(Path.of("target/zipx-interop/desktop"), false);
    }

    /** Reads newly regenerated Android raw archives after a targeted interoperability correction. */
    @Test void readAndroidRawArchives() throws Exception {
        String corpus = System.getProperty("zipx.interop.android");
        assumeTrue(corpus != null);
        ZipxInteropSupport.verifyRawArchives(Path.of(corpus), Path.of("target/zipx-interop/android-raw-on-desktop"));
    }
}
