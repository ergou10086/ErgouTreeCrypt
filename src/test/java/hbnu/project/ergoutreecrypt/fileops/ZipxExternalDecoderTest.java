package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies ordinary ASCII passwords with an unmodified external 7-Zip decoder. */
@EnabledIfSystemProperty(named = "zipx.external.7zip", matches = ".+")
class ZipxExternalDecoderTest {
    @TempDir Path root;

    /** Each production codec authenticates and restores through the external CLI without a password adapter. */
    @Test void asciiPasswordsWorkWithExternalDecoder() throws Exception {
        Path source = root.resolve("source.txt");
        Files.writeString(source, "Independent external restoration / 真实 Unicode 文件名\n".repeat(256));
        Path empty = root.resolve("empty");
        Files.write(empty, new byte[0]);
        String executable = System.getProperty("zipx.external.7zip");
        String password = "external-ascii-password";
        for (ZipxMethod method : ZipxMethod.values()) {
            Path archive = root.resolve(method + ".zipx");
            ZipxArchive.pack(archive, List.of(source, empty), List.of("目录/ひなみ 桜花.txt", "empty"), method, password, null);
            run(executable, "t", "-y", "-sccUTF-8", "-p" + password, archive.toString());
            Path output = root.resolve("out-" + method);
            run(executable, "x", "-y", "-sccUTF-8", "-p" + password, "-o" + output, archive.toString());
            assertEquals(-1, Files.mismatch(source, output.resolve("目录/ひなみ 桜花.txt")));
            assertEquals(0, Files.size(output.resolve("empty")));
        }
    }

    /**
     * Runs the explicitly configured decoder and checks its independent result.
     * @param command executable and argument vector
     * @throws Exception external decoding failed
     */
    private static void run(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String log = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), log);
    }
}
