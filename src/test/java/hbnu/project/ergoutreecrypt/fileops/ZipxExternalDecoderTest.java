package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** 使用未经修改的外部 7-Zip 解码器验证普通 ASCII 密码。 */
@EnabledIfSystemProperty(named = "zipx.external.7zip", matches = ".+")
class ZipxExternalDecoderTest {
    @TempDir Path root;

    /** 每种生产编解码器均由外部命令行直接认证并还原，无需密码适配器。 */
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
     * 运行明确配置的解码器，检查其独立结果。
     * @param command 可执行程序及参数列表
     * @throws Exception 外部解码失败
     */
    private static void run(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String log = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), log);
    }
}
