package hbnu.project.ergoutreecrypt.volume;

import static hbnu.project.ergoutreecrypt.volume.FastVolumeRoundtripTest.*;

import static org.junit.jupiter.api.Assertions.*;

import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

/** 验证共享核心的前后归档适配，完整双端界面与 SAF 组合留给 P3。 */
final class FastArchiveTest {
    /**
     * 每种已支持格式分别经过前归档与后归档。
     *
     * @param directory 测试目录
     * @throws Exception 归档或认证解密失败
     */
    @Test
    void beforeAndAfterArchiveFamilies(@TempDir Path directory) throws Exception {
        Path input = directory.resolve("中文🔐.txt");
        Files.writeString(input, "归档与 FAST 独立处理\n".repeat(100));
        for (var format : ArchivePacker.Format.values()) {
            String name = format.name();
            Path work = Files.createDirectory(directory.resolve(name));
            var before = encryption(input, work.resolve("before.ergou"), "密码");
            before.setPreArchiveFormat(name);
            Encryptor.encrypt(before);
            Path cipher = Path.of(before.getOutputFile());
            assertTrue(Verifier.verify(verification(cipher, "密码")));
            Path archive = work.resolve("restored" + ArchivePacker.extOf(format));
            Decryptor.decrypt(decryption(cipher, archive, "密码"));
            var extracted =
                    ArchiveExtractor.extractPreserving(
                            archive, Files.createDirectory(work.resolve("pre")), null);
            assertEquals(1, extracted.size());
            assertEquals(-1, Files.mismatch(input, extracted.getFirst()));
            var after = encryption(input, work.resolve("after.ergou"), "密码");
            after.setArchiveFormat(name);
            after.setArchivePassword("独立归档密码");
            Encryptor.encrypt(after);
            var ciphers =
                    ArchiveExtractor.extractPreserving(
                            Path.of(after.getOutputFile()),
                            Files.createDirectory(work.resolve("post")),
                            "独立归档密码");
            assertEquals(1, ciphers.size());
            assertTrue(Verifier.verify(verification(ciphers.getFirst(), "密码")));
            Path plain = work.resolve("plain");
            Decryptor.decrypt(decryption(ciphers.getFirst(), plain, "密码"));
            assertEquals(-1, Files.mismatch(input, plain));
            assertFalse(entries(work).stream().anyMatch(n -> n.startsWith(".ergou-fast-")));
        }
    }
}
