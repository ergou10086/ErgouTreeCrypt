package hbnu.project.ergoutreecrypt.volume;

import static hbnu.project.ergoutreecrypt.volume.FastVolumeRoundtripTest.*;

import static org.junit.jupiter.api.Assertions.*;

import hbnu.project.ergoutreecrypt.exception.CryptoException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

/** 高级选项不能从调用核心 API 绕过前端限制。 */
final class FastCapabilitiesTest {
    /**
     * @param directory 独占测试目录
     * @throws Exception 冲突拒绝失败
     */
    @Test
    void incompatibleOptionsAreRejectedBeforeOutput(@TempDir Path directory) throws Exception {
        Path input = directory.resolve("input"), output = directory.resolve("output");
        Files.writeString(input, "原文件");
        List<Consumer<EncryptRequest>> conflicts =
                List.of(
                        r -> r.setParanoid(true),
                        r -> r.setReedSolomon(true),
                        r -> r.setSplit(true),
                        r -> r.setCompress(true),
                        r -> r.setDeniability(true),
                        r -> r.setDualDeniability(true),
                        r -> r.setKeyfileOrdered(true),
                        r -> r.setKeyfiles(List.of("key")),
                        r -> r.setComments("说明"),
                        r -> r.setArgon2MemoryKib(8192),
                        r -> r.setArgon2Passes(1),
                        r -> r.setArgon2Threads(1),
                        r -> r.setInputFiles(List.of(input.toString(), input.toString())));
        for (var conflict : conflicts) {
            var request = encryption(input, output, "密码");
            conflict.accept(request);
            assertThrows(CryptoException.class, () -> Encryptor.encrypt(request));
            assertEquals(List.of("input"), entries(directory));
        }
        var fixed = encryption(input, output, "密码");
        fixed.setArgon2MemoryKib(65536);
        fixed.setArgon2Passes(3);
        fixed.setArgon2Threads(4);
        FastCapabilities.validateEncryption(fixed);
        var archived = encryption(input, output, "密码");
        archived.setPreArchiveFormat("ZIP");
        archived.setArchiveFormat("ZIP");
        FastCapabilities.validateEncryption(archived);
    }
}
