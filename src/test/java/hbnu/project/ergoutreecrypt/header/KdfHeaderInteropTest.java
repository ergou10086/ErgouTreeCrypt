package hbnu.project.ergoutreecrypt.header;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 桌面端与移动端真实加密文件的卷头互通基线测试（Phase 0.1）。
 *
 * <p>读取 {@code temp/test} 下的真实加密文件卷头，断言两端在「Argon2 参数是否
 * 落盘」上的不对称：桌面端加密的文件不记录有效 Argon2 参数（解密端回落到默认
 * 1 GiB），移动端加密的文件则把档位参数显式写入卷头（v2.15）。测试文件缺失时
 * 自动跳过（CI 环境不携带这些大文件）。
 *
 * @author ErgouTree
 */
class KdfHeaderInteropTest {

    /**
     * 桌面端加密的卷（启用加密前压缩）：卷头版本 v2.16，但 Argon2 参数块全零，
     * 故 {@code hasArgon2Params()} 为假——解密端会回落到 1 GiB 默认档。
     */
    @Test
    void desktopVolume_hasNoEffectiveArgon2Params() throws Exception {
        Path f = Path.of("temp/test/desktop/原内容.zip.ergou");
        assumeTrue(Files.exists(f), "缺少桌面端真实测试文件，跳过");
        try (InputStream in = Files.newInputStream(f)) {
            VolumeHeader header = new HeaderReader(in, new RsCodecs()).readHeader().getHeader();
            assertEquals("v2.16", header.getVersion());
            assertFalse(header.hasArgon2Params(), "桌面端文件不应记录有效 Argon2 参数");
            assertTrue(header.isCompressed(), "该文件启用了加密前压缩");
        }
    }

    /**
     * 移动端加密的卷：卷头版本 v2.15，且记录有效 Argon2 参数（低内存档位）。
     */
    @Test
    void mobileVolume_recordsArgon2Params() throws Exception {
        Path f = Path.of("temp/test/andorid/原内容.zip.ergou");
        assumeTrue(Files.exists(f), "缺少移动端真实测试文件，跳过");
        try (InputStream in = Files.newInputStream(f)) {
            VolumeHeader header = new HeaderReader(in, new RsCodecs()).readHeader().getHeader();
            assertEquals("v2.15", header.getVersion());
            assertTrue(header.hasArgon2Params(), "移动端文件应记录 Argon2 参数");
            assertTrue(header.getArgon2MemoryKib() > 0);
            assertTrue(header.getArgon2MemoryKib() <= (256 << 10),
                    "移动端档位不应超过 256 MiB");
        }
    }
}
