package hbnu.project.ergoutreecrypt.filestego.carrier.zip;

import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ZIP 流式倒扫 EOCD 定位测试。
 *
 * <p>验证 {@link ZipCarrierAdapter} 流式尾部倒扫在以下边界条件下仍能
 * 正确定位真实 EOCD：注释内含伪 EOCD 签名、Payload 内含伪 EOCD + 伪 EGFS、
 * 真实 EOCD 签名跨越 1 MiB 扫描块边界。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
class ZipEocdScanTest {

    private static final byte[] EOCD_SIG = {0x50, 0x4B, 0x05, 0x06};

    /**
     * 构造带注释的 ZIP 载体。
     *
     * @param dir     目录
     * @param name    文件名
     * @param comment 注释文本（UTF-8 编码为注释字节）
     * @return ZIP 路径
     * @throws Exception 写入失败
     */
    private static Path createZipWithComment(final Path dir, final String name,
                                             final String comment) throws Exception {
        Path p = dir.resolve(name);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(p))) {
            zos.putNextEntry(new ZipEntry("readme.txt"));
            zos.write("hello".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.setComment(comment);
        }
        return p;
    }

    /**
     * 构造隐写 ZIP：载体后追加 [meta + payload]。
     */
    private static Path craftStegoZip(final Path carrier, final Path out, final byte[] payload)
            throws Exception {
        CarrierMetadata meta = new CarrierMetadata(payload.length, (byte) 0,
                new byte[16], new byte[32], new byte[24], null, null);
        try (OutputStream os = Files.newOutputStream(out,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            Files.copy(carrier, os);
            os.write(meta.toBytes());
            os.write(payload);
        }
        return out;
    }

    /**
     * 注释内含伪 EOCD 签名：提取仍须定位真实 EOCD 并正确还原 Payload。
     */
    @Test
    void fakeEocdSignatureInCommentStillExtracts(@TempDir final Path dir) throws Exception {
        // 注释包含 EOCD 签名字节（"PK" + 0x05 + 0x06，UTF-8 单字节编码）
        String comment = "fake " + "PK" + new String(new byte[] {0x05, 0x06},
                StandardCharsets.UTF_8) + " tail comment";
        Path carrier = createZipWithComment(dir, "carrier.zip", comment);
        byte[] payload = randomBytes(512 * 1024);
        Path stego = craftStegoZip(carrier, dir.resolve("stego.zip"), payload);

        ZipCarrierAdapter adapter = new ZipCarrierAdapter();
        assertTrue(adapter.detect(stego), "注释含伪签名时仍应检测到隐写数据");

        Path payloadOut = dir.resolve("payload.out");
        CarrierMetadata meta = adapter.extractFullToFile(stego, null, payloadOut);
        assertEquals(payload.length, meta.payloadSize());
        assertArrayEquals(payload, Files.readAllBytes(payloadOut),
                "注释含伪 EOCD 签名时提取内容应正确");
    }

    /**
     * Payload 内含伪 EOCD + 伪 EGFS（魔数可通过但元数据非法）：
     * 倒扫必须拒绝该伪候选并定位真实 EOCD。
     */
    @Test
    void fakeEocdWithFakeMagicInPayloadStillExtracts(@TempDir final Path dir) throws Exception {
        Path carrier = createZipWithComment(dir, "carrier.zip", "plain comment");
        byte[] payload = randomBytes(512 * 1024);
        // 在 Payload 中部伪造：EOCD 签名 + commentLen=10 → 指向 "EGFS" + 非法元数据
        int k = 100_000;
        System.arraycopy(EOCD_SIG, 0, payload, k, 4);
        payload[k + 20] = 10;
        payload[k + 21] = 0;
        byte[] egfs = "EGFS".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(egfs, 0, payload, k + 32, 4);
        // 其后 100 字节为确定性伪随机垃圾（fromBytes 校验必失败）

        Path stego = craftStegoZip(carrier, dir.resolve("stego.zip"), payload);

        ZipCarrierAdapter adapter = new ZipCarrierAdapter();
        Path payloadOut = dir.resolve("payload.out");
        CarrierMetadata meta = adapter.extractFullToFile(stego, null, payloadOut);
        assertEquals(payload.length, meta.payloadSize());
        assertArrayEquals(payload, Files.readAllBytes(payloadOut),
                "Payload 含伪 EOCD+EGFS 时提取内容应正确");
    }

    /**
     * 真实 EOCD 签名跨越 1 MiB 扫描块边界：重叠读取逻辑必须保证不遗漏。
     *
     * <p>Payload 长度按 (metaLen + payloadLen + commentLen + EOCD_MIN_LEN) ≡ 1
     * (mod 1 MiB) 选取，使 EOCD 签名起点位于块边界前 1 字节。
     */
    @Test
    void eocdSignatureStraddlingScanBoundary(@TempDir final Path dir) throws Exception {
        String comment = "boundary";
        int commentLen = comment.getBytes(StandardCharsets.UTF_8).length;
        int metaLen = CarrierMetadata.totalSize(false, false);
        // fileSize - eocdOffset = metaLen + payloadLen + commentLen + 22 ≡ 1 (mod 1 MiB)
        int payloadLen = (1 << 20) + 1 - metaLen - commentLen - 22;
        assertTrue(payloadLen > 0, "Payload 长度须为正");

        Path carrier = createZipWithComment(dir, "carrier.zip", comment);
        byte[] payload = randomBytes(payloadLen);
        Path stego = craftStegoZip(carrier, dir.resolve("stego.zip"), payload);

        ZipCarrierAdapter adapter = new ZipCarrierAdapter();
        Path payloadOut = dir.resolve("payload.out");
        CarrierMetadata meta = adapter.extractFullToFile(stego, null, payloadOut);
        assertEquals(payload.length, meta.payloadSize());
        assertArrayEquals(payload, Files.readAllBytes(payloadOut),
                "EOCD 签名跨块边界时提取内容应正确");
    }

    /**
     * 干净 ZIP 不应被误判为隐写文件。
     */
    @Test
    void cleanZipNotDetected(@TempDir final Path dir) throws Exception {
        Path carrier = createZipWithComment(dir, "clean.zip", "nothing here");
        ZipCarrierAdapter adapter = new ZipCarrierAdapter();
        assertFalse(adapter.detect(carrier), "干净 ZIP 不应被误判为隐写文件");
    }

    /**
     * 生成确定性伪随机字节。
     */
    private static byte[] randomBytes(final int size) {
        byte[] b = new byte[size];
        for (int i = 0; i < size; i++) {
            b[i] = (byte) ((i * 31 + 7) & 0xFF);
        }
        return b;
    }
}
