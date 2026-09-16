package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PngChunkWriter} 与 {@link PngChunkReader} 的块级流式测试。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class PngChunkReaderWriterTest {

    /**
     * writer 写出的长度、类型、数据和 CRC 必须能被 reader 逐块恢复。
     *
     * @throws Exception 读写失败
     */
    @Test
    void chunkRoundTripPreservesDataAndCriticalBit() throws Exception {
        byte[] png = oneChunk("tEXt", "phase-two".getBytes(StandardCharsets.US_ASCII));
        PngChunkReader reader = new PngChunkReader(new ByteArrayInputStream(png));
        reader.readSignature();
        PngChunkReader.ChunkHeader header = reader.nextChunk();

        assertEquals("tEXt", header.type());
        assertEquals(9, header.length());
        assertFalse(header.critical());
        assertArrayEquals("phase-two".getBytes(StandardCharsets.US_ASCII),
                reader.readChunkBytes(32));
        assertEquals(null, reader.nextChunk());
    }

    /**
     * 任一块数据或 CRC 位变化都必须在消费块边界时被拒绝。
     *
     * @throws Exception 构造测试 PNG 失败
     */
    @Test
    void corruptedChunkCrcIsRejected() throws Exception {
        byte[] png = oneChunk("IDAT", new byte[]{1, 2, 3, 4});
        png[png.length - 1] ^= 1;

        PngChunkReader reader = new PngChunkReader(new ByteArrayInputStream(png));
        reader.readSignature();
        PngChunkReader.ChunkHeader header = reader.nextChunk();
        assertTrue(header.critical());
        ImageCryptException thrown = assertThrows(ImageCryptException.class,
                () -> reader.readChunkBytes(4));
        assertEquals(ErrorKind.INVALID_HEADER, thrown.kind());
    }

    /**
     * 伪造的无符号 0xffffffff 长度必须在分配数据数组前被拒绝。
     */
    @Test
    void oversizedUnsignedChunkLengthIsRejectedBeforeAllocation() {
        byte[] prefix = {
                (byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                'I', 'D', 'A', 'T'
        };
        PngChunkReader reader = new PngChunkReader(new ByteArrayInputStream(prefix));
        ImageCryptException thrown = assertThrows(ImageCryptException.class, () -> {
            reader.readSignature();
            reader.nextChunk();
        });
        assertEquals(ErrorKind.INVALID_HEADER, thrown.kind());
    }

    /**
     * PNG 块类型的第三个保留位为小写时必须拒绝。
     */
    @Test
    void lowercaseReservedTypeBitIsRejected() {
        byte[] prefix = {
                (byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
                0, 0, 0, 0,
                'a', 'b', 'c', 'd'
        };
        PngChunkReader reader = new PngChunkReader(new ByteArrayInputStream(prefix));
        assertThrows(ImageCryptException.class, () -> {
            reader.readSignature();
            reader.nextChunk();
        });
    }

    /**
     * 生成只含签名和单个块的 PNG 字节前缀。
     *
     * @param type 块类型
     * @param data 块数据
     * @return PNG 字节
     * @throws Exception 写出失败
     */
    private static byte[] oneChunk(final String type, final byte[] data) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        PngChunkWriter writer = new PngChunkWriter(output);
        writer.writeSignature();
        writer.writeChunk(type, data);
        return output.toByteArray();
    }
}
