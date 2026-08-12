package hbnu.project.ergoutreecrypt.filestego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.mp4.Mp4CarrierAdapter;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.BoxParser;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.Mp4Box;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * 文件隐写 FLAC / MP4 载体端到端往返测试（M3.1 / M3.2）。
 *
 * <p>覆盖 FLAC（APPLICATION/EGTC metadata block）与 MP4（末尾 uuid box）在
 * normal / paranoid / stealth 三种模式下的 hide → extract 数据一致性、
 * 检测能力与容器结构完整性。
 *
 * @author ErgouTree
 */
class FileStegoFlacMp4RoundtripTest {

    private static final byte[] PASSWORD = "flac-mp4-test-pwd".getBytes(StandardCharsets.UTF_8);

    /** FLAC Application ID。 */
    private static final byte[] FLAC_APP_ID = "EGTC".getBytes(StandardCharsets.US_ASCII);

    private final FileStegoCodec codec = new FileStegoCodec();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ---- 载体与秘密文件构造 ----

    /**
     * 生成最小合法 FLAC：fLaC + STREAMINFO(LAST) + 伪音频帧。
     *
     * @param dir  目录
     * @param name 文件名
     * @return 载体路径
     */
    private static Path createFlac(final Path dir, final String name) throws Exception {
        byte[] streamInfo = new byte[34];
        // min/max block size
        streamInfo[0] = 0x00;
        streamInfo[1] = 0x10;
        streamInfo[2] = 0x00;
        streamInfo[3] = 0x10;
        // sample rate 44100 / channels 1 / bits 16 压缩进后续位域，填合理占位即可
        streamInfo[10] = 0x0A;
        streamInfo[11] = (byte) 0xC4;
        streamInfo[12] = 0x42;
        // MD5 置零

        // STREAMINFO header: LAST=1, type=0, size=34
        int header = 0x80000000 | 34;
        ByteBuffer bb = ByteBuffer.allocate(4 + 4 + 34 + 16);
        bb.put("fLaC".getBytes(StandardCharsets.US_ASCII));
        bb.putInt(header);
        bb.put(streamInfo);
        // 伪帧字节（不参与解码校验，仅验证嵌入后原样保留）
        byte[] frames = new byte[16];
        new SecureRandom().nextBytes(frames);
        bb.put(frames);

        Path p = dir.resolve(name);
        Files.write(p, bb.array());
        return p;
    }

    /**
     * 生成最小合法 MP4：ftyp + moov(占位) + mdat。
     *
     * @param dir  目录
     * @param name 文件名
     * @return 载体路径
     */
    private static Path createMp4(final Path dir, final String name) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] ftypPayload = concat(
                "isom".getBytes(StandardCharsets.US_ASCII),
                intBE(0x200),
                "isomiso2mp41".getBytes(StandardCharsets.US_ASCII));
        writeBox(out, "ftyp", ftypPayload);

        byte[] moovPayload = new byte[32];
        for (int i = 0; i < moovPayload.length; i++) {
            moovPayload[i] = (byte) (i + 1);
        }
        writeBox(out, "moov", moovPayload);

        byte[] mdat = new byte[256];
        new SecureRandom().nextBytes(mdat);
        writeBox(out, "mdat", mdat);

        Path p = dir.resolve(name);
        Files.write(p, out.toByteArray());
        return p;
    }

    /**
     * 生成指定大小的随机秘密文件。
     *
     * @param dir  目录
     * @param name 文件名
     * @param size 字节数
     * @return 秘密文件路径
     */
    private static Path createSecret(final Path dir, final String name, final int size)
            throws Exception {
        byte[] data = new byte[size];
        new SecureRandom().nextBytes(data);
        Path p = dir.resolve(name);
        Files.write(p, data);
        return p;
    }

    // ---- FLAC ----

    @Test
    void flacRoundtripNormal(@TempDir final Path dir) throws Exception {
        runFlacRoundtrip(dir, false, false);
    }

    @Test
    void flacRoundtripParanoid(@TempDir final Path dir) throws Exception {
        runFlacRoundtrip(dir, true, false);
    }

    @Test
    void flacRoundtripStealth(@TempDir final Path dir) throws Exception {
        runFlacRoundtrip(dir, false, true);
    }

    /**
     * FLAC 往返核心流程。
     *
     * @param dir      临时目录
     * @param paranoid 偏执模式
     * @param stealth  隐蔽模式
     */
    private void runFlacRoundtrip(final Path dir, final boolean paranoid, final boolean stealth)
            throws Exception {
        Path carrier = createFlac(dir, "carrier.flac");
        byte[] carrierBefore = Files.readAllBytes(carrier);
        Path secret = createSecret(dir, "secret.bin", 24 * 1024);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.flac");

        FileStegoOptions options = FileStegoOptions.builder()
                .paranoid(paranoid)
                .stealth(stealth)
                .build();

        codec.hide(carrier, secret, stego, PASSWORD, options);

        assertTrue(codec.isStegoFile(stego), "应能检测到 FLAC 隐写数据");
        assertTrue(hasEgTcApplication(stego), "应存在 EGTC APPLICATION 块");

        // STREAMINFO 数据与伪帧应保持不变（仅插入 APPLICATION）
        byte[] stegoBytes = Files.readAllBytes(stego);
        assertTrue(regionMatches(stegoBytes, 0, "fLaC".getBytes(StandardCharsets.US_ASCII)));
        // 原 carrier：fLaC(4) + header(4) + STREAMINFO(34) + frames(16)
        // 嵌入后：fLaC + STREAMINFO(LAST=0) + APPLICATION + frames
        // STREAMINFO 体仍为原 34 字节
        byte[] origStreamInfo = Arrays.copyOfRange(carrierBefore, 8, 8 + 34);
        byte[] stegoStreamInfo = Arrays.copyOfRange(stegoBytes, 8, 8 + 34);
        assertArrayEquals(origStreamInfo, stegoStreamInfo, "STREAMINFO 体不应被改动");

        byte[] origFrames = Arrays.copyOfRange(carrierBefore, carrierBefore.length - 16,
                carrierBefore.length);
        byte[] stegoFrames = Arrays.copyOfRange(stegoBytes, stegoBytes.length - 16,
                stegoBytes.length);
        assertArrayEquals(origFrames, stegoFrames, "音频帧区不应被改动");

        Path outDir = dir.resolve("out");
        Path extracted = codec.extract(stego, outDir, PASSWORD);
        byte[] restored = Files.readAllBytes(extracted);

        assertEquals("secret.bin", extracted.getFileName().toString());
        assertArrayEquals(original, restored, "FLAC 还原内容应与原文一致");
    }

    // ---- MP4 ----

    @Test
    void mp4RoundtripNormal(@TempDir final Path dir) throws Exception {
        runMp4Roundtrip(dir, false, false);
    }

    @Test
    void mp4RoundtripParanoid(@TempDir final Path dir) throws Exception {
        runMp4Roundtrip(dir, true, false);
    }

    @Test
    void mp4RoundtripStealth(@TempDir final Path dir) throws Exception {
        runMp4Roundtrip(dir, false, true);
    }

    /**
     * MP4 往返核心流程。
     *
     * @param dir      临时目录
     * @param paranoid 偏执模式
     * @param stealth  隐蔽模式
     */
    private void runMp4Roundtrip(final Path dir, final boolean paranoid, final boolean stealth)
            throws Exception {
        Path carrier = createMp4(dir, "carrier.mp4");
        byte[] carrierBefore = Files.readAllBytes(carrier);
        Path secret = createSecret(dir, "payload.dat", 32 * 1024);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.mp4");

        FileStegoOptions options = FileStegoOptions.builder()
                .paranoid(paranoid)
                .stealth(stealth)
                .build();

        codec.hide(carrier, secret, stego, PASSWORD, options);

        assertTrue(codec.isStegoFile(stego), "应能检测到 MP4 隐写数据");

        // 原 ftyp/moov/mdat 前缀应原样保留（仅末尾追加 uuid）
        byte[] stegoBytes = Files.readAllBytes(stego);
        assertArrayEquals(carrierBefore,
                Arrays.copyOfRange(stegoBytes, 0, carrierBefore.length),
                "原 MP4 顶层 box 字节不应被改动");
        assertTrue(stegoBytes.length > carrierBefore.length, "隐写后文件应变大");

        BoxParser parser = BoxParser.parse(stego);
        assertNotNull(parser.findBox("ftyp"));
        assertNotNull(parser.findBox("moov"));
        assertNotNull(parser.findBox("mdat"));
        assertTrue(hasStegUuid(stego), "应存在隐写 uuid box");

        Path outDir = dir.resolve("out");
        Path extracted = codec.extract(stego, outDir, PASSWORD);
        byte[] restored = Files.readAllBytes(extracted);

        assertEquals("payload.dat", extracted.getFileName().toString());
        assertArrayEquals(original, restored, "MP4 还原内容应与原文一致");
    }

    /**
     * 验证隐写 uuid 可与媒体加密 uuid 共存。
     */
    @Test
    void mp4CoexistsWithMediaCryptUuid(@TempDir final Path dir) throws Exception {
        Path carrier = createMp4(dir, "carrier.mp4");
        // 先追加媒体加密用 uuid（假元数据）
        appendUuidBox(carrier, BoxParser.META_UUID, new byte[]{0x01, 0x02, 0x03, 0x04});

        Path secret = createSecret(dir, "coexist.bin", 4096);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.mp4");

        codec.hide(carrier, secret, stego, PASSWORD, FileStegoOptions.defaults());

        assertTrue(codec.isStegoFile(stego));
        assertTrue(hasUuid(stego, BoxParser.META_UUID), "媒体加密 uuid 应仍存在");
        assertTrue(hasStegUuid(stego), "隐写 uuid 应存在");

        Path extracted = codec.extract(stego, dir.resolve("out"), PASSWORD);
        assertArrayEquals(original, Files.readAllBytes(extracted));
    }

    // ---- 负向：干净文件不应被误判 ----

    @Test
    void cleanCarrierNotDetected(@TempDir final Path dir) throws Exception {
        Path flac = createFlac(dir, "clean.flac");
        Path mp4 = createMp4(dir, "clean.mp4");
        assertFalse(codec.isStegoFile(flac), "干净 FLAC 不应被判为隐写");
        assertFalse(codec.isStegoFile(mp4), "干净 MP4 不应被判为隐写");
    }

    // ---- 辅助 ----

    /**
     * 判断 FLAC 是否包含 Application ID 为 EGTC 的 APPLICATION 块。
     *
     * @param flac FLAC 文件
     * @return 是否存在
     */
    private static boolean hasEgTcApplication(final Path flac) throws Exception {
        byte[] bytes = Files.readAllBytes(flac);
        if (bytes.length < 8 || !regionMatches(bytes, 0, "fLaC".getBytes(StandardCharsets.US_ASCII))) {
            return false;
        }
        int pos = 4;
        while (pos + 4 <= bytes.length) {
            int header = ByteBuffer.wrap(bytes, pos, 4).getInt();
            boolean last = (header & 0x80000000) != 0;
            int type = (header >>> 24) & 0x7F;
            int size = header & 0x00FFFFFF;
            int dataStart = pos + 4;
            if (dataStart + size > bytes.length) {
                return false;
            }
            if (type == 2 && size >= FLAC_APP_ID.length
                    && regionMatches(bytes, dataStart, FLAC_APP_ID)) {
                return true;
            }
            pos = dataStart + size;
            if (last) {
                break;
            }
        }
        return false;
    }

    /**
     * 判断是否存在隐写专用 uuid box。
     *
     * @param mp4 MP4 文件
     * @return 是否存在
     */
    private static boolean hasStegUuid(final Path mp4) throws Exception {
        return hasUuid(mp4, Mp4CarrierAdapter.STEG_UUID);
    }

    /**
     * 判断顶层是否存在匹配指定 usertype 的 uuid box。
     *
     * @param mp4  MP4 文件
     * @param uuid usertype
     * @return 是否存在
     */
    private static boolean hasUuid(final Path mp4, final byte[] uuid) throws Exception {
        BoxParser parser = BoxParser.parse(mp4);
        byte[] bytes = Files.readAllBytes(mp4);
        for (Mp4Box b : parser.boxes()) {
            if (!"uuid".equals(b.type()) || b.payloadSize() < uuid.length) {
                continue;
            }
            if (regionMatches(bytes, (int) b.payloadOffset(), uuid)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 向文件末尾追加一个 uuid box。
     *
     * @param file     目标文件
     * @param usertype 16 字节 usertype
     * @param data     box 数据（usertype 之后）
     */
    private static void appendUuidBox(final Path file, final byte[] usertype, final byte[] data)
            throws Exception {
        int boxSize = 8 + usertype.length + data.length;
        ByteBuffer bb = ByteBuffer.allocate(boxSize).order(ByteOrder.BIG_ENDIAN);
        bb.putInt(boxSize);
        bb.put("uuid".getBytes(StandardCharsets.US_ASCII));
        bb.put(usertype);
        bb.put(data);
        Files.write(file, bb.array(), StandardOpenOption.APPEND);
    }

    /**
     * 写入一个 ISO-BMFF box。
     *
     * @param out     输出流
     * @param type    4 字符类型
     * @param payload payload
     */
    private static void writeBox(final ByteArrayOutputStream out, final String type,
                                 final byte[] payload) throws Exception {
        int size = 8 + payload.length;
        out.write(intBE(size));
        out.write(type.getBytes(StandardCharsets.US_ASCII));
        out.write(payload);
    }

    /**
     * 大端 int32。
     *
     * @param v 值
     * @return 4 字节
     */
    private static byte[] intBE(final int v) {
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(v).array();
    }

    /**
     * 拼接多段字节。
     *
     * @param parts 各段
     * @return 拼接结果
     */
    private static byte[] concat(final byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    /**
     * 区域字节匹配。
     *
     * @param data   源
     * @param offset 偏移
     * @param tag    目标
     * @return 是否匹配
     */
    private static boolean regionMatches(final byte[] data, final int offset, final byte[] tag) {
        if (offset < 0 || offset + tag.length > data.length) {
            return false;
        }
        for (int i = 0; i < tag.length; i++) {
            if (data[offset + i] != tag[i]) {
                return false;
            }
        }
        return true;
    }
}
