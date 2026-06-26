package hbnu.project.ergoutreecrypt.mediacrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 测试夹具：在内存中构造最小合法的 WAV / MP3 / MP4 文件，避免依赖外部样本资源。
 *
 * @author ErgouTree
 */
final class MediaTestFixtures {

    private MediaTestFixtures() {
    }

    /**
     * 构造一个合法的 16-bit PCM 单声道 WAV（44.1kHz），data payload 为给定字节。
     */
    static byte[] buildWav(byte[] pcmData) {
        int sampleRate = 44100;
        short channels = 1;
        short bitsPerSample = 16;
        int byteRate = sampleRate * channels * bitsPerSample / 8;
        short blockAlign = (short) (channels * bitsPerSample / 8);

        ByteBuffer fmt = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        fmt.putShort((short) 1);      // PCM
        fmt.putShort(channels);
        fmt.putInt(sampleRate);
        fmt.putInt(byteRate);
        fmt.putShort(blockAlign);
        fmt.putShort(bitsPerSample);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeChunk(body, "fmt ", fmt.array());
        writeChunk(body, "data", pcmData);
        byte[] bodyBytes = body.toByteArray();

        ByteBuffer riff = ByteBuffer.allocate(12 + bodyBytes.length).order(ByteOrder.LITTLE_ENDIAN);
        riff.put("RIFF".getBytes(StandardCharsets.US_ASCII));
        riff.putInt(4 + bodyBytes.length); // "WAVE" + body
        riff.put("WAVE".getBytes(StandardCharsets.US_ASCII));
        riff.put(bodyBytes);
        return riff.array();
    }

    private static void writeChunk(ByteArrayOutputStream out, String id, byte[] payload) {
        try {
            out.write(id.getBytes(StandardCharsets.US_ASCII));
            ByteBuffer size = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            size.putInt(payload.length);
            out.write(size.array());
            out.write(payload);
            if ((payload.length & 1) == 1) {
                out.write(0); // 奇数填充
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 构造若干个相同参数的 MPEG-1 Layer III CBR 帧（128kbps, 44.1kHz, 单声道）拼成 MP3。
     * 帧头真实合法，帧体填充可识别的伪数据（非全 0，便于验证加密改变了内容）。
     *
     * @param frameCount 帧数
     */
    static byte[] buildMp3(int frameCount) {
        // MPEG-1 Layer III, 128kbps, 44.1kHz, mono, no CRC, no padding。
        // 帧长 = 144 * 128000 / 44100 = 417 字节。
        int frameLen = 144 * 128000 / 44100; // 417
        byte[] header = new byte[]{
                (byte) 0xFF, // sync
                (byte) 0xFB, // MPEG1(11) LayerIII(01) noCRC(1) -> 1111 1011
                (byte) 0x90, // bitrate idx 1001=128k, samplerate 00=44.1k, pad 0 -> 1001 0000
                (byte) 0xC0  // channel mode 11=mono -> 1100 0000
        };

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int f = 0; f < frameCount; f++) {
            out.write(header, 0, 4);
            for (int i = 4; i < frameLen; i++) {
                // 帧体填充非平凡内容（含一些 0xFF 以检验扫描器不被伪同步字误导）。
                out.write((i * 31 + f * 7) & 0xFF);
            }
        }
        return out.toByteArray();
    }

    /**
     * 构造最小合法 MP4：ftyp + moov(占位) + mdat(媒体数据)。
     *
     * @param mdatData mdat payload
     */
    static byte[] buildMp4(byte[] mdatData) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // ftyp
        byte[] ftypPayload = concat(
                "isom".getBytes(StandardCharsets.US_ASCII), // major brand
                intBE(0x200),                                // minor version
                "isomiso2mp41".getBytes(StandardCharsets.US_ASCII)); // compatible brands
        writeBox(out, "ftyp", ftypPayload);
        // moov（占位，内容非真实但 box 结构合法即可——本子系统不解析 moov 内部）
        byte[] moovPayload = new byte[32];
        for (int i = 0; i < moovPayload.length; i++) {
            moovPayload[i] = (byte) (i + 1);
        }
        writeBox(out, "moov", moovPayload);
        // mdat
        writeBox(out, "mdat", mdatData);
        return out.toByteArray();
    }

    private static void writeBox(ByteArrayOutputStream out, String type, byte[] payload) {
        try {
            ByteBuffer size = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            size.putInt(8 + payload.length);
            out.write(size.array());
            out.write(type.getBytes(StandardCharsets.US_ASCII));
            out.write(payload);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] intBE(int v) {
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(v).array();
    }

    private static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            for (byte[] a : arrays) {
                out.write(a);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }

    /**
     * 生成可识别的伪 PCM/媒体数据（非全 0，便于验证加密确实改变了内容）。
     */
    static byte[] pseudoData(int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) ((i * 37 + 11) & 0xFF);
        }
        return b;
    }

    static Path write(Path dir, String name, byte[] content) throws IOException {
        Path p = dir.resolve(name);
        Files.write(p, content);
        return p;
    }
}
