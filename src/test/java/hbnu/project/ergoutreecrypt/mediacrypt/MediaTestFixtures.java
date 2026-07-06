package hbnu.project.ergoutreecrypt.mediacrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 测试夹具：在内存中构造最小合法的 WAV / MP3 / MP4 / M4A 文件，避免依赖外部样本资源。
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

    /**
     * 构造最小合法 M4A 音频文件（AAC-LC, 44.1kHz, 单声道）。
     *
     * <p>与通用 {@link #buildMp4(byte[])} 的区别：
     * <ul>
     *   <li>ftyp major brand 为 {@code "M4A "}（音频专用）</li>
     *   <li>moov 内含完整的音频轨道结构：{@code soun} handler、{@code mp4a} + {@code esds} sample entry</li>
     *   <li>sample table（stts/stsc/stsz/stco）为合法值，指向 mdat 中的媒体数据</li>
     * </ul>
     *
     * <p>加密子系统只操作顶层 box（ftyp/mdat），但构建真实 moov 可验证：
     * 加密后的文件对 MP4 解析器（如 ffprobe/BoxParser）仍是合法容器。
     *
     * @param mdatData mdat 中的音频数据
     */
    static byte[] buildM4a(byte[] mdatData) {
        int timescale = 44100;
        int sampleDelta = 1024;   // AAC 每帧 1024 采样
        int numSamples = 1;
        int duration = numSamples * sampleDelta;

        // ---- ftyp ----
        byte[] ftypPayload = M4aBoxBuilder.ftypPayload();

        // ---- 计算 mdat 在文件中的偏移 ----
        // ftyp 完整 size = 8 + ftypPayload.length
        int ftypSize = 8 + ftypPayload.length;

        // 先计算 moov 内部各子 box 的预留大小（用零占位构建，之后替换正确 size）
        byte[] moovBodyPlaceholder = M4aBoxBuilder.buildMoovBody(
                timescale, duration, numSamples, sampleDelta, 0 /* mdatOffset 先填 0 */);
        int moovSize = 8 + moovBodyPlaceholder.length;

        // mdat 起始位置 = ftyp + moov
        int mdatHeaderSize = 8;
        int mdatBoxStart = ftypSize + moovSize;
        int mdatPayloadOffset = mdatBoxStart + mdatHeaderSize;

        // 用正确的 mdat 偏移重建 moov
        byte[] moovBody = M4aBoxBuilder.buildMoovBody(
                timescale, duration, numSamples, sampleDelta, mdatPayloadOffset);

        // ---- 组装文件 ----
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBox(out, "ftyp", ftypPayload);
        writeBox(out, "moov", moovBody);
        writeBox(out, "mdat", mdatData);
        return out.toByteArray();
    }

    /**
     * 写入 ISO-BMFF box（32-bit size）。
     */
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

    /**
     * M4A 文件 moov body 及其子 box 的构建器。
     *
     * <p>所有 box 均采用 32-bit size + Big-Endian 编码。
     * FullBox 格式：size(4) + type(4) + version(1) + flags(3) + payload。
     */
    private static final class M4aBoxBuilder {

        private M4aBoxBuilder() {
        }

        /**
         * 构建 ftyp payload：major brand "M4A " + minor version + compatible brands。
         */
        static byte[] ftypPayload() {
            return concat(
                    "M4A ".getBytes(StandardCharsets.US_ASCII),
                    intBE(0x200),
                    "M4A isommp42".getBytes(StandardCharsets.US_ASCII)
            );
        }

        /**
         * 构建 moov body（不含 box header）。
         *
         * @param timescale    时间刻度（Hz）
         * @param duration     总时长（timescale 单位）
         * @param numSamples   mdat 中的 sample 数量
         * @param sampleDelta  每个 sample 的时长（timescale 单位）
         * @param mdatPayloadOffset mdat payload 在文件中的字节偏移
         */
        static byte[] buildMoovBody(int timescale, int duration, int numSamples,
                                     int sampleDelta, int mdatPayloadOffset) {
            byte[] mvhd = buildMvhd(timescale, duration);
            byte[] trak = buildTrak(timescale, duration, numSamples, sampleDelta, mdatPayloadOffset);
            return concat(mvhd, trak);
        }

        // ---- mvhd ----
        private static byte[] buildMvhd(int timescale, int duration) {
            ByteBuffer bb = ByteBuffer.allocate(96).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(0);                          // creation_time
            bb.putInt(0);                          // modification_time
            bb.putInt(timescale);
            bb.putInt(duration);
            bb.putInt(0x00010000);                 // rate (1.0)
            bb.putShort((short) 0x0100);           // volume (1.0)
            bb.putShort((short) 0);                // reserved
            bb.putInt(0); bb.putInt(0);            // reserved
            for (int i = 0; i < 9; i++) {          // matrix (identity)
                if (i == 0 || i == 4) {
                    bb.putInt(0x00010000);
                } else {
                    bb.putInt(0);
                }
            }
            for (int i = 0; i < 6; i++) {          // pre_defined
                bb.putInt(0);
            }
            bb.putInt(2);                          // next_track_id
            return fullBox("mvhd", (byte) 0, 0, bb.array());
        }

        // ---- trak ----
        private static byte[] buildTrak(int timescale, int duration, int numSamples,
                                         int sampleDelta, int mdatPayloadOffset) {
            byte[] tkhd = buildTkhd(duration);
            byte[] mdia = buildMdia(timescale, duration, numSamples, sampleDelta, mdatPayloadOffset);
            return box("trak", concat(tkhd, mdia));
        }

        private static byte[] buildTkhd(int duration) {
            ByteBuffer bb = ByteBuffer.allocate(80).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(0);                          // creation_time
            bb.putInt(0);                          // modification_time
            bb.putInt(1);                          // track_id
            bb.putInt(0);                          // reserved
            bb.putInt(duration);
            bb.putLong(0);                         // reserved
            bb.putShort((short) 0);                // layer
            bb.putShort((short) 0);                // alternate_group
            bb.putShort((short) 0x0100);           // volume (1.0)
            bb.putShort((short) 0);                // reserved
            for (int i = 0; i < 9; i++) {          // matrix (identity)
                if (i == 0 || i == 4) {
                    bb.putInt(0x00010000);
                } else {
                    bb.putInt(0);
                }
            }
            bb.putInt(0);                          // width
            bb.putInt(0);                          // height
            // flags: track_enabled(0x1) | track_in_movie(0x2) | track_in_preview(0x4) = 0x7
            return fullBox("tkhd", (byte) 0, 0x000007, bb.array());
        }

        // ---- mdia ----
        private static byte[] buildMdia(int timescale, int duration, int numSamples,
                                         int sampleDelta, int mdatPayloadOffset) {
            byte[] mdhd = buildMdhd(timescale, duration);
            byte[] hdlr = buildHdlr();
            byte[] minf = buildMinf(numSamples, sampleDelta, mdatPayloadOffset);
            return box("mdia", concat(mdhd, hdlr, minf));
        }

        private static byte[] buildMdhd(int timescale, int duration) {
            ByteBuffer bb = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(0);                          // creation_time
            bb.putInt(0);                          // modification_time
            bb.putInt(timescale);
            bb.putInt(duration);
            bb.putShort((short) 0x55C4);           // language "und"
            bb.putShort((short) 0);                // pre_defined
            return fullBox("mdhd", (byte) 0, 0, bb.array());
        }

        private static byte[] buildHdlr() {
            ByteBuffer bb = ByteBuffer.allocate(33).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(0);                          // pre_defined
            bb.put("soun".getBytes(StandardCharsets.US_ASCII)); // handler_type
            for (int i = 0; i < 3; i++) {          // reserved (12 bytes)
                bb.putInt(0);
            }
            bb.put("SoundHandler\0".getBytes(StandardCharsets.US_ASCII)); // name
            return fullBox("hdlr", (byte) 0, 0, bb.array());
        }

        // ---- minf ----
        private static byte[] buildMinf(int numSamples, int sampleDelta, int mdatPayloadOffset) {
            byte[] smhd = buildSmhd();
            byte[] dinf = buildDinf();
            byte[] stbl = buildStbl(numSamples, sampleDelta, mdatPayloadOffset);
            return box("minf", concat(smhd, dinf, stbl));
        }

        private static byte[] buildSmhd() {
            ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            bb.putShort((short) 0);                // balance
            bb.putShort((short) 0);                // reserved
            return fullBox("smhd", (byte) 0, 0, bb.array());
        }

        private static byte[] buildDinf() {
            // url box: flags=1 (self-contained), no payload
            byte[] url = fullBox("url ", (byte) 0, 0x000001, new byte[0]);
            ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(1);                          // entry_count
            byte[] drefPayload = concat(bb.array(), url);
            return box("dinf", fullBox("dref", (byte) 0, 0, drefPayload));
        }

        // ---- stbl ----
        private static byte[] buildStbl(int numSamples, int sampleDelta, int mdatPayloadOffset) {
            byte[] stsd = buildStsd();
            byte[] stts = buildStts(numSamples, sampleDelta);
            byte[] stsc = buildStsc(numSamples);
            byte[] stsz = buildStsz(numSamples);
            byte[] stco = buildStco(mdatPayloadOffset);
            return box("stbl", concat(stsd, stts, stsc, stsz, stco));
        }

        private static byte[] buildStsd() {
            // mp4a sample entry (AudioSampleEntry = 28 bytes + optional boxes)
            byte[] esds = buildEsds();
            ByteBuffer mp4a = ByteBuffer.allocate(28 + esds.length).order(ByteOrder.BIG_ENDIAN);
            for (int i = 0; i < 6; i++) mp4a.put((byte) 0); // reserved (SampleEntry prefix)
            mp4a.putShort((short) 1);              // data_reference_index
            mp4a.putInt(0);                        // reserved[0] (uint32, version/revision)
            mp4a.putInt(0);                        // reserved[1] (uint32, vendor)
            mp4a.putShort((short) 1);              // channelcount
            mp4a.putShort((short) 16);             // samplesize
            mp4a.putShort((short) 0);              // pre_defined
            mp4a.putShort((short) 0);              // reserved
            mp4a.putInt(44100 << 16);              // samplerate (16.16 fixed point)
            mp4a.put(esds);

            byte[] mp4aBox = box("mp4a", mp4a.array());

            ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(1);                          // entry_count
            return fullBox("stsd", (byte) 0, 0, concat(bb.array(), mp4aBox));
        }

        /**
         * 构建 esds box：包含 AAC-LC (44.1kHz mono) 的 DecoderSpecificInfo。
         */
        private static byte[] buildEsds() {
            // AudioSpecificConfig: AAC-LC, 44.1kHz, mono → 0x1210
            byte[] asc = new byte[]{(byte) 0x12, (byte) 0x10};

            // DecoderSpecificInfo (tag=5)
            byte[] dsi = descriptor(0x05, asc);

            // SLConfigDescriptor (tag=6, predefined=0x02)
            byte[] sl = descriptor(0x06, new byte[]{0x02});

            // DecoderConfigDescriptor (tag=4)
            ByteBuffer dcd = ByteBuffer.allocate(13).order(ByteOrder.BIG_ENDIAN);
            dcd.put((byte) 0x40);                  // objectTypeIndication (MPEG-4 Audio)
            dcd.put((byte) 0x15);                  // streamType(5)<<2|1<<1|1 = 0x15 (Audio, upstream=0, reserved=1)
            dcd.put((byte) 0);                     // bufferSizeDB[2]
            dcd.put((byte) 0);                     // bufferSizeDB[1]
            dcd.put((byte) 0);                     // bufferSizeDB[0]
            dcd.putInt(128000);                    // maxBitrate
            dcd.putInt(128000);                    // avgBitrate
            byte[] dcdPayload = concat(dcd.array(), dsi, sl);
            byte[] dcdDescriptor = descriptor(0x04, dcdPayload);

            // ES_Descriptor (tag=3)
            ByteBuffer es = ByteBuffer.allocate(3).order(ByteOrder.BIG_ENDIAN);
            es.putShort((short) 1);                // ES_ID
            es.put((byte) 0);                      // flags (no stream dependence, no URL, no OCR)
            byte[] esPayload = concat(es.array(), dcdDescriptor);
            byte[] esDescriptor = descriptor(0x03, esPayload);

            return fullBox("esds", (byte) 0, 0, esDescriptor);
        }

        /**
         * 构建 MPEG-4 描述符（tag + variable-length size + data）。
         *
         * <p>对于长度 &lt; 128 的情况，使用单字节长度编码。
         */
        private static byte[] descriptor(int tag, byte[] data) {
            int len = data.length;
            if (len >= 128) {
                throw new IllegalArgumentException("仅支持长度 < 128 的描述符");
            }
            byte[] result = new byte[2 + data.length];
            result[0] = (byte) tag;
            result[1] = (byte) len;
            System.arraycopy(data, 0, result, 2, data.length);
            return result;
        }

        // --- stts / stsc / stsz / stco ---

        private static byte[] buildStts(int numSamples, int sampleDelta) {
            ByteBuffer bb = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(numSamples);                 // sample_count
            bb.putInt(sampleDelta);                // sample_delta
            ByteBuffer hdr = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            hdr.putInt(1);                         // entry_count
            return fullBox("stts", (byte) 0, 0, concat(hdr.array(), bb.array()));
        }

        private static byte[] buildStsc(int numSamples) {
            ByteBuffer bb = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(1);                          // first_chunk
            bb.putInt(numSamples);                 // samples_per_chunk
            bb.putInt(1);                          // sample_description_index
            ByteBuffer hdr = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            hdr.putInt(1);                         // entry_count
            return fullBox("stsc", (byte) 0, 0, concat(hdr.array(), bb.array()));
        }

        private static byte[] buildStsz(int numSamples) {
            // variable sample size: use a fixed size sample
            int sampleSize = 100;
            ByteBuffer bb = ByteBuffer.allocate(8 + numSamples * 4).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(0);                          // sample_size = 0 (variable)
            bb.putInt(numSamples);                 // sample_count
            for (int i = 0; i < numSamples; i++) {
                bb.putInt(sampleSize);             // entry_size
            }
            return fullBox("stsz", (byte) 0, 0, bb.array());
        }

        private static byte[] buildStco(int mdatPayloadOffset) {
            ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(mdatPayloadOffset);          // chunk_offset
            ByteBuffer hdr = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            hdr.putInt(1);                         // entry_count
            return fullBox("stco", (byte) 0, 0, concat(hdr.array(), bb.array()));
        }

        // ---- 基础 box 构建 ----

        /**
         * 构建普通 box（32-bit size + type + payload）。
         */
        private static byte[] box(String type, byte[] payload) {
            ByteBuffer bb = ByteBuffer.allocate(8 + payload.length).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(8 + payload.length);
            bb.put(type.getBytes(StandardCharsets.US_ASCII));
            bb.put(payload);
            return bb.array();
        }

        /**
         * 构建 FullBox（32-bit size + type + version + flags + payload）。
         */
        private static byte[] fullBox(String type, byte version, int flags, byte[] payload) {
            ByteBuffer bb = ByteBuffer.allocate(12 + payload.length).order(ByteOrder.BIG_ENDIAN);
            bb.putInt(12 + payload.length);
            bb.put(type.getBytes(StandardCharsets.US_ASCII));
            bb.put(version);
            bb.put((byte) ((flags >> 16) & 0xFF));
            bb.put((byte) ((flags >> 8) & 0xFF));
            bb.put((byte) (flags & 0xFF));
            bb.put(payload);
            return bb.array();
        }
    }
}
