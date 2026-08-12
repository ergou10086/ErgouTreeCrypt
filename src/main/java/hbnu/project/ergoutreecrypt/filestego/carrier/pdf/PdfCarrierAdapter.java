package hbnu.project.ergoutreecrypt.filestego.carrier.pdf;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * PDF 载体适配器（不受限方案）。
 *
 * <p>PDF 阅读器从文件末尾的 {@code startxref} 读取交叉引用表偏移，{@code %%EOF}
 * 之后的内容通常被忽略。本适配器据此在 {@code %%EOF} 之后追加一段以注释标记包裹的
 * Base64 数据块：
 * <pre>
 *   [完整 PDF，以 %%EOF 结尾]
 *   \n%STEG-BEGIN\n
 *   Base64([CarrierMetadata + Payload])
 *   \n%STEG-END\n
 * </pre>
 *
 * <p>使用 {@code %} 注释行 + Base64 可打印字符，兼顾 PDF 阅读器安全忽略与二进制安全。
 * PDF 内容位流无稳定冗余，故采用 %%EOF 后追加的容量无关方案。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class PdfCarrierAdapter extends AbstractCarrierAdapter {

    /** PDF 隐写数据起始标记。 */
    private static final String STEG_BEGIN = "%STEG-BEGIN";

    /** PDF 隐写数据结束标记。 */
    private static final String STEG_END = "%STEG-END";

    /** PDF 文件签名（前 5 字节 "%PDF-"）。 */
    private static final byte[] PDF_SIGNATURE = {0x25, 0x50, 0x44, 0x46, 0x2D};

    /** 检测时向文件末尾回溯的最大扫描字节数。 */
    private static final int DETECT_SCAN_LEN = 4096;

    @Override
    public String id() {
        return "pdf";
    }

    @Override
    public String displayName() {
        return "PDF 文档";
    }

    @Override
    public List<String> supportedExtensions() {
        return List.of(".pdf");
    }

    @Override
    protected void validateCarrier(final Path carrierFile) throws CarrierException {
        super.validateCarrier(carrierFile);
        try {
            byte[] head = new byte[PDF_SIGNATURE.length];
            try (var in = Files.newInputStream(carrierFile)) {
                int read = in.readNBytes(head, 0, head.length);
                if (read != head.length || !Arrays.equals(head, PDF_SIGNATURE)) {
                    throw new CarrierException("不是有效的 PDF 文件（签名不匹配）: " + carrierFile);
                }
            }
        } catch (IOException e) {
            throw new CarrierException("读取 PDF 文件失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected void doEmbed(final Path carrier, final byte[] payload, final byte[] meta,
                           final Path output, final byte[] password,
                           final EmbedOptions options) throws CarrierException {
        // payload 参数此处为门面组合好的 [CarrierMetadata + Payload] 不透明块
        byte[] combined = payload;
        String base64 = Base64.getEncoder().encodeToString(combined);
        String block = "\n" + STEG_BEGIN + "\n" + base64 + "\n" + STEG_END + "\n";
        try {
            byte[] pdfBytes = Files.readAllBytes(carrier);
            try (OutputStream out = Files.newOutputStream(output,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                out.write(pdfBytes);
                out.write(block.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            throw new CarrierException("PDF 嵌入失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected CarrierMetadata doExtract(final Path stegoFile, final byte[] password)
            throws CarrierException {
        byte[] combined = readCombined(stegoFile);
        return CarrierMetadata.fromBytes(combined);
    }

    @Override
    protected byte[] readPayload(final Path stegoFile, final CarrierMetadata meta)
            throws CarrierException {
        byte[] combined = readCombined(stegoFile);
        int metaLen = CarrierMetadata.totalSize(meta.isParanoid(), meta.isStealth());
        if (combined.length < metaLen) {
            throw new CarrierException("PDF 隐写数据不完整：组合块短于元数据长度");
        }
        return Arrays.copyOfRange(combined, metaLen, combined.length);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            byte[] bytes = Files.readAllBytes(file);
            // %STEG-END 恒为最后一个标记，紧邻文件末尾，故在尾部窗口内扫描它更可靠
            int scanFrom = Math.max(0, bytes.length - DETECT_SCAN_LEN);
            int idx = lastIndexOf(bytes, STEG_END.getBytes(StandardCharsets.US_ASCII), scanFrom);
            return idx >= 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从隐写 PDF 中解析并解码组合块。
     *
     * @param stegoFile 隐写 PDF 文件
     * @return 组合块字节
     * @throws CarrierException 未找到标记或 Base64 解码失败
     */
    private byte[] readCombined(final Path stegoFile) throws CarrierException {
        try {
            byte[] bytes = Files.readAllBytes(stegoFile);
            byte[] beginMarker = STEG_BEGIN.getBytes(StandardCharsets.US_ASCII);
            byte[] endMarker = STEG_END.getBytes(StandardCharsets.US_ASCII);

            int beginIdx = lastIndexOf(bytes, beginMarker, 0);
            if (beginIdx < 0) {
                throw new CarrierException("PDF 中未找到隐写数据标记");
            }
            int dataStart = beginIdx + beginMarker.length;
            int endIdx = indexOf(bytes, endMarker, dataStart);
            if (endIdx < 0) {
                throw new CarrierException("PDF 隐写数据缺少结束标记");
            }

            String base64 = new String(bytes, dataStart, endIdx - dataStart,
                    StandardCharsets.US_ASCII).trim();
            byte[] combined;
            try {
                combined = Base64.getMimeDecoder().decode(base64);
            } catch (IllegalArgumentException e) {
                throw new CarrierException("PDF 隐写数据 Base64 解码失败: " + e.getMessage(), e);
            }
            if (!CarrierMetadata.startsWithMagic(combined)) {
                throw new CarrierException("PDF 隐写数据不是有效的隐写载荷");
            }
            return combined;
        } catch (IOException e) {
            throw new CarrierException("读取 PDF 隐写数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 在字节数组中从指定位置起正向查找子序列。
     *
     * @param data   源字节
     * @param needle 子序列
     * @param from   起始偏移
     * @return 首次匹配偏移，未找到返回 -1
     */
    private static int indexOf(final byte[] data, final byte[] needle, final int from) {
        if (needle.length == 0 || from < 0) {
            return -1;
        }
        outer:
        for (int i = from; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * 在字节数组中从指定下界起反向查找子序列的最后一次出现。
     *
     * @param data     源字节
     * @param needle   子序列
     * @param minStart 允许匹配的最小起始偏移
     * @return 最后一次匹配偏移，未找到返回 -1
     */
    private static int lastIndexOf(final byte[] data, final byte[] needle, final int minStart) {
        if (needle.length == 0) {
            return -1;
        }
        outer:
        for (int i = data.length - needle.length; i >= minStart; i--) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
