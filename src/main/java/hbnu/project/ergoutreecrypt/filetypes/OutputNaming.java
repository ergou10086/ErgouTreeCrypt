package hbnu.project.ergoutreecrypt.filetypes;

import java.nio.file.Path;
import java.util.Locale;

/**
 * 输出文件命名的统一纯函数集合。
 *
 * <p>此前命名逻辑散落在桌面端 {@code MainController.computeDefaultOutput}、
 * {@code MediaCryptController.computeDefaultOutput}、{@code MainViewSupport.deriveDecryptOutput}
 * 与移动端 {@code EncryptScreen}/{@code DecryptScreen}/{@code StegoScreen} 中，各写各的
 * 后缀拼接，是「{@code .enc.ext} 被误判为普通卷」之类问题的根源之一。此处集中为
 * 无副作用的纯函数，两端共用同一套规则：
 * <ul>
 *   <li>通用加密：{@code 原名.ergou}；</li>
 *   <li>格式保持加密：{@code 基名.enc.扩展名}；</li>
 *   <li>通用解密：剥掉 {@code .ergou}/{@code .pcv}，否则追加 {@code .decrypted}；</li>
 *   <li>格式保持解密：剥掉 {@code .enc} 标记后追加 {@code .dec}；</li>
 *   <li>隐写嵌入：{@code 基名_stego.扩展名}。</li>
 * </ul>
 *
 * <p><b>不负责</b>文件名合法化（非法字符清洗）：移动端在调用本类前自行调用
 * {@code FileNameSanitizer}，桌面端无此限制。因此本类返回的名字可直接用作文件名。
 *
 * @author ErgouTree
 * @since 2026/9/14
 */
public final class OutputNaming {

    /**
     * 通用加密卷的后缀。
     */
    public static final String GENERIC_SUFFIX = ".ergou";

    /**
     * 旧版通用加密卷的后缀（仅用于解密时剥离）。
     */
    public static final String LEGACY_SUFFIX = ".pcv";

    /**
     * 格式保持加密的标记后缀（插在基名与扩展名之间）。
     */
    public static final String FPE_MARKER = ".enc";

    /**
     * 格式保持解密的标记后缀（插在基名与扩展名之间）。
     */
    public static final String FPE_DEC_SUFFIX = ".dec";

    /**
     * 通用解密在无法剥离卷后缀时的兜底后缀。
     */
    public static final String DECRYPT_FALLBACK_SUFFIX = ".decrypted";

    /**
     * 隐写产物的文件名标记后缀（插在基名与扩展名之间）。
     */
    public static final String STEGO_MARKER = "_stego";

    private OutputNaming() {
    }

    /**
     * 计算通用加密的输出文件名。
     *
     * @param fileName 输入文件名（不含路径）
     * @return 输入名追加 {@code .ergou}
     */
    public static String encryptOutputName(final String fileName) {
        return fileName + GENERIC_SUFFIX;
    }

    /**
     * 计算通用加密的输出路径（与输入同目录）。
     *
     * @param input 输入文件路径
     * @return 同目录下追加 {@code .ergou} 的输出路径
     */
    public static Path encryptOutput(final Path input) {
        return input.resolveSibling(encryptOutputName(input.getFileName().toString()));
    }

    /**
     * 计算格式保持加密的输出文件名。
     *
     * <p>形如 {@code song.mp3 → song.enc.mp3}，必须保留原媒体扩展名，否则两端解密
     * 无法按扩展名识别媒体格式。文件名无扩展名时退化为 {@code 原名.enc}。
     *
     * @param fileName 输入媒体文件名（不含路径）
     * @return 基名与扩展名之间插入 {@code .enc} 的文件名
     */
    public static String fpeEncryptOutputName(final String fileName) {
        int dot = fileName.lastIndexOf('.');
        if (dot <= 0) {
            return fileName + FPE_MARKER;
        }
        return fileName.substring(0, dot) + FPE_MARKER + fileName.substring(dot);
    }

    /**
     * 计算格式保持加密的输出路径（与输入同目录）。
     *
     * @param input 输入媒体文件路径
     * @return 同目录下形如 {@code song.enc.mp3} 的输出路径
     */
    public static Path fpeEncryptOutput(final Path input) {
        return input.resolveSibling(fpeEncryptOutputName(input.getFileName().toString()));
    }

    /**
     * 计算通用解密的输出文件名。
     *
     * <p>剥离 {@code .ergou} 或 {@code .pcv} 后缀；两者皆无时追加
     * {@link #DECRYPT_FALLBACK_SUFFIX}，与原 {@code MainViewSupport.deriveDecryptOutput}
     * 的兜底行为一致。
     *
     * @param fileName 输入加密卷文件名（不含路径）
     * @return 剥离卷后缀后的文件名
     */
    public static String decryptOutputName(final String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (lower.endsWith(GENERIC_SUFFIX)) {
            return fileName.substring(0, fileName.length() - GENERIC_SUFFIX.length());
        }
        if (lower.endsWith(LEGACY_SUFFIX)) {
            return fileName.substring(0, fileName.length() - LEGACY_SUFFIX.length());
        }
        return fileName + DECRYPT_FALLBACK_SUFFIX;
    }

    /**
     * 计算通用解密的输出路径（与输入同目录）。
     *
     * @param input 输入加密卷路径
     * @return 剥离卷后缀后的输出路径
     */
    public static Path decryptOutput(final Path input) {
        return input.resolveSibling(decryptOutputName(input.getFileName().toString()));
    }

    /**
     * 计算格式保持解密的输出文件名。
     *
     * <p>剥掉基名末尾的 {@code .enc} 标记后插入 {@code .dec}，保留原媒体扩展名，
     * 形如 {@code song.enc.mp3 → song.dec.mp3}；输入本身无 {@code .enc} 标记时
     * 按噪声媒体处理，直接得到 {@code song.dec.mp3}。
     *
     * @param fileName 输入媒体文件名（不含路径）
     * @return 形如 {@code 基名.dec.扩展名} 的文件名
     */
    public static String fpeDecryptOutputName(final String fileName) {
        int dot = fileName.lastIndexOf('.');
        String base = dot > 0 ? fileName.substring(0, dot) : fileName;
        String ext = dot > 0 ? fileName.substring(dot) : "";
        String stem = stripMarkerToken(base);
        return stem + FPE_DEC_SUFFIX + ext;
    }

    /**
     * 计算格式保持解密的输出路径（与输入同目录）。
     *
     * @param input 输入加密媒体路径
     * @return 同目录下形如 {@code song.dec.mp3} 的输出路径
     */
    public static Path fpeDecryptOutput(final Path input) {
        return input.resolveSibling(fpeDecryptOutputName(input.getFileName().toString()));
    }

    /**
     * 计算隐写产物的输出文件名。
     *
     * <p>形如 {@code photo.png → photo_stego.png}，与两端「隐藏」操作当前的默认命名一致。
     *
     * @param carrierName 载体文件名（不含路径）
     * @return 基名与扩展名之间插入 {@code _stego} 的文件名
     */
    public static String stegoOutputName(final String carrierName) {
        int dot = carrierName.lastIndexOf('.');
        if (dot <= 0) {
            return carrierName + STEGO_MARKER;
        }
        return carrierName.substring(0, dot) + STEGO_MARKER + carrierName.substring(dot);
    }

    /**
     * 计算隐写产物的输出路径（与载体同目录）。
     *
     * @param carrier 载体文件路径
     * @return 同目录下形如 {@code photo_stego.png} 的输出路径
     */
    public static Path stegoOutput(final Path carrier) {
        return carrier.resolveSibling(stegoOutputName(carrier.getFileName().toString()));
    }

    /**
     * 剥掉文件名中的 {@code .enc} 格式保持加密标记（大小写不敏感）。
     *
     * <p>形如 {@code song.enc.mp4 → song.mp4}、{@code song.enc → song}；不含该标记时
     * 原样返回。用于「解密后解压 / 解压后解密」等需要还原原始文件名的场景。
     *
     * @param fileName 文件名（可含扩展名，不含路径）
     * @return 去掉 {@code .enc} 标记的文件名
     */
    public static String stripFpeMarker(final String fileName) {
        int dot = fileName.lastIndexOf('.');
        if (dot > 0) {
            String base = fileName.substring(0, dot);
            if (endsWithMarker(base)) {
                return base.substring(0, base.length() - FPE_MARKER.length())
                        + fileName.substring(dot);
            }
        }
        if (endsWithMarker(fileName)) {
            return fileName.substring(0, fileName.length() - FPE_MARKER.length());
        }
        return fileName;
    }

    /**
     * 剥掉基名末尾的 {@code .enc} 标记（大小写不敏感）。
     *
     * @param base 已去掉扩展名的基名
     * @return 去掉 {@code .enc} 标记的基名；不含该标记时原样返回
     */
    private static String stripMarkerToken(final String base) {
        return endsWithMarker(base)
                ? base.substring(0, base.length() - FPE_MARKER.length())
                : base;
    }

    /**
     * 判断字符串是否以 {@code .enc} 标记结尾（大小写不敏感）。
     *
     * @param text 待判定字符串
     * @return true 表示以标记结尾
     */
    private static boolean endsWithMarker(final String text) {
        return text.length() >= FPE_MARKER.length()
                && text.regionMatches(true, text.length() - FPE_MARKER.length(),
                        FPE_MARKER, 0, FPE_MARKER.length());
    }
}
