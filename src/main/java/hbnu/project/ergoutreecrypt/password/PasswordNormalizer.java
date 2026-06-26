package hbnu.project.ergoutreecrypt.password;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 密码归一化
 *
 * <h3>设计依据</h3>
 * <p>不同平台（macOS 用 NFD、Windows/Linux 用 NFC）输入的同一视觉密码，底层字节不同，
 * 导致 Argon2 导出不同密钥。本类在加密时将密码归一为 NFC（RFC 8265 / NIST SP 800-63B-4），
 * 解密时依次尝试 NFC/NFD/raw 三种形态，确保跨平台互操作性
 *
 * <p>兼容归一（NFKC/NFKD，会合并不同字符降低熵）、大小写折叠（土耳其 dotless-i 碰撞）、空白裁剪（降低熵）。
 *
 * @author ErgouTree
 */
public final class PasswordNormalizer {

    private PasswordNormalizer() {
    }

    /**
     * 将输入归一为 Unicode NFC 形式。
     */
    public static String normalize(String pw) {
        if (pw == null) {
            return "";
        }
        return Normalizer.normalize(pw, Normalizer.Form.NFC);
    }

    /**
     * 加密时使用的 KDF 输入：NFC 归一化后的 UTF-8 字节。
     */
    public static byte[] encodeForKdf(String pw) {
        return normalize(pw == null ? "" : pw).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 解密时依次尝试的密码候选形态（去重后最多 3 个）。
     *
     * <ol>
     *   <li>NFC — 新卷 + 旧 ASCII/NFC 卷（优先，命中率最高）</li>
     *   <li>NFD — 旧分解形态卷</li>
     *   <li>raw — 非规范顺序（既非 NFC 也非 NFD）的遗留卷</li>
     * </ol>
     *
     * <p>ASCII 密码仅返回 1 个候选（ASCII 在所有归一形态下不变），避免额外的 Argon2 开销。
     */
    public static List<byte[]> candidates(String pw) {
        if (pw == null) {
            pw = "";
        }
        List<byte[]> result = new ArrayList<>(3);

        if (!containsNonASCII(pw)) {
            // ASCII is invariant, single candidate
            result.add(pw.getBytes(StandardCharsets.UTF_8));
            return result;
        }

        byte[] nfc = Normalizer.normalize(pw, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8);
        byte[] nfd = Normalizer.normalize(pw, Normalizer.Form.NFD).getBytes(StandardCharsets.UTF_8);
        byte[] raw = pw.getBytes(StandardCharsets.UTF_8);

        addIfNotPresent(result, nfc);
        addIfNotPresent(result, nfd);
        addIfNotPresent(result, raw);

        return result;
    }

    /**
     * 密码中是否含非 ASCII 字符。
     */
    public static boolean containsNonASCII(String pw) {
        if (pw == null) {
            return false;
        }
        for (int i = 0; i < pw.length(); i++) {
            if (pw.charAt(i) >= 0x80) {
                return true;
            }
        }
        return false;
    }

    private static void addIfNotPresent(List<byte[]> list, byte[] candidate) {
        for (byte[] existing : list) {
            if (Arrays.equals(existing, candidate)) {
                return;
            }
        }
        list.add(candidate);
    }
}
