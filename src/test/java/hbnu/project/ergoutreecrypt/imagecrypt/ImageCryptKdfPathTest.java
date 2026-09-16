package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.Argon2OffHeap;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.NativeArgon2;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * EGTC-IMG v1 的 KDF 执行路径一致性与依赖版本一致性校验。
 *
 * <h3>为什么"同一份源码"还不够</h3>
 * <p>共享核心只有一份，但 {@code Argon2Kdf} 在运行时会按可用堆内存选择三条完全不同的执行路径：
 * BouncyCastle 的堆内实现、Java 离堆实现（{@code Argon2OffHeap}）与 native libargon2。
 * "任意端生成、任意端恢复"要求这三条路径在<b>同一组输入下产出逐字节相同的 32 字节密钥</b>——
 * 只要有一条在某个参数组合上偏移一位，密码模式的文件就会变成"只有本机能打开"。
 *
 * <h3>v1 只使用一组固定参数</h3>
 * <p>因此本测试不复用通用的参数扫描（那属于 Argon2 原语自身的回归），而是钉住 v1 的规范性
 * 组合 {@code 65536 KiB / 3 passes / 4 lanes / 32 字节输出}：它是两端唯一会真正遇到的档位。
 *
 * <h3>为什么还要比较构建文件里的版本号</h3>
 * <p>Maven 与 Gradle 各自解析依赖。若两处声明的 Bouncy Castle 版本不同，桌面端与 Android 端
 * 就会跑在不同版本的 Argon2 实现上，而所有在单一构建里通过的测试都不会有任何异常表现。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class ImageCryptKdfPathTest {

    /**
     * v1 测试口令（用 8 位以上、含大小写与数字，贴近真实使用而非"password"）。
     */
    private static final byte[] PASSWORD = "Str0ng-Pass".getBytes(StandardCharsets.UTF_8);

    /**
     * 固定 salt，取自 EGTC-IMG v1 的 salt 长度（16 字节）。
     */
    private static final byte[] SALT = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    /**
     * 三条执行路径在 v1 规范性参数下必须给出完全相同的密钥。
     */
    @Test
    void everyExecutionPathAgreesOnV1Parameters() {
        byte[] heap = deriveWithBouncyCastle();

        byte[] offHeap = Argon2OffHeap.deriveKey(PASSWORD, SALT,
                ImageCryptProtocol.ARGON2_MEMORY_KIB,
                ImageCryptProtocol.ARGON2_PASSES,
                ImageCryptProtocol.ARGON2_LANES,
                ImageCryptProtocol.ARGON2_OUTPUT_LENGTH);
        assertEquals(ImageCryptProtocol.ARGON2_OUTPUT_LENGTH, offHeap.length);
        assertArrayEquals(heap, offHeap, "Java 离堆实现与 BouncyCastle 在 v1 参数下不一致");

        // native libargon2 只在打包了 .so 的平台（Android）可用；桌面端跳过而不是伪造结果
        if (NativeArgon2.isAvailable()) {
            byte[] nativeKey = NativeArgon2.deriveKey(PASSWORD, SALT,
                    ImageCryptProtocol.ARGON2_MEMORY_KIB,
                    ImageCryptProtocol.ARGON2_PASSES,
                    ImageCryptProtocol.ARGON2_LANES,
                    ImageCryptProtocol.ARGON2_OUTPUT_LENGTH);
            assertArrayEquals(heap, nativeKey, "native libargon2 与 BouncyCastle 在 v1 参数下不一致");
            assertArrayEquals(offHeap, nativeKey, "native libargon2 与离堆实现在 v1 参数下不一致");
        }
    }

    /**
     * 门面的密钥编排必须与"直接用 BouncyCastle 派生 + HKDF 域分离"逐字节一致。
     *
     * <p>这条断言把 {@link ImageKeySchedule} 与协议规范 §7 的密钥编排公式钉在一起：
     * 若有人把 info、salt 顺序或子密钥切分改掉，这里立刻失败，而不是等到跨端文件打不开。
     *
     * @throws Exception 派生或 HKDF 失败
     */
    @Test
    void imageKeyScheduleMatchesSpecifiedComposition() throws Exception {
        byte[] masterKey = deriveWithBouncyCastle();
        byte[] hkdfSalt = new byte[ImageCryptProtocol.HKDF_SALT_LENGTH];
        for (int i = 0; i < hkdfSalt.length; i++) {
            hkdfSalt[i] = (byte) (i * 7 + 3);
        }

        byte[] expectedMaterial = new HkdfStream(masterKey, hkdfSalt,
                ImageCryptProtocol.HKDF_INFO.getBytes(StandardCharsets.US_ASCII))
                .read(ImageCryptProtocol.KEY_MATERIAL_LENGTH);

        try (ImageKeySchedule direct = ImageKeySchedule.fromPublicMasterKey(masterKey, hkdfSalt)) {
            assertArrayEquals(expectedMaterial,
                    concat(direct.encKey(), direct.macKey()),
                    "公开模式的密钥编排与规范公式不一致");
        }

        try (ImageKeySchedule fromPassword = ImageKeySchedule.fromPassword(
                PASSWORD, SALT, hkdfSalt, null)) {
            assertArrayEquals(expectedMaterial,
                    concat(fromPassword.encKey(), fromPassword.macKey()),
                    "密码模式的密钥编排与规范公式不一致");
        }
        org.bouncycastle.util.Arrays.clear(expectedMaterial);
        org.bouncycastle.util.Arrays.clear(masterKey);
    }

    /**
     * 公开模式的密钥编排路径不得触碰 Argon2，密码模式才允许派生。
     *
     * <p>这条断言守的是"无密码路径不执行 Argon2"这条发布验收项：公开模式若误入 KDF，
     * 既浪费时间，也让人误以为该模式有额外的机密性来源。
     *
     * @throws Exception 派生失败
     */
    @Test
    void publicModeNeverEntersArgon2() throws Exception {
        byte[] masterKey = new byte[ImageCryptProtocol.MASTER_KEY_LENGTH];
        for (int i = 0; i < masterKey.length; i++) {
            masterKey[i] = (byte) (i + 1);
        }
        byte[] hkdfSalt = new byte[ImageCryptProtocol.HKDF_SALT_LENGTH];

        long start = System.nanoTime();
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(masterKey, hkdfSalt)) {
            assertTrue(schedule.encKey().length == ImageCryptProtocol.ENC_KEY_LENGTH);
        }
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;

        // 一次 64 MiB / 3 passes 的 Argon2 在桌面端需要数百毫秒；公开模式只做 HKDF，
        // 因此用宽松阈值把"误入 KDF"与正常的哈希开销区分开
        assertTrue(elapsedMillis < 50,
                "公开恢复模式的密钥编排耗时 " + elapsedMillis + " ms，疑似进入了 Argon2");
    }

    /**
     * Maven 与两个 Gradle 构建必须声明同一个 Bouncy Castle 版本。
     *
     * @throws IOException 读取构建文件失败
     */
    @Test
    void bouncyCastleVersionIsIdenticalAcrossBuildFiles() throws IOException {
        Path pom = Path.of("pom.xml");
        Path libs = Path.of("android/gradle/libs.versions.toml");
        Path sharedTest = Path.of("android/shared-test/build.gradle.kts");
        Assumptions.assumeTrue(Files.isRegularFile(pom) && Files.isRegularFile(libs)
                        && Files.isRegularFile(sharedTest),
                "不在仓库根目录运行，跳过构建文件比对");

        String mavenVersion = firstGroup(Files.readString(pom),
                "<bouncycastle\\.version>([0-9][^<]*)</bouncycastle\\.version>", "pom.xml");
        String gradleVersion = firstGroup(Files.readString(libs),
                "(?m)^bouncycastle\\s*=\\s*\"([0-9][^\"]*)\"", "libs.versions.toml");
        String sharedTestVersion = firstGroup(Files.readString(sharedTest),
                "bcprov-jdk18on:([0-9][^\"']*)", "shared-test/build.gradle.kts");

        assertEquals(mavenVersion, gradleVersion,
                "Maven 与 Android app 的 Bouncy Castle 版本不一致");
        assertEquals(mavenVersion, sharedTestVersion,
                "Maven 与 android/shared-test 的 Bouncy Castle 版本不一致");
    }

    // ==================== 工具 ====================

    /**
     * 直接用 BouncyCastle 的 Argon2id 派生 v1 密钥。
     *
     * @return 32 字节密钥
     */
    private static byte[] deriveWithBouncyCastle() {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(ImageCryptProtocol.ARGON2_MEMORY_KIB)
                .withIterations(ImageCryptProtocol.ARGON2_PASSES)
                .withParallelism(ImageCryptProtocol.ARGON2_LANES)
                .withSalt(SALT)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        byte[] output = new byte[ImageCryptProtocol.ARGON2_OUTPUT_LENGTH];
        generator.generateBytes(PASSWORD, output);
        return output;
    }

    /**
     * 拼接两段密钥材料。
     *
     * @param first  第一段
     * @param second 第二段
     * @return 拼接结果
     */
    private static byte[] concat(final byte[] first, final byte[] second) {
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }

    /**
     * 取出正则的第一个捕获组。
     *
     * @param text    文本
     * @param pattern 正则
     * @param source  来源描述（用于失败信息）
     * @return 捕获组内容
     */
    private static String firstGroup(final String text, final String pattern, final String source) {
        Matcher matcher = Pattern.compile(pattern).matcher(text);
        assertTrue(matcher.find(), "未能在 " + source + " 中解析出 Bouncy Castle 版本");
        return matcher.group(1);
    }

    /**
     * 断言 Argon2Kdf 门面在 v1 参数下也能派生（覆盖 KDF 锁与档位校验路径）。
     *
     * @throws Exception 派生失败
     */
    @Test
    void argon2FacadeAcceptsV1Parameters() throws Exception {
        byte[] key = Argon2Kdf.deriveKey(PASSWORD, SALT, false,
                ImageCryptProtocol.ARGON2_MEMORY_KIB,
                ImageCryptProtocol.ARGON2_PASSES,
                ImageCryptProtocol.ARGON2_LANES,
                null);
        assertArrayEquals(deriveWithBouncyCastle(), key,
                "门面派生的密钥与直接调用 BouncyCastle 不一致");
    }
}
