package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.CancelledException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.png.PixelPngReader;
import hbnu.project.ergoutreecrypt.imagecrypt.png.PixelPngWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.assertKind;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.fixture;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.minimalBmp;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.minimalGif;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.refreshCrc32;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ImageCryptCodec} 的全流程测试：五种首期格式的字节级往返、认证失败分类、
 * 截断与尾部追加、取消清理、目标冲突与只读探测。
 *
 * <h3>为什么断言"字节一致"而不是"像素一致"</h3>
 * <p>本功能承诺的是恢复文件与输入文件逐字节相同，因此每条往返断言都比较 SHA-256 与长度，
 * 并在不一致时用 {@link Files#mismatch(Path, Path)} 报出第一个差异偏移。
 *
 * <h3>慢测试的取舍</h3>
 * <p>密码模式的 Argon2id 固定为 64 MiB / 3 passes，单次派生约需一秒。因此只有少数用例
 * 使用真实密码派生；其余覆盖保护模式之外逻辑的用例一律走公开恢复，避免把测试时间浪费在
 * 重复的 KDF 上。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class ImageCryptCodecTest {

    /**
     * 测试输出目录。
     */
    @TempDir
    Path workDir;

    /**
     * 公开恢复下五种首期格式都必须逐字节往返。
     *
     * @throws Exception 读写失败
     */
    @Test
    void publicRecoveryRoundTripsEverySupportedFormat() throws Exception {
        for (FormatSample sample : samples()) {
            Path source = write(sample.fileName(), sample.bytes());
            Path encrypted = workDir.resolve(sample.fileName() + ".egimg.png");
            Path restoreDir = Files.createDirectories(workDir.resolve("out-" + sample.fileName()));

            new ImageCryptCodec().encrypt(source, encrypted, null,
                    ImageCryptOptions.of(ImageCryptMode.PUBLIC_RECOVERY), ImageCryptProgress.NONE);
            assertTrue(Files.exists(encrypted), sample.fileName() + " 未产出产物");

            Path restored = new ImageCryptCodec().decrypt(encrypted, restoreDir, null,
                    ImageCryptProgress.NONE);
            assertSameBytes(source, restored, sample.fileName());
        }
    }

    /**
     * 密码保护模式必须逐字节往返，且 ASCII 与组合字符口令都成立。
     *
     * @throws Exception 读写失败
     */
    @Test
    void passwordModeRoundTripsAsciiAndComposedPasswords() throws Exception {
        byte[] ascii = ImageCryptPassword.encodeForV1("Str0ng-Pass");
        byte[] composed = ImageCryptPassword.encodeForV1("café-中文");
        byte[] source = fixture("sample.jpg");

        for (byte[] password : List.of(ascii, composed)) {
            Path sourcePath = write("photo.jpg", source);
            Path encrypted = workDir.resolve("pw-" + password.length + "-" + source.length + ".png");
            Path restoreDir = Files.createDirectories(workDir.resolve("pw-out-" + password.length));

            new ImageCryptCodec().encrypt(sourcePath, encrypted, password,
                    ImageCryptOptions.of(ImageCryptMode.PASSWORD), ImageCryptProgress.NONE);
            Path restored = new ImageCryptCodec().decrypt(encrypted, restoreDir, password,
                    ImageCryptProgress.NONE);
            assertSameBytes(sourcePath, restored, "密码模式");
        }
    }

    /**
     * 错误密码必须在 keyConfirm 阶段被拒绝，且不产出任何文件。
     *
     * @throws Exception 读写失败
     */
    @Test
    void wrongPasswordIsRejectedWithoutLeavingOutput() throws Exception {
        byte[] correct = ImageCryptPassword.encodeForV1("correct-horse");
        byte[] wrong = ImageCryptPassword.encodeForV1("wrong-horse");
        Path source = write("secret.png", fixture("sample.png"));
        Path encrypted = workDir.resolve("secret.egimg.png");
        Path restoreDir = Files.createDirectories(workDir.resolve("wrong-pw-out"));

        new ImageCryptCodec().encrypt(source, encrypted, correct,
                ImageCryptOptions.of(ImageCryptMode.PASSWORD), ImageCryptProgress.NONE);

        assertKind(ErrorKind.WRONG_PASSWORD,
                () -> new ImageCryptCodec().decrypt(encrypted, restoreDir, wrong));
        assertEquals(List.of(), listFiles(restoreDir), "错误密码不得留下任何恢复产物");
    }

    /**
     * 保护模式与密码的存在性必须匹配，两个方向都视为调用错误。
     *
     * @throws Exception 读写失败
     */
    @Test
    void protectionModeAndPasswordMustAgree() throws Exception {
        Path source = write("mode.png", fixture("sample.png"));
        Path target = workDir.resolve("mode.egimg.png");
        byte[] password = ImageCryptPassword.encodeForV1("pw");

        assertKind(ErrorKind.INTERNAL_ERROR,
                () -> new ImageCryptCodec().encrypt(source, target, null,
                        ImageCryptOptions.of(ImageCryptMode.PASSWORD), ImageCryptProgress.NONE));
        assertKind(ErrorKind.INTERNAL_ERROR,
                () -> new ImageCryptCodec().encrypt(source, target, new byte[0],
                        ImageCryptOptions.of(ImageCryptMode.PASSWORD), ImageCryptProgress.NONE));
        assertKind(ErrorKind.INTERNAL_ERROR,
                () -> new ImageCryptCodec().encrypt(source, target, password,
                        ImageCryptOptions.of(ImageCryptMode.PUBLIC_RECOVERY),
                        ImageCryptProgress.NONE));
        assertFalse(Files.exists(target), "模式冲突不得写出产物");
    }

    /**
     * 密码保护模式的文件缺少密码时必须早失败，且不生成任何文件。
     *
     * @throws Exception 读写失败
     */
    @Test
    void passwordProtectedFileRequiresPasswordOnDecrypt() throws Exception {
        byte[] password = ImageCryptPassword.encodeForV1("need-me");
        Path source = write("need.png", fixture("sample.png"));
        Path encrypted = workDir.resolve("need.egimg.png");
        Path restoreDir = Files.createDirectories(workDir.resolve("need-out"));

        new ImageCryptCodec().encrypt(source, encrypted, password,
                ImageCryptOptions.of(ImageCryptMode.PASSWORD), ImageCryptProgress.NONE);

        assertKind(ErrorKind.INTERNAL_ERROR,
                () -> new ImageCryptCodec().decrypt(encrypted, restoreDir, null));
        assertEquals(List.of(), listFiles(restoreDir));
    }

    /**
     * 密文与认证标签被改动都必须报"数据被修改"，而不是被当成密码错误。
     *
     * @throws Exception 读写失败
     */
    @Test
    void ciphertextAndAuthTagTamperingIsReportedAsTampered() throws Exception {
        Path source = write("tamper.png", fixture("sample.png"));
        Path encrypted = workDir.resolve("tamper.egimg.png");
        new ImageCryptCodec().encrypt(source, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        ImageCryptFrame frame = readFrame(encrypted);
        long ciphertextLength = frame.ciphertextLength();

        Path flippedCipher = tamperLogicalByte(encrypted, "tamper-cipher.png",
                (int) (ImageCryptProtocol.OUTER_HEADER_LENGTH + ciphertextLength - 1), 0x01);
        assertKind(ErrorKind.TAMPERED_DATA,
                () -> new ImageCryptCodec().decrypt(flippedCipher, outDir("tamper-cipher"), null));

        Path flippedTag = tamperLogicalByte(encrypted, "tamper-tag.png",
                (int) (ImageCryptProtocol.OUTER_HEADER_LENGTH + ciphertextLength), 0x01);
        assertKind(ErrorKind.TAMPERED_DATA,
                () -> new ImageCryptCodec().decrypt(flippedTag, outDir("tamper-tag"), null));
        assertEquals(List.of(), listFiles(outDir("tamper-tag")));
    }

    /**
     * 协议头字段被改动且 CRC 被同步重算后，仍必须被认证范围拦住。
     *
     * <p>被改的是 {@code hkdfSalt}：它不参与 headerCrc32 之外的任何结构校验，只能由
     * keyConfirm 与完整标签发现，因此这条用例专门证明"头部字段确实在认证覆盖内"。
     *
     * @throws Exception 读写失败
     */
    @Test
    void headerFieldChangeIsCaughtByAuthentication() throws Exception {
        Path source = write("header.png", fixture("sample.png"));
        Path encrypted = workDir.resolve("header.egimg.png");
        new ImageCryptCodec().encrypt(source, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        Path tampered = rewriteHeaderByte(encrypted, "header-tampered.png",
                ImageCryptProtocol.OFF_HKDF_SALT, 0x5a);
        assertKind(ErrorKind.TAMPERED_DATA,
                () -> new ImageCryptCodec().decrypt(tampered, outDir("header-tampered"), null));
    }

    /**
     * 认证覆盖之外的画布填充被重写后，还原结果必须保持不变。
     *
     * <p>padding 是协议明文规定的展示性填充，不参与认证也不参与恢复；若实现误把它纳入
     * 载荷或校验，这条用例会因为"额外的字节"而失败。
     *
     * @throws Exception 读写失败
     */
    @Test
    void canvasPaddingIsNotAuthenticatedAndDoesNotAffectRecovery() throws Exception {
        byte[] source = fixture("sample.png");
        Path sourcePath = write("padding.png", source);
        Path encrypted = workDir.resolve("padding.egimg.png");
        new ImageCryptCodec().encrypt(sourcePath, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        ImageCryptFrame frame = readFrame(encrypted);
        long frameLength = frame.ciphertextLength() + ImageCryptProtocol.OUTER_HEADER_LENGTH
                + ImageCryptProtocol.AUTH_TAG_LENGTH;
        long capacity = ImageCryptProtocol.canvasCapacity(
                frame.canvasWidth(), frame.canvasHeight());

        byte[] fullLogical = readLogical(encrypted, capacity);
        assertEquals((int) capacity, fullLogical.length);
        assertArrayEquals(Arrays.copyOf(fullLogical, (int) frameLength),
                readLogical(encrypted, frameLength),
                "按帧长抽取的前缀必须与整块画布的前缀逐字节一致");
        assertTrue(capacity > frameLength,
                "该样本必须留下真实的未认证画布尾部，否则本条用例没有测到 padding");
        assertTrue(frame.canvasWidth() * frame.canvasHeight()
                        >= ImageCryptProtocol.requiredPixels(frameLength),
                "画布像素数必须至少覆盖整帧");

        Path repacked = rewriteLogical(encrypted, "padding-repacked.png", ignored -> {
        });
        Path restored = new ImageCryptCodec().decrypt(repacked, outDir("padding-repacked"), null);
        assertSameBytes(sourcePath, restored, "重新打包 padding 后的还原");
    }

    /**
     * PNG 关键块被破坏必须被 CRC 拒绝。
     *
     * @throws Exception 读写失败
     */
    @Test
    void corruptedPngChunkIsRejected() throws Exception {
        Path source = write("chunk.png", fixture("sample.png"));
        Path encrypted = workDir.resolve("chunk.egimg.png");
        new ImageCryptCodec().encrypt(source, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        byte[] raw = Files.readAllBytes(encrypted);
        raw[16] ^= 0x01;
        Path broken = write("chunk-broken.png", raw);

        assertKind(ErrorKind.INVALID_HEADER,
                () -> new ImageCryptCodec().decrypt(broken, outDir("chunk-broken"), null));
        assertEquals(List.of(), listFiles(outDir("chunk-broken")));
    }

    /**
     * 各种截断都必须友好失败且不留下半成品。
     *
     * @throws Exception 读写失败
     */
    @Test
    void truncationIsRejectedAtEveryBoundary() throws Exception {
        Path source = write("trunc.png", fixture("sample.png"));
        Path encrypted = workDir.resolve("trunc.egimg.png");
        new ImageCryptCodec().encrypt(source, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        byte[] raw = Files.readAllBytes(encrypted);
        int[] cutPoints = {0, 8, 33, 64, raw.length / 2, raw.length - 12, raw.length - 1};
        for (int cut : cutPoints) {
            Path broken = write("trunc-" + cut + ".png", Arrays.copyOf(raw, cut));
            Path out = outDir("trunc-" + cut);
            assertThrows(ImageCryptException.class,
                    () -> new ImageCryptCodec().decrypt(broken, out, null),
                    "截断到 " + cut + " 字节时应失败");
            assertEquals(List.of(), listFiles(out), "截断到 " + cut + " 字节时留下产物");
        }
    }

    /**
     * IEND 之后追加数据必须被拒绝，避免"看起来更完整"的文件掩盖真实损坏。
     *
     * @throws Exception 读写失败
     */
    @Test
    void trailingDataAfterIendIsRejected() throws Exception {
        Path source = write("tail.png", fixture("sample.png"));
        Path encrypted = workDir.resolve("tail.egimg.png");
        new ImageCryptCodec().encrypt(source, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        byte[] raw = Files.readAllBytes(encrypted);
        byte[] withTail = Arrays.copyOf(raw, raw.length + 16);
        Path appended = write("tail-appended.png", withTail);

        assertKind(ErrorKind.INVALID_HEADER,
                () -> new ImageCryptCodec().decrypt(appended, outDir("tail-appended"), null));
    }

    /**
     * 加密过程中取消必须中止并清理临时文件。
     *
     * @throws Exception 读写失败
     */
    @Test
    void cancellingEncryptionLeavesNoOutput() throws Exception {
        Path source = write("cancel-large.png", largePng());
        Path target = workDir.resolve("cancel-large.egimg.png");

        assertThrows(CancelledException.class,
                () -> new ImageCryptCodec().encrypt(source, target, null,
                        ImageCryptOptions.DEFAULT, new CancelAfterFirstChunk()));
        assertFalse(Files.exists(target), "取消后不得留下产物");
        assertEquals(List.of(), tempFiles(workDir), "取消后不得留下临时文件");
    }

    /**
     * 还原过程中取消必须中止、清理临时文件，且不产出恢复文件。
     *
     * @throws Exception 读写失败
     */
    @Test
    void cancellingDecryptionLeavesNoOutput() throws Exception {
        byte[] source = largePng();
        Path sourcePath = write("cancel-dec.png", source);
        Path encrypted = workDir.resolve("cancel-dec.egimg.png");
        new ImageCryptCodec().encrypt(sourcePath, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);
        Path restoreDir = Files.createDirectories(workDir.resolve("cancel-dec-out"));

        assertThrows(CancelledException.class,
                () -> new ImageCryptCodec().decrypt(encrypted, restoreDir, null,
                        new CancelAfterFirstChunk()));
        assertEquals(List.of(), listFiles(restoreDir));
    }

    /**
     * 输出已存在且未允许覆盖时必须失败，允许覆盖时才替换。
     *
     * @throws Exception 读写失败
     */
    @Test
    void existingOutputIsRejectedUnlessOverwriteIsAllowed() throws Exception {
        Path source = write("exists.png", fixture("sample.png"));
        Path target = write("exists.egimg.png", "occupied".getBytes(StandardCharsets.US_ASCII));

        assertKind(ErrorKind.FILE_EXISTS,
                () -> new ImageCryptCodec().encrypt(source, target, null, ImageCryptOptions.DEFAULT,
                        ImageCryptProgress.NONE));
        assertEquals("occupied", Files.readString(target), "被拒绝时不得改写目标文件");

        new ImageCryptCodec().encrypt(source, target, null,
                ImageCryptOptions.overwriting(ImageCryptMode.PUBLIC_RECOVERY),
                ImageCryptProgress.NONE);
        assertTrue(new ImageCryptCodec().isEncrypted(target), "允许覆盖时应写出真正的产物");
    }

    /**
     * 恢复目录里已有同名产物时必须拒绝覆盖，且不留下新的临时文件。
     *
     * @throws Exception 读写失败
     */
    @Test
    void existingRestoredFileIsRejected() throws Exception {
        byte[] source = fixture("sample.png");
        Path sourcePath = write("holiday.png", source);
        Path encrypted = workDir.resolve("holiday.egimg.png");
        Path restoreDir = Files.createDirectories(workDir.resolve("holiday-out"));
        new ImageCryptCodec().encrypt(sourcePath, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        write(restoreDir.resolve("holiday.restored.png"),
                "occupied".getBytes(StandardCharsets.US_ASCII));
        assertKind(ErrorKind.FILE_EXISTS,
                () -> new ImageCryptCodec().decrypt(encrypted, restoreDir, null));
        assertEquals(List.of("holiday.restored.png"), listFiles(restoreDir));
    }

    /**
     * 恢复文件名来自加密区内的清单，与当前文件名无关。
     *
     * @throws Exception 读写失败
     */
    @Test
    void restoredNameComesFromManifestEvenAfterRenaming() throws Exception {
        byte[] source = fixture("sample.jpg");
        Path sourcePath = write("holiday.jpg", source);
        Path encrypted = workDir.resolve("holiday.egimg.png");
        new ImageCryptCodec().encrypt(sourcePath, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        Path renamed = write("random-name.png", Files.readAllBytes(encrypted));
        Path restoreDir = Files.createDirectories(workDir.resolve("renamed-out"));
        Path restored = new ImageCryptCodec().decrypt(renamed, restoreDir, null,
                ImageCryptProgress.NONE);

        assertEquals("holiday.restored.jpg", restored.getFileName().toString());
        assertSameBytes(sourcePath, restored, "改名后的还原");
    }

    /**
     * verify 必须完成认证但不产出任何文件，伪造数据时按分类抛出。
     *
     * @throws Exception 读写失败
     */
    @Test
    void verifyAuthenticatesWithoutProducingFiles() throws Exception {
        byte[] source = fixture("sample.webp");
        Path sourcePath = write("verify.webp", source);
        Path encrypted = workDir.resolve("verify.egimg.png");
        new ImageCryptCodec().encrypt(sourcePath, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);
        Path restoreDir = Files.createDirectories(workDir.resolve("verify-out"));

        new ImageCryptCodec().verify(encrypted, null, ImageCryptProgress.NONE);
        assertEquals(List.of(), listFiles(restoreDir));
        assertEquals(List.of(), listFiles(workDir).stream()
                .filter(name -> name.startsWith("verify.restored")).toList());

        ImageCryptFrame frame = readFrame(encrypted);
        Path tampered = tamperLogicalByte(encrypted, "verify-tampered.png",
                (int) (ImageCryptProtocol.OUTER_HEADER_LENGTH + frame.ciphertextLength()), 0x01);
        assertKind(ErrorKind.TAMPERED_DATA,
                () -> new ImageCryptCodec().verify(tampered, null, ImageCryptProgress.NONE));
    }

    /**
     * 只读探测必须能区分 EGTC-IMG 产物与普通 PNG，并给出正确的元数据。
     *
     * @throws Exception 读写失败
     */
    @Test
    void peekMetadataDescribesPublicAndPasswordFiles() throws Exception {
        Path source = write("peek.jpg", fixture("sample.jpg"));
        Path publicTarget = workDir.resolve("peek-public.egimg.png");
        Path passwordTarget = workDir.resolve("peek-password.egimg.png");
        byte[] password = ImageCryptPassword.encodeForV1("peek-pw");

        ImageCryptCodec codec = new ImageCryptCodec();
        codec.encrypt(source, publicTarget, null, ImageCryptOptions.DEFAULT, ImageCryptProgress.NONE);
        codec.encrypt(source, passwordTarget, password,
                ImageCryptOptions.of(ImageCryptMode.PASSWORD), ImageCryptProgress.NONE);

        assertTrue(codec.isEncrypted(publicTarget));
        assertTrue(codec.isEncrypted(passwordTarget));
        assertFalse(codec.isEncrypted(source), "普通 JPEG 不应被判定为图片密文");

        ImageCryptMetadata publicMeta = codec.peekMetadata(publicTarget);
        assertEquals(ImageCryptProtocol.VERSION, publicMeta.protocolVersion());
        assertEquals(ImageCryptMode.PUBLIC_RECOVERY, publicMeta.mode());
        assertFalse(publicMeta.requiresPassword());
        assertEquals(0, publicMeta.argon2MemoryKiB(), "公开恢复不得声明 Argon2 参数");
        assertTrue(publicMeta.hasSourceSizeHint(), "应携带原图尺寸提示");
        long sourceLength = Files.size(source);
        assertTrue(publicMeta.maxRestoredBytes() >= sourceLength,
                "恢复大小上界必须覆盖原文件长度");

        ImageCryptMetadata passwordMeta = codec.peekMetadata(passwordTarget);
        assertEquals(ImageCryptMode.PASSWORD, passwordMeta.mode());
        assertTrue(passwordMeta.requiresPassword());
        assertEquals(ImageCryptProtocol.ARGON2_MEMORY_KIB, passwordMeta.argon2MemoryKiB());
        assertEquals(ImageCryptProtocol.ARGON2_PASSES, passwordMeta.argon2Passes());
        assertEquals(ImageCryptProtocol.ARGON2_LANES, passwordMeta.argon2Lanes());

        assertKind(ErrorKind.NOT_IMAGE_CRYPT, () -> codec.peekMetadata(source));
    }

    /**
     * 不受支持的输入必须被拒绝，并且不得写出任何产物。
     *
     * @throws Exception 读写失败
     */
    @Test
    void unsupportedInputIsRejected() throws Exception {
        Path text = write("notes.txt", "这不是图片".getBytes(StandardCharsets.UTF_8));
        Path empty = write("empty.png", new byte[0]);
        Path target = workDir.resolve("rejected.egimg.png");

        assertKind(ErrorKind.UNSUPPORTED_FORMAT,
                () -> new ImageCryptCodec().encrypt(text, target, null, ImageCryptOptions.DEFAULT,
                        ImageCryptProgress.NONE));
        assertKind(ErrorKind.UNSUPPORTED_FORMAT,
                () -> new ImageCryptCodec().encrypt(empty, target, null, ImageCryptOptions.DEFAULT,
                        ImageCryptProgress.NONE));
        assertFalse(Files.exists(target));
    }

    /**
     * 源文件与产物同路径必须被预检拒绝，不能让加密把原图覆盖掉。
     *
     * @throws Exception 读写失败
     */
    @Test
    void outputMustDifferFromInput() throws Exception {
        byte[] source = fixture("sample.png");
        Path sourcePath = write("same.png", source);

        assertKind(ErrorKind.INTERNAL_ERROR,
                () -> new ImageCryptCodec().encrypt(sourcePath, sourcePath, null,
                        ImageCryptOptions.overwriting(ImageCryptMode.PUBLIC_RECOVERY),
                        ImageCryptProgress.NONE));
        assertArrayEquals(source, Files.readAllBytes(sourcePath), "原图必须保持原样");
    }

    /**
     * 恢复扩展名必须以魔数判定为准，不能被误导性的文件名带偏。
     *
     * @throws Exception 读写失败
     */
    @Test
    void restoredExtensionFollowsMagicNotFileName() throws Exception {
        byte[] source = fixture("sample.png");
        Path misleading = write("photo.jp2", source);
        Path encrypted = workDir.resolve("misleading.egimg.png");
        new ImageCryptCodec().encrypt(misleading, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        Path restored = new ImageCryptCodec().decrypt(encrypted, outDir("misleading-out"), null);
        assertEquals("photo.restored.png", restored.getFileName().toString(),
                "扩展名指向另一种格式时必须采用魔数判定的扩展名");
        assertSameBytes(misleading, restored, "误导性扩展名的还原");
    }

    /**
     * 扩展名与魔数一致时必须沿用原后缀，避免把 {@code .jpeg} 一律规整成 {@code .jpg}。
     *
     * @throws Exception 读写失败
     */
    @Test
    void restoredExtensionPreservesMatchingAlias() throws Exception {
        byte[] source = fixture("sample.jpg");
        Path sourcePath = write("photo.jpeg", source);
        Path encrypted = workDir.resolve("alias.egimg.png");
        new ImageCryptCodec().encrypt(sourcePath, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        Path restored = new ImageCryptCodec().decrypt(encrypted, outDir("alias-out"), null);
        assertEquals("photo.restored.jpeg", restored.getFileName().toString());
    }

    /**
     * 同一输入重复加密必须得到不同产物，证明每文件 salt、nonce 与主密钥都是新的。
     *
     * @throws Exception 读写失败
     */
    @Test
    void repeatedEncryptionProducesDifferentFiles() throws Exception {
        Path source = write("fresh.png", fixture("sample.png"));
        Path first = workDir.resolve("fresh-1.egimg.png");
        Path second = workDir.resolve("fresh-2.egimg.png");
        ImageCryptCodec codec = new ImageCryptCodec();

        codec.encrypt(source, first, null, ImageCryptOptions.DEFAULT, ImageCryptProgress.NONE);
        codec.encrypt(source, second, null, ImageCryptOptions.DEFAULT, ImageCryptProgress.NONE);

        assertNotEquals(readFrameHex(first), readFrameHex(second),
                "两次加密的协议帧不得相同");
        assertArrayEquals(Files.readAllBytes(source),
                Files.readAllBytes(codec.decrypt(first, outDir("fresh-1"), null)));
        assertArrayEquals(Files.readAllBytes(source),
                Files.readAllBytes(codec.decrypt(second, outDir("fresh-2"), null)));
    }

    /**
     * 跨默认 IDAT 边界的大载荷必须逐字节往返，并驱动进度回调。
     *
     * @throws Exception 读写失败
     */
    @Test
    void largePayloadCrossesChunkBoundariesWithProgress() throws Exception {
        byte[] source = largePng();
        Path sourcePath = write("large.png", source);
        Path encrypted = workDir.resolve("large.egimg.png");
        Path restoreDir = Files.createDirectories(workDir.resolve("large-out"));
        RecordingProgress encryptProgress = new RecordingProgress();
        RecordingProgress decryptProgress = new RecordingProgress();
        ImageCryptCodec codec = new ImageCryptCodec();

        codec.encrypt(sourcePath, encrypted, null, ImageCryptOptions.DEFAULT, encryptProgress);
        Path restored = codec.decrypt(encrypted, restoreDir, null, decryptProgress);

        assertSameBytes(sourcePath, restored, "大载荷");
        assertTrue(encryptProgress.maxProcessed() > 1 << 20,
                "加密应上报超过一个分块的字节进度");
        assertTrue(decryptProgress.maxProcessed() > 0, "还原应上报字节进度");
        assertEquals(ImageCryptPhase.DONE, encryptProgress.lastPhase());
        assertEquals(ImageCryptPhase.DONE, decryptProgress.lastPhase());
        assertTrue(encryptProgress.phases().contains(ImageCryptPhase.PROBE));
        assertTrue(encryptProgress.phases().contains(ImageCryptPhase.ENCRYPTING));
        assertTrue(encryptProgress.phases().contains(ImageCryptPhase.DONE));
        assertTrue(decryptProgress.phases().contains(ImageCryptPhase.PNG_READING));
        assertTrue(decryptProgress.phases().contains(ImageCryptPhase.MAC_VERIFY));
        assertTrue(decryptProgress.phases().contains(ImageCryptPhase.COMMITTING));
    }

    // ==================== 夹具 ====================

    /**
     * 首期格式样本。
     *
     * @param fileName 文件名（决定扩展名提示）
     * @param bytes    文件字节
     */
    private record FormatSample(String fileName, byte[] bytes) {
    }

    /**
     * 构造五种格式的样本。
     *
     * <p>PNG/JPEG/WebP 使用测试资源中的真实文件；GIF/BMP 由 ImageIO 现场生成，
     * 避免把二进制夹具塞进仓库。
     *
     * @return 样本列表
     * @throws IOException 读取夹具或生成图片失败
     */
    private static List<FormatSample> samples() throws IOException {
        List<FormatSample> samples = new ArrayList<>();
        samples.add(new FormatSample("sample.png", fixture("sample.png")));
        samples.add(new FormatSample("sample.jpg", fixture("sample.jpg")));
        samples.add(new FormatSample("sample.webp", fixture("sample.webp")));
        samples.add(new FormatSample("sample.gif", generatedImage("gif", 40, 30)));
        samples.add(new FormatSample("sample.bmp", generatedImage("bmp", 40, 30)));
        samples.add(new FormatSample("header-only.gif", minimalGif(320, 240)));
        samples.add(new FormatSample("tiny.bmp", minimalBmp(64, 48, 40)));
        return samples;
    }

    /**
     * 用 ImageIO 生成一张指定格式的彩色小图。
     *
     * @param format 格式名（gif/bmp）
     * @param width  宽度
     * @param height 高度
     * @return 图片字节
     * @throws IOException 编码失败
     */
    private static byte[] generatedImage(final String format, final int width, final int height)
            throws IOException {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                image.setRGB(x, y, (x * 7 + y * 13) & 0xffffff);
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertTrue(ImageIO.write(image, format, out), "ImageIO 缺少 " + format + " 编码器");
        return out.toByteArray();
    }

    /**
     * 生成一张尺寸足以跨越多个 IDAT 与加密分块、且几乎不可压缩的 PNG。
     *
     * @return PNG 字节
     * @throws IOException 编码失败
     */
    private static byte[] largePng() throws IOException {
        int width = 800;
        int height = 640;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Random random = new Random(20260916L);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                image.setRGB(x, y, random.nextInt(0xffffff));
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertTrue(ImageIO.write(image, "png", out));
        assertTrue(out.size() > 1 << 20, "大样本应超过 1 MiB，实际 " + out.size());
        return out.toByteArray();
    }

    // ==================== 断言与工具 ====================

    /**
     * 断言两个文件逐字节一致，失败时报告长度与首个差异偏移。
     *
     * @param expected 期望文件
     * @param actual   实际文件
     * @param label    断言上下文
     * @throws IOException 读取失败
     */
    private static void assertSameBytes(final Path expected, final Path actual, final String label)
            throws IOException {
        assertEquals(Files.size(expected), Files.size(actual), label + "：恢复长度不一致");
        long mismatch = Files.mismatch(expected, actual);
        assertEquals(-1L, mismatch, label + "：首个差异位于偏移 " + mismatch);
    }

    /**
     * 写出一个测试文件。
     *
     * @param name  文件名
     * @param bytes 内容
     * @return 文件路径
     * @throws IOException 写入失败
     */
    private Path write(final String name, final byte[] bytes) throws IOException {
        return write(workDir.resolve(name), bytes);
    }

    /**
     * 把内容写入指定路径。
     *
     * @param path  目标路径
     * @param bytes 内容
     * @return 目标路径
     * @throws IOException 写入失败
     */
    private static Path write(final Path path, final byte[] bytes) throws IOException {
        Files.write(path, bytes);
        return path;
    }

    /**
     * 创建并返回一个输出目录。
     *
     * @param name 目录名
     * @return 目录路径
     * @throws IOException 创建失败
     */
    private Path outDir(final String name) throws IOException {
        return Files.createDirectories(workDir.resolve(name));
    }

    /**
     * 列出目录下的文件名。
     *
     * @param directory 目录
     * @return 文件名列表
     * @throws IOException 读取失败
     */
    private static List<String> listFiles(final Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (Stream<Path> stream = Files.list(directory)) {
            return stream.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    /**
     * 列出目录下的图片加密临时文件。
     *
     * @param directory 目录
     * @return 临时文件名列表
     * @throws IOException 读取失败
     */
    private static List<String> tempFiles(final Path directory) throws IOException {
        return listFiles(directory).stream()
                .filter(name -> name.startsWith("egtcimg-") && name.endsWith(".part"))
                .toList();
    }

    /**
     * 读取产物的逻辑协议帧。
     *
     * @param encrypted 产物路径
     * @return 外层协议头
     * @throws Exception PNG 或协议解析失败
     */
    private static ImageCryptFrame readFrame(final Path encrypted) throws Exception {
        ByteArrayOutputStream frameOut = new ByteArrayOutputStream();
        try (InputStream in = Files.newInputStream(encrypted)) {
            return new PixelPngReader().readFrame(in, frameOut);
        }
    }

    /**
     * 读取产物逻辑帧的十六进制表示，用于比较两次加密是否产生不同内容。
     *
     * @param encrypted 产物路径
     * @return 十六进制文本
     * @throws Exception PNG 或协议解析失败
     */
    private static String readFrameHex(final Path encrypted) throws Exception {
        ByteArrayOutputStream frameOut = new ByteArrayOutputStream();
        try (InputStream in = Files.newInputStream(encrypted)) {
            new PixelPngReader().readFrame(in, frameOut);
        }
        return ImageCryptTestSupport.hex(frameOut.toByteArray());
    }

    /**
     * 从产物中抽取指定长度的逻辑画布前缀。
     *
     * @param encrypted     产物路径
     * @param logicalLength 需要抽取的逻辑字节数
     * @return 逻辑字节
     * @throws Exception PNG 解析失败
     */
    private static byte[] readLogical(final Path encrypted, final long logicalLength)
            throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = Files.newInputStream(encrypted)) {
            new PixelPngReader().read(in, out, logicalLength);
        }
        return out.toByteArray();
    }

    /**
     * 翻转逻辑帧中的一个字节并重写成一张新 PNG。
     *
     * @param encrypted  原始产物
     * @param targetName 新文件名
     * @param index      逻辑帧内的字节偏移
     * @param mask       异或掩码
     * @return 新产物路径
     * @throws Exception PNG 或协议解析失败
     */
    private static Path tamperLogicalByte(final Path encrypted, final String targetName,
                                          final int index, final int mask) throws Exception {
        return rewriteLogical(encrypted, targetName, frame -> frame[index] ^= (byte) mask);
    }

    /**
     * 改写协议头中的一个字节、重算 headerCrc32 后重写成一张新 PNG。
     *
     * @param encrypted  原始产物
     * @param targetName 新文件名
     * @param offset     协议头内的偏移
     * @param value      新字节值
     * @return 新产物路径
     * @throws Exception PNG 或协议解析失败
     */
    private static Path rewriteHeaderByte(final Path encrypted, final String targetName,
                                          final int offset, final int value) throws Exception {
        return rewriteLogical(encrypted, targetName, frame -> {
            frame[offset] = (byte) value;
            refreshCrc32(frame);
        });
    }

    /**
     * 读取逻辑帧、施加改写、再写成一张合法的 PNG。
     *
     * <p>直接改写 PNG 像素是做不到的：像素经过 zlib 与 CRC 封装。走
     * {@link PixelPngReader}/{@link PixelPngWriter} 重打包既保持了 PNG 结构合法，
     * 又能精确命中协议帧内部的单一字段，从而把失败原因隔离到被测校验点。
     *
     * @param encrypted  原始产物
     * @param targetName 新文件名
     * @param mutation   对逻辑帧字节的改写动作
     * @return 新产物路径
     * @throws Exception PNG 或协议解析失败
     */
    private static Path rewriteLogical(final Path encrypted, final String targetName,
                                       final FrameMutation mutation) throws Exception {
        ByteArrayOutputStream frameOut = new ByteArrayOutputStream();
        ImageCryptFrame frame;
        try (InputStream in = Files.newInputStream(encrypted)) {
            frame = new PixelPngReader().readFrame(in, frameOut);
        }
        byte[] logical = frameOut.toByteArray();
        mutation.apply(logical);
        Path target = encrypted.getParent().resolve(targetName);
        try (OutputStream out = Files.newOutputStream(target)) {
            new PixelPngWriter().write(out, frame.canvasWidth(), frame.canvasHeight(),
                    new ByteArrayInputStream(logical), logical.length);
        }
        return target;
    }

    /**
     * 对逻辑帧字节的原地改写动作。
     */
    @FunctionalInterface
    private interface FrameMutation {

        /**
         * 执行改写。
         *
         * @param frameBytes 逻辑帧字节
         */
        void apply(byte[] frameBytes);
    }

    /**
     * 在第一个载荷分块之后立即请求取消。
     *
     * <p>用真实的 1 MiB 分块边界触发取消，而不是"第一次回调就取消"：后者在极小文件上会
     * 退化成"开始前取消"，测不到中途清理。每次使用都新建实例，避免测试之间互相污染状态。
     */
    private static final class CancelAfterFirstChunk implements ImageCryptProgress {

        /**
         * 是否已经处理过至少一个分块。
         */
        private boolean triggered;

        @Override
        public void onPhase(final ImageCryptPhase phase) {
            // 阶段变化不参与取消判定
        }

        @Override
        public void onBytes(final long processed, final long total) {
            triggered = true;
        }

        @Override
        public boolean isCancelled() {
            return triggered;
        }
    }

    /**
     * 记录阶段与字节进度的测试回调。
     */
    private static final class RecordingProgress implements ImageCryptProgress {

        /**
         * 收到的阶段序列。
         */
        private final List<ImageCryptPhase> phases = new ArrayList<>();

        /**
         * 收到过的最大已处理字节数。
         */
        private long maxProcessed;

        @Override
        public void onPhase(final ImageCryptPhase phase) {
            phases.add(phase);
        }

        @Override
        public void onBytes(final long processed, final long total) {
            maxProcessed = Math.max(maxProcessed, processed);
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        /**
         * 返回收到的阶段序列。
         *
         * @return 阶段列表
         */
        private List<ImageCryptPhase> phases() {
            return phases;
        }

        /**
         * 返回最后一个阶段。
         *
         * @return 阶段；未收到任何回调时为 {@code null}
         */
        private ImageCryptPhase lastPhase() {
            return phases.isEmpty() ? null : phases.get(phases.size() - 1);
        }

        /**
         * 返回最大已处理字节数。
         *
         * @return 字节数
         */
        private long maxProcessed() {
            return maxProcessed;
        }
    }
}
