package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMetadata;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptOptions;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPassword;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * 桌面图片加密页面与共享核心之间的无界面工作流。
 *
 * <p>本类集中处理保护模式、密码规范化和密码字节清零，使 JavaFX 控制器只负责任务调度与
 * 视图状态。所有方法都同步执行，调用方必须放入后台执行器，不能直接在 JavaFX 线程调用。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class ImageCryptDesktopWorkflow {

    /** 共享图片加密门面。 */
    private final ImageCryptCodec codec;

    /**
     * 创建使用生产图片加密门面的桌面工作流。
     */
    public ImageCryptDesktopWorkflow() {
        this(new ImageCryptCodec());
    }

    /**
     * 创建使用指定门面的桌面工作流。
     *
     * @param codec 图片加密门面
     */
    ImageCryptDesktopWorkflow(final ImageCryptCodec codec) {
        this.codec = Objects.requireNonNull(codec, "codec");
    }

    /**
     * 加密图片并生成 EGTC-IMG PNG。
     *
     * @param input             输入图片
     * @param output            输出 PNG
     * @param mode              保护模式
     * @param password          用户输入的密码；公开恢复模式会忽略该值
     * @param overwriteExisting 是否覆盖已有输出
     * @param progress          进度与取消回调
     * @throws ImageCryptException 图片格式、密码、容量或协议处理失败
     * @throws hbnu.project.ergoutreecrypt.exception.CancelledException 用户取消
     * @throws IOException 文件读写失败
     */
    public void encrypt(final Path input, final Path output, final ImageCryptMode mode,
                        final String password, final boolean overwriteExisting,
                        final ImageCryptProgress progress)
            throws ImageCryptException,
            hbnu.project.ergoutreecrypt.exception.CancelledException, IOException {
        Objects.requireNonNull(mode, "mode");
        byte[] passwordBytes = encodePassword(mode, password);
        try {
            codec.encrypt(input, output, passwordBytes,
                    new ImageCryptOptions(mode, overwriteExisting), progress);
        } finally {
            erase(passwordBytes);
        }
    }

    /**
     * 还原 EGTC-IMG PNG，并依据协议头自动决定是否规范化密码。
     *
     * @param input             EGTC-IMG PNG
     * @param outputDirectory   恢复目录
     * @param password          用户输入的密码；公开恢复产物会忽略该值
     * @param overwriteExisting 是否覆盖已有恢复文件
     * @param progress          进度与取消回调
     * @return 实际恢复文件路径
     * @throws ImageCryptException 协议、密码、认证或输出处理失败
     * @throws hbnu.project.ergoutreecrypt.exception.CancelledException 用户取消
     * @throws IOException 文件读写失败
     */
    public Path decrypt(final Path input, final Path outputDirectory, final String password,
                        final boolean overwriteExisting, final ImageCryptProgress progress)
            throws ImageCryptException,
            hbnu.project.ergoutreecrypt.exception.CancelledException, IOException {
        ImageCryptMetadata metadata = codec.peekMetadata(input);
        byte[] passwordBytes = encodePassword(metadata.mode(), password);
        try {
            return codec.decrypt(input, outputDirectory, passwordBytes, overwriteExisting,
                    progress);
        } finally {
            erase(passwordBytes);
        }
    }

    /**
     * 完整校验 EGTC-IMG PNG，并依据协议头自动决定是否规范化密码。
     *
     * @param input    EGTC-IMG PNG
     * @param password 用户输入的密码；公开恢复产物会忽略该值
     * @param progress 进度与取消回调
     * @throws ImageCryptException 协议、密码或认证失败
     * @throws hbnu.project.ergoutreecrypt.exception.CancelledException 用户取消
     * @throws IOException 文件读取失败
     */
    public void verify(final Path input, final String password,
                       final ImageCryptProgress progress)
            throws ImageCryptException,
            hbnu.project.ergoutreecrypt.exception.CancelledException, IOException {
        ImageCryptMetadata metadata = codec.peekMetadata(input);
        byte[] passwordBytes = encodePassword(metadata.mode(), password);
        try {
            codec.verify(input, passwordBytes, progress);
        } finally {
            erase(passwordBytes);
        }
    }

    /**
     * 按保护模式生成协议要求的密码字节。
     *
     * @param mode     保护模式
     * @param password 用户输入的密码
     * @return 密码模式的规范化字节；公开恢复模式为 {@code null}
     * @throws ImageCryptException 密码无效
     */
    private static byte[] encodePassword(final ImageCryptMode mode, final String password)
            throws ImageCryptException {
        return mode == ImageCryptMode.PASSWORD
                ? ImageCryptPassword.encodeForV1(password) : null;
    }

    /**
     * 清零工作流持有的临时密码字节。
     *
     * @param bytes 待清零字节，可为 {@code null}
     */
    private static void erase(final byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
